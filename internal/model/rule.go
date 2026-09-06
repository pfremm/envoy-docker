package model

import "fmt"

// Rule is a parsed, normalized HTTP routing rule: a boolean expression over
// matcher atoms (Host, Path, PathPrefix, Headers, Method, Query, ClientIP).
// It is the single typed representation consumed by both the rule parser and
// the xDS snapshot builder, so no raw Envoy proto leaks into the model layer.
//
// A Rule is a tree of Nodes joined by boolean operators:
//
//	Rule{Node: And(Or(Host("a"), Host("b")), PathPrefix("/api"))}
//
// Multiple values inside a single matcher (e.g. Host("a.com","b.com")) are
// represented as an Or of single-value atoms, so every atom carries exactly
// one value. This keeps the DNF expansion and the Envoy translation uniform.
type Rule struct {
	Node *Node
}

// Node is one node in the boolean expression tree. Children are pointers so
// the (otherwise self-referential) type is legal in Go.
type Node struct {
	// Op is the logical operator. A leaf node has Op=OpAtom.
	Op Op
	// Left is the left operand (and the sole operand for OpNot).
	Left *Node
	// Right is the right operand (OpAnd, OpOr only).
	Right *Node
	// Atom is the matcher for leaf nodes (OpAtom).
	Atom *Atom
}

// Op is a logical operator in a rule expression.
type Op int

const (
	// OpAtom marks a leaf node that holds an Atom.
	OpAtom Op = iota
	// OpNot is unary negation (Left only).
	OpNot
	// OpAnd is logical conjunction (Left && Right).
	OpAnd
	// OpOr is logical disjunction (Left || Right).
	OpOr
)

// AtomKind identifies which matcher an Atom uses.
type AtomKind int

const (
	// KindHost matches the request Host header (case-insensitive).
	KindHost AtomKind = iota
	// KindPath matches the request path exactly (case-sensitive).
	KindPath
	// KindPathPrefix matches the request path prefix (case-sensitive).
	KindPathPrefix
	// KindHeader matches a request header by name and value.
	KindHeader
	// KindMethod matches the HTTP method.
	KindMethod
	// KindQuery matches a URL query parameter by name and value.
	KindQuery
	// KindClientIP matches the client source IP against a CIDR.
	KindClientIP
)

// Atom is a single matcher leaf in a rule expression.
//
//   - KindHost:    Value = host name (case-insensitive match).
//   - KindPath:    Value = exact path (case-sensitive).
//   - KindPathPrefix: Value = path prefix (case-sensitive).
//   - KindHeader:  Name = header name, Value = header value.
//   - KindMethod:  Value = HTTP method (e.g. "GET").
//   - KindQuery:   Name = query param name, Value = expected value. An empty
//     Value means "parameter is present" (presence match).
//   - KindClientIP: Value = CIDR (e.g. "10.0.0.0/8" or "10.1.2.3/32").
type Atom struct {
	Kind  AtomKind
	Name  string
	Value string
}

// NewHost builds a Host(...) atom (case-insensitive host match).
func NewHost(host string) Atom {
	return Atom{Kind: KindHost, Value: host}
}

// NewPath builds a Path(...) atom (exact, case-sensitive path match).
func NewPath(path string) Atom {
	return Atom{Kind: KindPath, Value: path}
}

// NewPathPrefix builds a PathPrefix(...) atom (case-sensitive prefix match).
func NewPathPrefix(prefix string) Atom {
	return Atom{Kind: KindPathPrefix, Value: prefix}
}

// NewHeader builds a Headers(name, value) atom.
func NewHeader(name, value string) Atom {
	return Atom{Kind: KindHeader, Name: name, Value: value}
}

// NewMethod builds a Method(...) atom.
func NewMethod(method string) Atom {
	return Atom{Kind: KindMethod, Value: method}
}

// NewQuery builds a Query(name, value) atom. An empty value is a presence
// match ("the parameter is present").
func NewQuery(name, value string) Atom {
	return Atom{Kind: KindQuery, Name: name, Value: value}
}

// NewClientIP builds a ClientIP(...) atom; value must be a CIDR.
func NewClientIP(cidr string) Atom {
	return Atom{Kind: KindClientIP, Value: cidr}
}

// And joins two nodes with logical AND.
func And(left, right *Node) *Node {
	return &Node{Op: OpAnd, Left: left, Right: right}
}

// Or joins two nodes with logical OR.
func Or(left, right *Node) *Node {
	return &Node{Op: OpOr, Left: left, Right: right}
}

// Not negates a node.
func Not(n *Node) *Node {
	return &Node{Op: OpNot, Left: n}
}

// AtomNode wraps an Atom as a leaf Node.
func AtomNode(a Atom) *Node {
	return &Node{Op: OpAtom, Atom: &a}
}

// String renders the rule back into its canonical expression form. This is
// used for logging and for the xDS "rule expression" bookkeeping so operators
// can see what a generated route was derived from.
func (r Rule) String() string {
	if r.Node == nil {
		return ""
	}
	return r.Node.String()
}

func (n *Node) String() string {
	if n == nil {
		return ""
	}
	switch n.Op {
	case OpAtom:
		return n.Atom.String()
	case OpNot:
		return "!(" + n.Left.String() + ")"
	case OpAnd:
		return "(" + n.Left.String() + " && " + n.Right.String() + ")"
	case OpOr:
		return "(" + n.Left.String() + " || " + n.Right.String() + ")"
	default:
		return "<unknown>"
	}
}

func (a Atom) String() string {
	switch a.Kind {
	case KindHost:
		return "Host(" + a.Value + ")"
	case KindPath:
		return "Path(" + a.Value + ")"
	case KindPathPrefix:
		return "PathPrefix(" + a.Value + ")"
	case KindHeader:
		return "Headers(" + a.Name + ", " + a.Value + ")"
	case KindMethod:
		return "Method(" + a.Value + ")"
	case KindQuery:
		return "Query(" + a.Name + ", " + a.Value + ")"
	case KindClientIP:
		return "ClientIP(" + a.Value + ")"
	default:
		return "<unknown>"
	}
}

// Hosts returns the set of host names in the rule (across the whole tree,
// ignoring negation). Used for grouping routes into Envoy virtual hosts.
func (r Rule) Hosts() []string {
	seen := map[string]bool{}
	var walk func(n *Node)
	walk = func(n *Node) {
		if n == nil {
			return
		}
		switch n.Op {
		case OpAtom:
			if n.Atom != nil && n.Atom.Kind == KindHost {
				seen[n.Atom.Value] = true
			}
		case OpNot, OpAnd, OpOr:
			walk(n.Left)
			if n.Op != OpNot {
				walk(n.Right)
			}
		}
	}
	walk(r.Node)
	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	// Deterministic order.
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// HasClientIP reports whether the rule references a ClientIP matcher anywhere
// (including under negation). Such rules cannot be expressed as a pure RDS
// route match in this Envoy version and are rejected at xDS build time.
func (r Rule) HasClientIP() bool {
	var walk func(n *Node) bool
	walk = func(n *Node) bool {
		if n == nil {
			return false
		}
		switch n.Op {
		case OpAtom:
			return n.Atom != nil && n.Atom.Kind == KindClientIP
		case OpNot:
			return walk(n.Left)
		case OpAnd, OpOr:
			return walk(n.Left) || walk(n.Right)
		}
		return false
	}
	return walk(r.Node)
}

// KindName returns a human-readable name for the atom kind, used in error
// messages and diagnostics.
func (k AtomKind) Name() string {
	switch k {
	case KindHost:
		return "Host"
	case KindPath:
		return "Path"
	case KindPathPrefix:
		return "PathPrefix"
	case KindHeader:
		return "Headers"
	case KindMethod:
		return "Method"
	case KindQuery:
		return "Query"
	case KindClientIP:
		return "ClientIP"
	default:
		return "unknown"
	}
}

// Translatable reports whether the rule can be expressed as one or more Envoy
// RDS route matches in this control plane's Envoy version, and returns an
// actionable error describing the first unsupported construct if it cannot.
//
// Unsupported constructs (rejected, not crashed on):
//   - ClientIP: this Envoy version's RouteMatch has no source-IP / CIDR field,
//     so client-IP matching cannot be expressed as a route match.
//   - Negation (!) on Path, PathPrefix, Query, or Host: Envoy route matches
//     cannot express "not path" / "not query" / "not host". Negation IS
//     supported on Headers and Method (via the header matcher's invert_match).
//
// The check expands the rule to DNF (so negations are pushed to atoms first)
// and inspects every atom in every term.
func (r Rule) Translatable() error {
	if r.Node == nil {
		return nil
	}
	if r.HasClientIP() {
		return fmt.Errorf("ClientIP(...) is not supported: this Envoy version's route match has no source-IP/CIDR field. Remove the ClientIP matcher or match on a header instead")
	}
	terms, err := r.ToDNF()
	if err != nil {
		return err
	}
	for _, term := range terms {
		for _, e := range term {
			if !e.Negated {
				continue
			}
			switch e.Atom.Kind {
			case KindHeader, KindMethod:
				// Negation via header matcher invert_match: supported.
			default:
				return fmt.Errorf("negation (!) is only supported on Headers(...) and Method(...); !%s(...) cannot be expressed as an Envoy route match", e.Atom.Kind.Name())
			}
		}
	}
	return nil
}

// RuleLen returns the length of the rule's canonical string form, used as a
// specificity proxy when no explicit priority is set.
func (r Rule) RuleLen() int {
	return len(r.String())
}
