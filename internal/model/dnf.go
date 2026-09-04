package model

import "fmt"

// DNF (disjunctive normal form) expansion bounds. A rule that expands to more
// than MaxDNFTerms conjunctions, or a single conjunction with more than
// MaxDNFAtomsPerTerm atoms, is considered pathological and rejected with a
// clear error rather than emitting an unbounded number of Envoy routes.
const (
	MaxDNFTerms        = 128
	MaxDNFAtomsPerTerm = 32
)

// DNFElem is one element in a DNF term: an atom, optionally negated.
type DNFElem struct {
	Atom    Atom
	Negated bool
}

// DNFTerm is a single conjunction (logical AND) of DNFElems. A rule's DNF is
// a list of DNFTerm values joined by OR.
type DNFTerm []DNFElem

// ToDNF expands the rule into disjunctive normal form: a list of conjunctions
// (terms), each a list of (possibly negated) atoms, joined by OR. The
// expansion is boolean-correct (De Morgan for negation, distribution of OR
// over AND) and bounded: it returns an error if the expansion exceeds
// MaxDNFTerms terms or MaxDNFAtomsPerTerm atoms in a single term.
//
// Contradictory terms (conjunctions that can never be true, e.g.
// Path("/a") && Path("/b")) are dropped. If every term is contradictory the
// rule is unsatisfiable and an error is returned.
func (r Rule) ToDNF() ([]DNFTerm, error) {
	if r.Node == nil {
		return nil, fmt.Errorf("empty rule")
	}
	nnf, err := toNNF(r.Node)
	if err != nil {
		return nil, err
	}
	terms, err := expand(nnf)
	if err != nil {
		return nil, err
	}
	// Drop contradictory terms.
	kept := terms[:0]
	for _, term := range terms {
		if !isContradiction(term) {
			kept = append(kept, term)
		}
	}
	if len(kept) == 0 {
		return nil, fmt.Errorf("rule is unsatisfiable (no request can match it)")
	}
	return kept, nil
}

// toNNF pushes negations inward so that negation only ever applies directly
// to an atom (De Morgan's laws + double-negation elimination).
func toNNF(n *Node) (*Node, error) {
	if n == nil {
		return nil, fmt.Errorf("empty rule")
	}
	switch n.Op {
	case OpAtom:
		if n.Atom == nil {
			return nil, fmt.Errorf("empty rule")
		}
		return n, nil
	case OpNot:
		inner, err := toNNF(n.Left)
		if err != nil {
			return nil, err
		}
		switch inner.Op {
		case OpAtom:
			// Negation of an atom stays as a negated atom leaf.
			return Not(inner), nil
		case OpNot:
			// Double negation: !!x == x
			return inner.Left, nil
		case OpAnd:
			// !(a && b) == !a || !b
			l, err := toNNF(Not(inner.Left))
			if err != nil {
				return nil, err
			}
			r, err := toNNF(Not(inner.Right))
			if err != nil {
				return nil, err
			}
			return Or(l, r), nil
		case OpOr:
			// !(a || b) == !a && !b
			l, err := toNNF(Not(inner.Left))
			if err != nil {
				return nil, err
			}
			r, err := toNNF(Not(inner.Right))
			if err != nil {
				return nil, err
			}
			return And(l, r), nil
		}
		return nil, fmt.Errorf("unexpected node op %v", inner.Op)
	case OpAnd:
		l, err := toNNF(n.Left)
		if err != nil {
			return nil, err
		}
		r, err := toNNF(n.Right)
		if err != nil {
			return nil, err
		}
		return And(l, r), nil
	case OpOr:
		l, err := toNNF(n.Left)
		if err != nil {
			return nil, err
		}
		r, err := toNNF(n.Right)
		if err != nil {
			return nil, err
		}
		return Or(l, r), nil
	default:
		return nil, fmt.Errorf("unexpected node op %v", n.Op)
	}
}

// expand converts an NNF tree into a list of DNF terms.
func expand(n *Node) ([]DNFTerm, error) {
	if n == nil {
		return nil, fmt.Errorf("empty rule")
	}
	switch n.Op {
	case OpAtom:
		if n.Atom != nil {
			return []DNFTerm{{DNFElem{Atom: *n.Atom}}}, nil
		}
		return nil, fmt.Errorf("empty rule")
	case OpNot:
		// Only a negated atom reaches here after NNF.
		if n.Left != nil && n.Left.Atom != nil {
			return []DNFTerm{{DNFElem{Atom: *n.Left.Atom, Negated: true}}}, nil
		}
		return nil, fmt.Errorf("unexpected negated non-atom in NNF")
	case OpOr:
		left, err := expand(n.Left)
		if err != nil {
			return nil, err
		}
		right, err := expand(n.Right)
		if err != nil {
			return nil, err
		}
		out := append(left, right...)
		if len(out) > MaxDNFTerms {
			return nil, fmt.Errorf("rule expands to %d terms, exceeding the limit of %d; simplify the expression", len(out), MaxDNFTerms)
		}
		return out, nil
	case OpAnd:
		left, err := expand(n.Left)
		if err != nil {
			return nil, err
		}
		right, err := expand(n.Right)
		if err != nil {
			return nil, err
		}
		// Cross product: every left term ANDed with every right term.
		out := make([]DNFTerm, 0, len(left)*len(right))
		for _, l := range left {
			for _, r := range right {
				term := make(DNFTerm, 0, len(l)+len(r))
				term = append(term, l...)
				term = append(term, r...)
				if len(term) > MaxDNFAtomsPerTerm {
					return nil, fmt.Errorf("rule expands to a conjunction of %d atoms, exceeding the limit of %d; simplify the expression", len(term), MaxDNFAtomsPerTerm)
				}
				out = append(out, term)
			}
		}
		if len(out) > MaxDNFTerms {
			return nil, fmt.Errorf("rule expands to %d terms, exceeding the limit of %d; simplify the expression", len(out), MaxDNFTerms)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unexpected node op %v", n.Op)
	}
}

// dimension returns the matching dimension key and value for an atom. Two
// non-negated atoms in the same conjunction on the same dimension must agree
// for the conjunction to be satisfiable.
func dimension(a Atom) (key, value string) {
	switch a.Kind {
	case KindHost:
		return "host", a.Value
	case KindPath:
		return "path", a.Value
	case KindPathPrefix:
		return "pathprefix", a.Value
	case KindHeader:
		return "header:" + a.Name, a.Value
	case KindMethod:
		return "method", a.Value
	case KindQuery:
		return "query:" + a.Name, a.Value
	case KindClientIP:
		return "clientip", a.Value
	default:
		return "unknown", ""
	}
}

// isContradiction reports whether a conjunction can never be true, by checking
// for conflicting non-negated atoms on the same dimension.
func isContradiction(term DNFTerm) bool {
	byDim := map[string][]string{}
	for _, e := range term {
		if e.Negated {
			continue
		}
		key, value := dimension(e.Atom)
		byDim[key] = append(byDim[key], value)
	}
	for key, values := range byDim {
		for i := 0; i < len(values); i++ {
			for j := i + 1; j < len(values); j++ {
				if !dimsCompatible(key, values[i], values[j]) {
					return true
				}
			}
		}
	}
	return false
}

// dimsCompatible reports whether two values on the same dimension can both be
// true in one request. For pathprefix, one prefix subsumes the other iff it
// is a prefix of it; for all other dimensions the values must be equal.
func dimsCompatible(key, a, b string) bool {
	if a == b {
		return true
	}
	if key == "pathprefix" {
		// Satisfiable iff one is a prefix of the other (the shorter subsumes
		// the longer). E.g. "/api" and "/api/v2" both hold for "/api/v2/x".
		return hasPrefix(b, a) || hasPrefix(a, b)
	}
	return false
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
