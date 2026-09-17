// Package rule parses Traefik-style HTTP routing rule expressions into the
// typed model.Rule AST. The grammar is:
//
//	expr     = or
//	or       = and ( "||" and )*
//	and      = unary ( "&&" unary )*
//	unary    = "!" unary | primary
//	primary  = "(" expr ")" | matcher
//	matcher  = IDENT "(" arg ( "," arg )* ")"
//
// Supported matchers: Host, Path, PathPrefix, Headers, Method, Query,
// ClientIP. Multiple values inside a matcher are ORed. Precedence is
// ! > && > ||, matching Traefik and common boolean conventions.
package rule

import (
	"fmt"
	"net"
	"strings"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
)

// Parse parses a rule expression string into a model.Rule. It returns an
// error with an actionable message on any syntax or semantic problem.
func Parse(expr string) (model.Rule, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return model.Rule{}, fmt.Errorf("rule expression is empty")
	}
	p := &parser{src: expr}
	node, err := p.parseOr()
	if err != nil {
		return model.Rule{}, err
	}
	if !p.atEnd() {
		return model.Rule{}, fmt.Errorf("unexpected trailing input at %q (position %d)", p.peekToken(), p.pos)
	}
	return model.Rule{Node: node}, nil
}

type tokKind int

const (
	tokEOF tokKind = iota
	tokIdent
	tokLParen
	tokRParen
	tokComma
	tokAnd
	tokOr
	tokNot
)

type token struct {
	kind  tokKind
	value string // ident text
}

type parser struct {
	src string
	pos int
}

func (p *parser) atEnd() bool { return p.pos >= len(p.src) }

func (p *parser) peekToken() string {
	rest := p.src[p.pos:]
	if len(rest) > 24 {
		return rest[:24] + "..."
	}
	return rest
}

// skipWS advances past whitespace.
func (p *parser) skipWS() {
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			p.pos++
		} else {
			break
		}
	}
}

// next returns the next token, advancing past it.
func (p *parser) next() (token, error) {
	p.skipWS()
	if p.atEnd() {
		return token{kind: tokEOF}, nil
	}
	c := p.src[p.pos]
	switch {
	case c == '(':
		p.pos++
		return token{kind: tokLParen}, nil
	case c == ')':
		p.pos++
		return token{kind: tokRParen}, nil
	case c == ',':
		p.pos++
		return token{kind: tokComma}, nil
	case c == '!':
		// "!=" is not part of the grammar; a bare "!" is negation.
		p.pos++
		return token{kind: tokNot}, nil
	case c == '&':
		if p.pos+1 < len(p.src) && p.src[p.pos+1] == '&' {
			p.pos += 2
			return token{kind: tokAnd}, nil
		}
		return token{}, fmt.Errorf("unexpected character '&' at position %d (did you mean '&&'?)", p.pos)
	case c == '|':
		if p.pos+1 < len(p.src) && p.src[p.pos+1] == '|' {
			p.pos += 2
			return token{kind: tokOr}, nil
		}
		return token{}, fmt.Errorf("unexpected character '|' at position %d (did you mean '||'?)", p.pos)
	case isIdentStart(c):
		start := p.pos
		for p.pos < len(p.src) && isIdentPart(p.src[p.pos]) {
			p.pos++
		}
		return token{kind: tokIdent, value: p.src[start:p.pos]}, nil
	default:
		return token{}, fmt.Errorf("unexpected character %q at position %d", c, p.pos)
	}
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}

// peek returns the next token without consuming it.
func (p *parser) peek() (token, error) {
	saved := p.pos
	tok, err := p.next()
	p.pos = saved
	return tok, err
}

// parseOr: or = and ( "||" and )*
func (p *parser) parseOr() (*model.Node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for {
		tok, err := p.peek()
		if err != nil {
			return nil, err
		}
		if tok.kind != tokOr {
			break
		}
		if _, err := p.next(); err != nil { // consume ||
			return nil, err
		}
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = model.Or(left, right)
	}
	return left, nil
}

// parseAnd: and = unary ( "&&" unary )*
func (p *parser) parseAnd() (*model.Node, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for {
		tok, err := p.peek()
		if err != nil {
			return nil, err
		}
		if tok.kind != tokAnd {
			break
		}
		if _, err := p.next(); err != nil { // consume &&
			return nil, err
		}
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = model.And(left, right)
	}
	return left, nil
}

// parseUnary: unary = "!" unary | primary
func (p *parser) parseUnary() (*model.Node, error) {
	tok, err := p.peek()
	if err != nil {
		return nil, err
	}
	if tok.kind == tokNot {
		if _, err := p.next(); err != nil { // consume !
			return nil, err
		}
		inner, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return model.Not(inner), nil
	}
	return p.parsePrimary()
}

// parsePrimary: primary = "(" expr ")" | matcher
func (p *parser) parsePrimary() (*model.Node, error) {
	tok, err := p.peek()
	if err != nil {
		return nil, err
	}
	if tok.kind == tokLParen {
		if _, err := p.next(); err != nil { // consume (
			return nil, err
		}
		node, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		closing, err := p.next()
		if err != nil {
			return nil, err
		}
		if closing.kind != tokRParen {
			return nil, fmt.Errorf("expected ')' but got %q at position %d", closing.value, p.pos)
		}
		return node, nil
	}
	if tok.kind == tokIdent {
		return p.parseMatcher()
	}
	return nil, fmt.Errorf("expected a matcher (Host, Path, PathPrefix, Headers, Method, Query, ClientIP) or '(' but got %q at position %d", tok.value, p.pos)
}

// parseMatcher: matcher = IDENT "(" arg ( "," arg )* ")"
func (p *parser) parseMatcher() (*model.Node, error) {
	nameTok, err := p.next() // consume ident
	if err != nil {
		return nil, err
	}
	open, err := p.next()
	if err != nil {
		return nil, err
	}
	if open.kind != tokLParen {
		return nil, fmt.Errorf("matcher %q must be followed by '(', got %q at position %d", nameTok.value, open.value, p.pos)
	}

	// Collect arguments (comma-separated identifiers/values).
	var args []string
	for {
		arg, err := p.parseArg()
		if err != nil {
			return nil, err
		}
		args = append(args, arg)
		tok, err := p.peek()
		if err != nil {
			return nil, err
		}
		if tok.kind == tokComma {
			if _, err := p.next(); err != nil { // consume ,
				return nil, err
			}
			continue
		}
		break
	}

	closing, err := p.next()
	if err != nil {
		return nil, err
	}
	if closing.kind != tokRParen {
		return nil, fmt.Errorf("matcher %q: expected ')' but got %q at position %d", nameTok.value, closing.value, p.pos)
	}

	atoms, err := buildAtoms(nameTok.value, args)
	if err != nil {
		return nil, fmt.Errorf("matcher %q: %w", nameTok.value, err)
	}
	// OR the atoms together (multiple values within a matcher are ORed).
	node := model.AtomNode(atoms[0])
	for _, a := range atoms[1:] {
		node = model.Or(node, model.AtomNode(a))
	}
	return node, nil
}

// parseArg reads one matcher argument. Unquoted arguments run until the next
// ',' or ')' (whitespace-trimmed), which allows values with dots, slashes,
// hyphens, and digits (hostnames, paths, IPs, header names). Quoted strings
// ("...") allow arbitrary content including commas, via \" and \\ escapes.
func (p *parser) parseArg() (string, error) {
	p.skipWS()
	if p.atEnd() {
		return "", fmt.Errorf("expected a value inside a matcher, got end of input")
	}
	c := p.src[p.pos]
	if c == '"' {
		// Quoted string: read until the closing quote. Supports \" and \\ escapes.
		p.pos++ // consume opening quote
		var sb strings.Builder
		for p.pos < len(p.src) {
			ch := p.src[p.pos]
			if ch == '\\' && p.pos+1 < len(p.src) {
				next := p.src[p.pos+1]
				if next == '"' || next == '\\' {
					sb.WriteByte(next)
					p.pos += 2
					continue
				}
				return "", fmt.Errorf("invalid escape sequence at position %d", p.pos)
			}
			if ch == '"' {
				p.pos++ // consume closing quote
				return sb.String(), nil
			}
			sb.WriteByte(ch)
			p.pos++
		}
		return "", fmt.Errorf("unterminated string starting at position %d", p.pos)
	}
	// Unquoted: consume until ',' or ')' (or end of input, which the caller
	// will report as a missing ')').
	start := p.pos
	for p.pos < len(p.src) && p.src[p.pos] != ',' && p.src[p.pos] != ')' {
		p.pos++
	}
	val := strings.TrimSpace(p.src[start:p.pos])
	if val == "" {
		return "", fmt.Errorf("empty value inside a matcher at position %d", start)
	}
	// Reject Traefik-style backticked values (Host(`app.example.com`))
	// with an actionable error. Accepting them silently would keep the
	// backticks INSIDE the value: the resulting virtual-host domain
	// "`app.example.com`" can never equal a real :authority, so the router
	// would publish and then never match anything — a silent blackhole on
	// the single most common idiom pasted from Traefik configs.
	if strings.ContainsRune(val, '`') {
		return "", fmt.Errorf("backticks are not valid around matcher values (got %s at position %d): remove the Traefik-style backticks and use a bare value, e.g. Host(app.example.com), or double quotes", val, start)
	}
	return val, nil
}

// buildAtoms turns a matcher name + args into one or more model.Atom values.
func buildAtoms(name string, args []string) ([]model.Atom, error) {
	switch strings.ToLower(name) {
	case "host":
		if len(args) == 0 {
			return nil, fmt.Errorf("Host requires at least one host name")
		}
		out := make([]model.Atom, 0, len(args))
		for _, a := range args {
			if a == "" {
				return nil, fmt.Errorf("Host requires a non-empty host name")
			}
			out = append(out, model.NewHost(a))
		}
		return out, nil

	case "path":
		if len(args) == 0 {
			return nil, fmt.Errorf("Path requires at least one path")
		}
		out := make([]model.Atom, 0, len(args))
		for _, a := range args {
			if a == "" {
				return nil, fmt.Errorf("Path requires a non-empty path")
			}
			out = append(out, model.NewPath(a))
		}
		return out, nil

	case "pathprefix":
		if len(args) == 0 {
			return nil, fmt.Errorf("PathPrefix requires at least one prefix")
		}
		out := make([]model.Atom, 0, len(args))
		for _, a := range args {
			if a == "" {
				return nil, fmt.Errorf("PathPrefix requires a non-empty prefix")
			}
			out = append(out, model.NewPathPrefix(a))
		}
		return out, nil

	case "headers":
		if len(args) == 0 {
			return nil, fmt.Errorf("Headers requires a name and value")
		}
		// Headers(name, value). Only the first two args are used; additional
		// args are treated as additional (name, value) pairs.
		out := make([]model.Atom, 0, len(args)/2)
		for i := 0; i+1 < len(args); i += 2 {
			if args[i] == "" {
				return nil, fmt.Errorf("Headers requires a non-empty header name")
			}
			out = append(out, model.NewHeader(args[i], args[i+1]))
		}
		if len(args)%2 != 0 {
			return nil, fmt.Errorf("Headers requires pairs of (name, value); got %d argument(s)", len(args))
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("Headers requires at least one (name, value) pair")
		}
		return out, nil

	case "method":
		if len(args) == 0 {
			return nil, fmt.Errorf("Method requires at least one method")
		}
		out := make([]model.Atom, 0, len(args))
		for _, a := range args {
			m := strings.ToUpper(a)
			if m == "" {
				return nil, fmt.Errorf("Method requires a non-empty method")
			}
			out = append(out, model.NewMethod(m))
		}
		return out, nil

	case "query":
		if len(args) == 0 {
			return nil, fmt.Errorf("Query requires at least one parameter name")
		}
		// Query(name) is a presence match; Query(name, value) is an exact
		// value match. Only these two arities are supported.
		switch len(args) {
		case 1:
			if args[0] == "" {
				return nil, fmt.Errorf("Query requires a non-empty parameter name")
			}
			return []model.Atom{model.NewQuery(args[0], "")}, nil
		case 2:
			if args[0] == "" {
				return nil, fmt.Errorf("Query requires a non-empty parameter name")
			}
			return []model.Atom{model.NewQuery(args[0], args[1])}, nil
		default:
			return nil, fmt.Errorf("Query takes one parameter name or a (name, value) pair; got %d argument(s)", len(args))
		}

	case "clientip":
		if len(args) == 0 {
			return nil, fmt.Errorf("ClientIP requires at least one CIDR")
		}
		out := make([]model.Atom, 0, len(args))
		for _, a := range args {
			normalized, err := normalizeCIDR(a)
			if err != nil {
				return nil, fmt.Errorf("ClientIP %q: %w", a, err)
			}
			out = append(out, model.NewClientIP(normalized))
		}
		return out, nil

	case "hostsni":
		if len(args) == 0 {
			return nil, fmt.Errorf("HostSNI requires at least one SNI value")
		}
		out := make([]model.Atom, 0, len(args))
		for _, a := range args {
			if a == "" {
				return nil, fmt.Errorf("HostSNI requires a non-empty SNI value or the catch-all *")
			}
			out = append(out, model.NewSNI(a))
		}
		return out, nil

	default:
		return nil, fmt.Errorf("unknown matcher %q (supported: Host, Path, PathPrefix, Headers, Method, Query, ClientIP, HostSNI)", name)
	}
}

// normalizeCIDR validates s as a CIDR (or a bare IP, which is normalized to
// a /32 for IPv4 or /128 for IPv6) and returns the canonical CIDR form.
func normalizeCIDR(s string) (string, error) {
	if strings.Contains(s, "/") {
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return "", fmt.Errorf("not a valid CIDR: %w", err)
		}
		// Canonicalize: use the network address, not the host address.
		return ipnet.IP.String() + "/" + fmt.Sprint(networkPrefixLen(ipnet)), nil
	}
	// Bare IP: normalize to a /prefix CIDR.
	ip := net.ParseIP(s)
	if ip == nil {
		return "", fmt.Errorf("not a valid IP address or CIDR")
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String() + "/32", nil
	}
	return ip.String() + "/128", nil
}

// networkPrefixLen returns the prefix length of a parsed CIDR.
func networkPrefixLen(ipnet *net.IPNet) int {
	ones, _ := ipnet.Mask.Size()
	return ones
}
