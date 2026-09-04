package rule

import (
	"testing"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
)

// parseOrDie parses expr, failing the test on error.
func parseOrDie(t *testing.T, expr string) model.Rule {
	t.Helper()
	r, err := Parse(expr)
	if err != nil {
		t.Fatalf("Parse(%q) unexpected error: %v", expr, err)
	}
	return r
}

// mustErr asserts that parsing expr fails.
func mustErr(t *testing.T, expr string) {
	t.Helper()
	if _, err := Parse(expr); err == nil {
		t.Fatalf("Parse(%q) expected error, got nil", expr)
	}
}

func TestParse_Host(t *testing.T) {
	r := parseOrDie(t, `Host(a.com)`)
	if r.String() != "Host(a.com)" {
		t.Errorf("got %q, want Host(a.com)", r.String())
	}
	terms, err := r.ToDNF()
	if err != nil {
		t.Fatalf("ToDNF error: %v", err)
	}
	if len(terms) != 1 || terms[0][0].Atom.Kind != model.KindHost || terms[0][0].Atom.Value != "a.com" {
		t.Errorf("got %+v, want single Host(a.com)", terms)
	}
}

func TestParse_Host_MultiValueOr(t *testing.T) {
	r := parseOrDie(t, `Host(a.com, b.com)`)
	if r.String() != "(Host(a.com) || Host(b.com))" {
		t.Errorf("got %q, want (Host(a.com) || Host(b.com))", r.String())
	}
	terms, err := r.ToDNF()
	if err != nil {
		t.Fatalf("ToDNF error: %v", err)
	}
	if len(terms) != 2 {
		t.Errorf("got %d DNF terms, want 2: %+v", len(terms), terms)
	}
}

func TestParse_Path(t *testing.T) {
	r := parseOrDie(t, `Path(/api/v1/users)`)
	if r.String() != "Path(/api/v1/users)" {
		t.Errorf("got %q, want Path(/api/v1/users)", r.String())
	}
}

func TestParse_PathPrefix(t *testing.T) {
	r := parseOrDie(t, `PathPrefix(/api)`)
	if r.String() != "PathPrefix(/api)" {
		t.Errorf("got %q, want PathPrefix(/api)", r.String())
	}
}

func TestParse_Headers(t *testing.T) {
	r := parseOrDie(t, `Headers(X-Api-Key, secret)`)
	if r.String() != "Headers(X-Api-Key, secret)" {
		t.Errorf("got %q, want Headers(X-Api-Key, secret)", r.String())
	}
	terms, err := r.ToDNF()
	if err != nil {
		t.Fatalf("ToDNF error: %v", err)
	}
	if len(terms) != 1 || terms[0][0].Atom.Kind != model.KindHeader ||
		terms[0][0].Atom.Name != "X-Api-Key" || terms[0][0].Atom.Value != "secret" {
		t.Errorf("got %+v, want single Headers(X-Api-Key, secret)", terms)
	}
}

func TestParse_Headers_QuotedValueWithSpaces(t *testing.T) {
	r := parseOrDie(t, `Headers("X-Custom", "hello world")`)
	if r.String() != "Headers(X-Custom, hello world)" {
		t.Errorf("got %q, want Headers(X-Custom, hello world)", r.String())
	}
	terms, _ := r.ToDNF()
	if terms[0][0].Atom.Name != "X-Custom" || terms[0][0].Atom.Value != "hello world" {
		t.Errorf("got %+v, want name X-Custom value 'hello world'", terms[0][0])
	}
}

func TestParse_Method(t *testing.T) {
	r := parseOrDie(t, `Method(GET)`)
	if r.String() != "Method(GET)" {
		t.Errorf("got %q, want Method(GET)", r.String())
	}
	// Method is case-normalized to upper.
	r2 := parseOrDie(t, `Method(get)`)
	if r2.String() != "Method(GET)" {
		t.Errorf("got %q, want Method(GET) (uppercased)", r2.String())
	}
}

func TestParse_Method_Multi(t *testing.T) {
	r := parseOrDie(t, `Method(GET, POST)`)
	if r.String() != "(Method(GET) || Method(POST))" {
		t.Errorf("got %q, want (Method(GET) || Method(POST))", r.String())
	}
}

func TestParse_Query_Presence(t *testing.T) {
	r := parseOrDie(t, `Query(debug)`)
	terms, err := r.ToDNF()
	if err != nil {
		t.Fatalf("ToDNF error: %v", err)
	}
	if terms[0][0].Atom.Kind != model.KindQuery || terms[0][0].Atom.Name != "debug" || terms[0][0].Atom.Value != "" {
		t.Errorf("got %+v, want Query(debug, <presence>)", terms[0][0])
	}
}

func TestParse_Query_Value(t *testing.T) {
	r := parseOrDie(t, `Query(page, 2)`)
	terms, err := r.ToDNF()
	if err != nil {
		t.Fatalf("ToDNF error: %v", err)
	}
	if terms[0][0].Atom.Kind != model.KindQuery || terms[0][0].Atom.Name != "page" || terms[0][0].Atom.Value != "2" {
		t.Errorf("got %+v, want Query(page, 2)", terms[0][0])
	}
}

func TestParse_ClientIP(t *testing.T) {
	r := parseOrDie(t, `ClientIP(10.0.0.0/8)`)
	terms, err := r.ToDNF()
	if err != nil {
		t.Fatalf("ToDNF error: %v", err)
	}
	if terms[0][0].Atom.Kind != model.KindClientIP || terms[0][0].Atom.Value != "10.0.0.0/8" {
		t.Errorf("got %+v, want ClientIP(10.0.0.0/8)", terms[0][0])
	}
}

func TestParse_ClientIP_BareIPNormalized(t *testing.T) {
	r := parseOrDie(t, `ClientIP(10.1.2.3)`)
	terms, err := r.ToDNF()
	if err != nil {
		t.Fatalf("ToDNF error: %v", err)
	}
	if terms[0][0].Atom.Value != "10.1.2.3/32" {
		t.Errorf("got %q, want 10.1.2.3/32 (bare IP normalized)", terms[0][0].Atom.Value)
	}
}

func TestParse_AndPrecedence(t *testing.T) {
	// && binds tighter than ||: A && B || C == (A && B) || C
	r := parseOrDie(t, `Host(a) && Path(/x) || Host(b)`)
	want := "((Host(a) && Path(/x)) || Host(b))"
	if r.String() != want {
		t.Errorf("got %q, want %q", r.String(), want)
	}
}

func TestParse_Parentheses(t *testing.T) {
	r := parseOrDie(t, `(Host(a) || Host(b)) && PathPrefix(/api)`)
	want := "((Host(a) || Host(b)) && PathPrefix(/api))"
	if r.String() != want {
		t.Errorf("got %q, want %q", r.String(), want)
	}
	terms, err := r.ToDNF()
	if err != nil {
		t.Fatalf("ToDNF error: %v", err)
	}
	// Distribution: (a||b) && c -> (a&&c) || (b&&c) = 2 terms
	if len(terms) != 2 {
		t.Errorf("got %d DNF terms, want 2: %+v", len(terms), terms)
	}
}

func TestParse_Not(t *testing.T) {
	r := parseOrDie(t, `!Path(/admin)`)
	terms, err := r.ToDNF()
	if err != nil {
		t.Fatalf("ToDNF error: %v", err)
	}
	if len(terms) != 1 || !terms[0][0].Negated || terms[0][0].Atom.Kind != model.KindPath {
		t.Errorf("got %+v, want negated Path(/admin)", terms)
	}
}

func TestParse_NotCompound(t *testing.T) {
	// !(A && B) == !A || !B
	r := parseOrDie(t, `!(Host(a) && Path(/x))`)
	terms, err := r.ToDNF()
	if err != nil {
		t.Fatalf("ToDNF error: %v", err)
	}
	if len(terms) != 2 {
		t.Errorf("got %d DNF terms, want 2: %+v", len(terms), terms)
	}
	for _, term := range terms {
		if !term[0].Negated {
			t.Errorf("expected all negated, got %+v", term)
		}
	}
}

func TestParse_NestedNot(t *testing.T) {
	// !!A == A
	r := parseOrDie(t, `!!Host(a)`)
	terms, err := r.ToDNF()
	if err != nil {
		t.Fatalf("ToDNF error: %v", err)
	}
	if len(terms) != 1 || terms[0][0].Negated {
		t.Errorf("got %+v, want positive Host(a)", terms)
	}
}

func TestParse_Complex(t *testing.T) {
	r := parseOrDie(t, `Host(a.com) && (PathPrefix(/api) || PathPrefix(/v2)) && Method(GET)`)
	terms, err := r.ToDNF()
	if err != nil {
		t.Fatalf("ToDNF error: %v", err)
	}
	// Host && (A||B) && Method -> (Host&&A&&Method) || (Host&&B&&Method) = 2 terms
	if len(terms) != 2 {
		t.Errorf("got %d DNF terms, want 2: %+v", len(terms), terms)
	}
	for _, term := range terms {
		if len(term) != 3 {
			t.Errorf("term %v has %d atoms, want 3", term, len(term))
		}
	}
}

func TestParse_Empty(t *testing.T) {
	mustErr(t, ``)
	mustErr(t, `   `)
}

func TestParse_UnknownMatcher(t *testing.T) {
	mustErr(t, `Foo(bar)`)
}

func TestParse_MissingParen(t *testing.T) {
	mustErr(t, `Host a.com`)
}

func TestParse_UnclosedParen(t *testing.T) {
	mustErr(t, `(Host(a) && Path(/x)`)
}

func TestParse_TrailingGarbage(t *testing.T) {
	mustErr(t, `Host(a) &&`)
	mustErr(t, `Host(a) extra`)
}

func TestParse_BadOperator(t *testing.T) {
	mustErr(t, `Host(a) & Path(/x)`)
	mustErr(t, `Host(a) | Path(/x)`)
}

func TestParse_EmptyMatcherArgs(t *testing.T) {
	mustErr(t, `Host()`)
	mustErr(t, `Path()`)
}

func TestParse_HeadersOddArgs(t *testing.T) {
	mustErr(t, `Headers(onlyname)`)
}

func TestParse_ClientIPInvalid(t *testing.T) {
	mustErr(t, `ClientIP(not-an-ip)`)
	mustErr(t, `ClientIP(999.999.999.999/8)`)
}

func TestParse_QueryTooManyArgs(t *testing.T) {
	mustErr(t, `Query(a, b, c)`)
}

func TestParse_MatcherNameCaseInsensitive(t *testing.T) {
	// Matcher names are case-insensitive.
	r := parseOrDie(t, `host(a.com)`)
	if r.String() != "Host(a.com)" {
		t.Errorf("got %q, want Host(a.com)", r.String())
	}
	r2 := parseOrDie(t, `PATHPREFIX(/api)`)
	if r2.String() != "PathPrefix(/api)" {
		t.Errorf("got %q, want PathPrefix(/api)", r2.String())
	}
}

func TestParse_DNFBounded(t *testing.T) {
	// A rule that would expand beyond the term limit must be rejected at DNF
	// time (the parser itself succeeds; the bound is enforced by ToDNF).
	var expr string
	for i := 0; i < 8; i++ {
		part := `(` + `Headers(h` + string(rune('0'+i)) + `, a) || Headers(h` + string(rune('0'+i)) + `, b)` + `)`
		if expr == "" {
			expr = part
		} else {
			expr = expr + ` && ` + part
		}
	}
	r, err := Parse(expr)
	if err != nil {
		t.Fatalf("Parse error (expected parse to succeed, DNF to fail): %v", err)
	}
	if _, err := r.ToDNF(); err == nil {
		t.Errorf("expected DNF term-limit error, got nil")
	}
}

func TestParse_WhitespaceTolerance(t *testing.T) {
	r := parseOrDie(t, `  Host(a.com)   &&   PathPrefix(/api)  `)
	want := "(Host(a.com) && PathPrefix(/api))"
	if r.String() != want {
		t.Errorf("got %q, want %q", r.String(), want)
	}
}
