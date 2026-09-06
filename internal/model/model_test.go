package model

import (
	"testing"
)

func TestToDNF_SingleAtom(t *testing.T) {
	r := Rule{Node: AtomNode(NewHost("a.com"))}
	terms, err := r.ToDNF()
	if err != nil {
		t.Fatalf("ToDNF() error: %v", err)
	}
	if len(terms) != 1 || len(terms[0]) != 1 {
		t.Fatalf("got %d terms, want 1x1: %+v", len(terms), terms)
	}
	if terms[0][0].Atom.Kind != KindHost || terms[0][0].Atom.Value != "a.com" || terms[0][0].Negated {
		t.Errorf("got %+v, want Host(a.com) positive", terms[0][0])
	}
}

func TestToDNF_And(t *testing.T) {
	r := Rule{Node: And(AtomNode(NewHost("a.com")), AtomNode(NewPath("/api")))}
	terms, err := r.ToDNF()
	if err != nil {
		t.Fatalf("ToDNF() error: %v", err)
	}
	if len(terms) != 1 || len(terms[0]) != 2 {
		t.Fatalf("got %d terms of len, want 1 term of 2 atoms: %+v", len(terms), terms)
	}
}

func TestToDNF_Or(t *testing.T) {
	// Host(a) || Host(b)  ->  two terms, each one atom.
	r := Rule{Node: Or(AtomNode(NewHost("a.com")), AtomNode(NewHost("b.com")))}
	terms, err := r.ToDNF()
	if err != nil {
		t.Fatalf("ToDNF() error: %v", err)
	}
	if len(terms) != 2 {
		t.Fatalf("got %d terms, want 2: %+v", len(terms), terms)
	}
}

func TestToDNF_Distribution(t *testing.T) {
	// (A || B) && C  ->  (A && C) || (B && C)
	a := AtomNode(NewHost("a.com"))
	b := AtomNode(NewHost("b.com"))
	c := AtomNode(NewPath("/api"))
	r := Rule{Node: And(Or(a, b), c)}
	terms, err := r.ToDNF()
	if err != nil {
		t.Fatalf("ToDNF() error: %v", err)
	}
	if len(terms) != 2 {
		t.Fatalf("got %d terms, want 2: %+v", len(terms), terms)
	}
	for _, term := range terms {
		if len(term) != 2 {
			t.Fatalf("term %v has %d atoms, want 2", term, len(term))
		}
		// Each term must contain C.
		hasC := false
		for _, e := range term {
			if e.Atom.Kind == KindPath && e.Atom.Value == "/api" {
				hasC = true
			}
		}
		if !hasC {
			t.Errorf("term %v missing Path(/api)", term)
		}
	}
}

func TestToDNF_DoubleNegation(t *testing.T) {
	// !!Host(a)  ->  Host(a)
	r := Rule{Node: Not(Not(AtomNode(NewHost("a.com"))))}
	terms, err := r.ToDNF()
	if err != nil {
		t.Fatalf("ToDNF() error: %v", err)
	}
	if len(terms) != 1 || len(terms[0]) != 1 {
		t.Fatalf("got %+v, want 1x1", terms)
	}
	if terms[0][0].Negated {
		t.Errorf("double negation should be positive, got negated")
	}
}

func TestToDNF_DeMorganNotAnd(t *testing.T) {
	// !(A && B)  ->  !A || !B
	a := AtomNode(NewHeader("h", "v"))
	b := AtomNode(NewHeader("h2", "v2"))
	r := Rule{Node: Not(And(a, b))}
	terms, err := r.ToDNF()
	if err != nil {
		t.Fatalf("ToDNF() error: %v", err)
	}
	if len(terms) != 2 {
		t.Fatalf("got %d terms, want 2: %+v", len(terms), terms)
	}
	for _, term := range terms {
		if len(term) != 1 || !term[0].Negated {
			t.Errorf("expected a single negated atom, got %v", term)
		}
	}
}

func TestToDNF_DeMorganNotOr(t *testing.T) {
	// !(A || B)  ->  !A && !B
	a := AtomNode(NewHeader("h", "v"))
	b := AtomNode(NewHeader("h2", "v2"))
	r := Rule{Node: Not(Or(a, b))}
	terms, err := r.ToDNF()
	if err != nil {
		t.Fatalf("ToDNF() error: %v", err)
	}
	if len(terms) != 1 || len(terms[0]) != 2 {
		t.Fatalf("got %+v, want 1 term of 2 atoms", terms)
	}
	for _, e := range terms[0] {
		if !e.Negated {
			t.Errorf("expected negated atom, got %v", e)
		}
	}
}

func TestToDNF_ContradictionDropped(t *testing.T) {
	// Path(/a) && Path(/b)  ->  contradictory, unsatisfiable.
	r := Rule{Node: And(AtomNode(NewPath("/a")), AtomNode(NewPath("/b")))}
	if _, err := r.ToDNF(); err == nil {
		t.Fatalf("expected error for contradictory rule, got nil")
	}
}

func TestToDNF_ContradictionOrKeepsOthers(t *testing.T) {
	// (Path(/a) && Path(/b)) || Host(a.com)  ->  the contradiction is dropped,
	// the Host term survives.
	r := Rule{Node: Or(
		And(AtomNode(NewPath("/a")), AtomNode(NewPath("/b"))),
		AtomNode(NewHost("a.com")),
	)}
	terms, err := r.ToDNF()
	if err != nil {
		t.Fatalf("ToDNF() error: %v", err)
	}
	if len(terms) != 1 {
		t.Fatalf("got %d terms, want 1 (contradiction dropped): %+v", len(terms), terms)
	}
	if terms[0][0].Atom.Kind != KindHost {
		t.Errorf("surviving term should be Host, got %+v", terms[0][0])
	}
}

func TestToDNF_PathPrefixSubsumption(t *testing.T) {
	// PathPrefix(/api) && PathPrefix(/api/v2) is satisfiable (subsumption).
	r := Rule{Node: And(AtomNode(NewPathPrefix("/api")), AtomNode(NewPathPrefix("/api/v2")))}
	terms, err := r.ToDNF()
	if err != nil {
		t.Fatalf("ToDNF() error: %v", err)
	}
	if len(terms) != 1 || len(terms[0]) != 2 {
		t.Fatalf("got %+v, want 1 term of 2 atoms", terms)
	}
}

func TestToDNF_PathPrefixConflict(t *testing.T) {
	// PathPrefix(/api) && PathPrefix(/web) is contradictory (neither is a
	// prefix of the other).
	r := Rule{Node: And(AtomNode(NewPathPrefix("/api")), AtomNode(NewPathPrefix("/web")))}
	if _, err := r.ToDNF(); err == nil {
		t.Fatalf("expected error for conflicting prefixes, got nil")
	}
}

func TestToDNF_TermLimit(t *testing.T) {
	// Build (A1||B1) && (A2||B2) && ... && (An||Bn) which is 2^n terms.
	// 8 factors -> 256 terms > MaxDNFTerms(128) -> error.
	var node *Node
	for i := 0; i < 8; i++ {
		factor := Or(AtomNode(NewHeader("h"+string(rune('0'+i)), "a")), AtomNode(NewHeader("h"+string(rune('0'+i)), "b")))
		if node == nil {
			node = factor
		} else {
			node = And(node, factor)
		}
	}
	r := Rule{Node: node}
	if _, err := r.ToDNF(); err == nil {
		t.Fatalf("expected term-limit error, got nil")
	}
}

func TestToDNF_AtomsPerTermLimit(t *testing.T) {
	// A conjunction of more than MaxDNFAtomsPerTerm atoms.
	var node *Node
	for i := 0; i < MaxDNFAtomsPerTerm+1; i++ {
		atom := AtomNode(NewHeader("h"+string(rune('0'+i%10)), string(rune('a'+i%26))))
		if node == nil {
			node = atom
		} else {
			node = And(node, atom)
		}
	}
	r := Rule{Node: node}
	if _, err := r.ToDNF(); err == nil {
		t.Fatalf("expected atoms-per-term error, got nil")
	}
}

func TestPrecedence_ExplicitPriorityWins(t *testing.T) {
	// A route with an explicit priority beats one without, regardless of
	// rule length.
	a := Route{RuleExpr: "Host(a.com) && PathPrefix(/api) && Method(GET)", Priority: 1, PrioritySet: true, RouterName: "a"}
	b := Route{RuleExpr: "Host(a.com)", RouterName: "b"}
	if !Precedence(a, b) {
		t.Errorf("explicit priority should beat no priority")
	}
	if Precedence(b, a) {
		t.Errorf("no priority should not beat explicit priority")
	}
}

func TestPrecedence_ExplicitHigherFirst(t *testing.T) {
	a := Route{Priority: 10, PrioritySet: true, RouterName: "a"}
	b := Route{Priority: 5, PrioritySet: true, RouterName: "b"}
	if !Precedence(a, b) {
		t.Errorf("priority 10 should beat 5")
	}
	if Precedence(b, a) {
		t.Errorf("priority 5 should not beat 10")
	}
}

func TestPrecedence_SpecificityWhenNoPriority(t *testing.T) {
	// Without explicit priority, the longer (more specific) rule wins.
	a := Route{RuleExpr: "Host(a.com) && PathPrefix(/api) && Method(GET)", RouterName: "a"}
	b := Route{RuleExpr: "Host(a.com)", RouterName: "b"}
	if !Precedence(a, b) {
		t.Errorf("more specific rule should come first")
	}
}

func TestPrecedence_LegacySubdomainLast(t *testing.T) {
	// A legacy subdomain route (no rule) has specificity 0 and sorts after a
	// rule-based route.
	a := Route{RuleExpr: "Host(a.com) && PathPrefix(/api)", RouterName: "a"}
	b := Route{Subdomain: "a.com", RouterName: "b"} // no rule
	if !Precedence(a, b) {
		t.Errorf("rule route should come before legacy subdomain route")
	}
}

func TestPrecedence_NameTieBreaker(t *testing.T) {
	// Same specificity, no priority: router name ascending.
	a := Route{RuleExpr: "Host(a.com)", RouterName: "alpha"}
	b := Route{RuleExpr: "Host(b.com)", RouterName: "beta"}
	if !Precedence(a, b) {
		t.Errorf("alpha should sort before beta on name tie-break")
	}
}

func TestSortByPrecedence_Ordering(t *testing.T) {
	routes := []Route{
		{RuleExpr: "Host(a.com)", RouterName: "legacy"},                  // specificity 10
		{RuleExpr: "Host(a.com) && PathPrefix(/api)", RouterName: "mid"}, // specificity 28
		{Priority: 100, PrioritySet: true, RuleExpr: "Host(a.com) && PathPrefix(/api/v2)", RouterName: "top"},
	}
	sorted := SortByPrecedence(routes)
	if sorted[0].RouterName != "top" {
		t.Errorf("explicit priority route should be first, got %q", sorted[0].RouterName)
	}
	if sorted[1].RouterName != "mid" {
		t.Errorf("more specific rule should be second, got %q", sorted[1].RouterName)
	}
	if sorted[2].RouterName != "legacy" {
		t.Errorf("least specific should be last, got %q", sorted[2].RouterName)
	}
}

func TestRule_String(t *testing.T) {
	r := Rule{Node: And(Or(AtomNode(NewHost("a.com")), AtomNode(NewHost("b.com"))), AtomNode(NewPathPrefix("/api")))}
	got := r.String()
	want := "((Host(a.com) || Host(b.com)) && PathPrefix(/api))"
	if got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestRule_Hosts(t *testing.T) {
	r := Rule{Node: And(Or(AtomNode(NewHost("b.com")), AtomNode(NewHost("a.com"))), AtomNode(NewPathPrefix("/api")))}
	got := r.Hosts()
	if len(got) != 2 || got[0] != "a.com" || got[1] != "b.com" {
		t.Errorf("Hosts() = %v, want [a.com b.com]", got)
	}
}

func TestRule_HasClientIP(t *testing.T) {
	r := Rule{Node: And(AtomNode(NewHost("a.com")), AtomNode(NewClientIP("10.0.0.0/8")))}
	if !r.HasClientIP() {
		t.Errorf("HasClientIP() = false, want true")
	}
	r2 := Rule{Node: AtomNode(NewHost("a.com"))}
	if r2.HasClientIP() {
		t.Errorf("HasClientIP() = true, want false")
	}
}
