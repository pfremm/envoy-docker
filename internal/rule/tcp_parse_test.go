package rule

import (
	"testing"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
)

func TestParse_HostSNI_Exact(t *testing.T) {
	r := parseOrDie(t, `HostSNI(a.example.com)`)
	if r.String() != "HostSNI(a.example.com)" {
		t.Errorf("got %q, want HostSNI(a.example.com)", r.String())
	}
	if r.Node.Atom.Kind != model.KindSNI {
		t.Fatalf("atom kind = %v, want KindSNI", r.Node.Atom.Kind)
	}
}

func TestParse_HostSNI_CatchAll(t *testing.T) {
	r := parseOrDie(t, `HostSNI(*)`)
	if r.String() != "HostSNI(*)" {
		t.Errorf("got %q, want HostSNI(*)", r.String())
	}
}

func TestParse_HostSNI_CaseInsensitive(t *testing.T) {
	r := parseOrDie(t, `HostSNI(A.Example.COM)`)
	if r.Node.Atom.Value != "a.example.com" {
		t.Errorf("SNI value = %q, want lowercased a.example.com", r.Node.Atom.Value)
	}
}

func TestParse_HostSNI_MultiValueOr(t *testing.T) {
	r := parseOrDie(t, `HostSNI(a.com, b.com)`)
	terms, err := r.ToDNF()
	if err != nil {
		t.Fatalf("ToDNF error: %v", err)
	}
	if len(terms) != 2 {
		t.Fatalf("got %d DNF terms, want 2: %+v", len(terms), terms)
	}
}

func TestParse_HostSNI_BooleanCombinators(t *testing.T) {
	// && , || , ! , parens must be semantically valid for SNI too, even
	// though most combinations are rejected later at SNITranslatable (only
	// pure HostSNI(...) atoms, no negation, are actually usable for TCP
	// filter-chain matching). The grammar itself must still parse them.
	if _, err := Parse(`HostSNI(a.com) || HostSNI(b.com)`); err != nil {
		t.Fatalf("|| combinator: %v", err)
	}
	if _, err := Parse(`HostSNI(a.com) && HostSNI(b.com)`); err != nil {
		t.Fatalf("&& combinator: %v", err)
	}
	if _, err := Parse(`!HostSNI(a.com)`); err != nil {
		t.Fatalf("! combinator: %v", err)
	}
	if _, err := Parse(`(HostSNI(a.com) || HostSNI(b.com)) && !HostSNI(c.com)`); err != nil {
		t.Fatalf("parens combinator: %v", err)
	}
}

func TestParse_HostSNI_RequiresValue(t *testing.T) {
	mustErr(t, `HostSNI()`)
}
