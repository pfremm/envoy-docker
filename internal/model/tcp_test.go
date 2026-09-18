package model

import (
	"strings"
	"testing"
)

func hostSNI(value string) Rule {
	return Rule{Node: AtomNode(NewSNI(value))}
}

func orSNI(values ...string) Rule {
	if len(values) == 1 {
		return hostSNI(values[0])
	}
	n := AtomNode(NewSNI(values[0]))
	for _, v := range values[1:] {
		n = Or(n, AtomNode(NewSNI(v)))
	}
	return Rule{Node: n}
}

func TestSNITranslatable_ExactAndCatchAll(t *testing.T) {
	if err := hostSNI("a.example.com").SNITranslatable(); err != nil {
		t.Fatalf("exact SNI: %v", err)
	}
	if err := hostSNI("*").SNITranslatable(); err != nil {
		t.Fatalf("catch-all SNI: %v", err)
	}
	if err := orSNI("a.com", "b.com").SNITranslatable(); err != nil {
		t.Fatalf("OR of SNI values: %v", err)
	}
}

func TestSNITranslatable_RejectsNegation(t *testing.T) {
	r := Rule{Node: Not(AtomNode(NewSNI("a.com")))}
	if err := r.SNITranslatable(); err == nil || !strings.Contains(err.Error(), "negation") {
		t.Fatalf("expected negation rejection, got %v", err)
	}
}

func TestSNITranslatable_RejectsHTTPMatchers(t *testing.T) {
	r := Rule{Node: AtomNode(NewPath("/api"))}
	if err := r.SNITranslatable(); err == nil || !strings.Contains(err.Error(), "HTTP matcher") {
		t.Fatalf("expected HTTP-matcher rejection, got %v", err)
	}
}

func TestSNITranslatable_RejectsAndOfDistinctSNI(t *testing.T) {
	// Host(a) && Host(b) is a contradiction (dimsCompatible requires equal
	// values for "sni"), so ToDNF rejects it as unsatisfiable rather than
	// SNITranslatable rejecting a matcher kind. Either way it must error.
	r := Rule{Node: And(AtomNode(NewSNI("a.com")), AtomNode(NewSNI("b.com")))}
	if err := r.SNITranslatable(); err == nil {
		t.Fatal("expected error for contradictory AND of distinct SNI values")
	}
}

func TestTCPRouterSNIValuesAndCatchAll(t *testing.T) {
	r := TCPRouter{Name: "web", Rule: orSNI("a.com", "b.com")}
	if got := r.SNIValues(); len(got) != 2 || got[0] != "a.com" || got[1] != "b.com" {
		t.Fatalf("SNIValues() = %v", got)
	}
	if r.HasCatchAll() {
		t.Fatal("should not be catch-all")
	}
	catchAll := TCPRouter{Name: "cat", Rule: hostSNI("*")}
	if !catchAll.HasCatchAll() {
		t.Fatal("expected catch-all")
	}
}

func TestTCPRouterValidate(t *testing.T) {
	base := TCPRouter{Name: "web", Rule: hostSNI("a.com"), ServiceName: "svc", TLSPassthrough: true}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid passthrough router: %v", err)
	}

	noRule := TCPRouter{Name: "web", ServiceName: "svc", TLSPassthrough: true}
	if err := noRule.Validate(); err == nil {
		t.Fatal("expected error for missing rule")
	}

	noService := TCPRouter{Name: "web", Rule: hostSNI("a.com"), TLSPassthrough: true}
	if err := noService.Validate(); err == nil {
		t.Fatal("expected error for missing service")
	}

	emptyEntrypoint := TCPRouter{Name: "web", Rule: hostSNI("*"), ServiceName: "svc", Entrypoints: []string{" "}}
	if err := emptyEntrypoint.Validate(); err == nil {
		t.Fatal("expected error for blank entrypoint name")
	}
}

func TestTCPRouterValidate_RawRequiresCatchAll(t *testing.T) {
	rawConcrete := TCPRouter{Name: "raw", Rule: hostSNI("a.com"), ServiceName: "svc", TLSPassthrough: false}
	if err := rawConcrete.Validate(); err == nil || !strings.Contains(err.Error(), "catch-all") {
		t.Fatalf("expected raw+concrete-SNI rejection, got %v", err)
	}

	rawCatchAll := TCPRouter{Name: "raw", Rule: hostSNI("*"), ServiceName: "svc", TLSPassthrough: false}
	if err := rawCatchAll.Validate(); err != nil {
		t.Fatalf("raw catch-all should be valid: %v", err)
	}

	passthroughConcrete := TCPRouter{Name: "tls", Rule: hostSNI("a.com"), ServiceName: "svc", TLSPassthrough: true}
	if err := passthroughConcrete.Validate(); err != nil {
		t.Fatalf("passthrough with concrete SNI should be valid: %v", err)
	}
}

func TestTCPServiceValidate(t *testing.T) {
	ok := TCPService{Name: "s", Endpoints: []Endpoint{{Address: "10.0.0.1", Port: 80}}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid service: %v", err)
	}
	both := TCPService{Name: "s", Endpoints: []Endpoint{{Address: "10.0.0.1", Port: 80}}, Weighted: []WeightedService{{Name: "x", Weight: 1}}}
	if err := both.Validate(); err == nil {
		t.Fatal("expected error combining endpoints and weighted")
	}
	empty := TCPService{Name: "s"}
	if err := empty.Validate(); err == nil {
		t.Fatal("expected error for empty service")
	}
}

func TestTCPConfigurationResolveTCPServiceFlattensWeights(t *testing.T) {
	cfg := TCPConfiguration{Services: map[string]TCPService{
		"blue":    {Name: "blue", Endpoints: []Endpoint{{Address: "10.0.0.1", Port: 1}}},
		"green":   {Name: "green", Endpoints: []Endpoint{{Address: "10.0.0.2", Port: 2}}},
		"rollout": {Name: "rollout", Weighted: []WeightedService{{Name: "blue", Weight: 9}, {Name: "green", Weight: 1}}},
	}}
	resolved, err := cfg.ResolveTCPService("rollout")
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 2 || resolved[0].Name != "blue" || resolved[0].Weight != 9 || resolved[1].Name != "green" || resolved[1].Weight != 1 {
		t.Fatalf("resolved = %+v", resolved)
	}
}

func TestTCPConfigurationResolveTCPServiceDetectsCycles(t *testing.T) {
	cfg := TCPConfiguration{Services: map[string]TCPService{
		"a": {Name: "a", Weighted: []WeightedService{{Name: "b", Weight: 1}}},
		"b": {Name: "b", Weighted: []WeightedService{{Name: "a", Weight: 1}}},
	}}
	if _, err := cfg.ResolveTCPService("a"); err == nil {
		t.Fatal("expected cycle error")
	}
}

func TestTCPPrecedence_ExplicitPriorityWins(t *testing.T) {
	high := TCPRouter{Name: "high", Priority: 10, PrioritySet: true}
	low := TCPRouter{Name: "low", RuleExpr: "HostSNI(a.very.long.hostname.example.com)"}
	if !TCPPrecedence(high, low) {
		t.Fatal("explicit priority should beat rule specificity")
	}
}

func TestTCPPrecedence_RuleSpecificityThenName(t *testing.T) {
	longRule := TCPRouter{Name: "z", RuleExpr: "HostSNI(a.very.long.hostname.example.com)"}
	shortRule := TCPRouter{Name: "a", RuleExpr: "HostSNI(a.com)"}
	if !TCPPrecedence(longRule, shortRule) {
		t.Fatal("longer rule expression should sort first")
	}
	sameLen1 := TCPRouter{Name: "a", RuleExpr: "HostSNI(x)"}
	sameLen2 := TCPRouter{Name: "b", RuleExpr: "HostSNI(y)"}
	if !TCPPrecedence(sameLen1, sameLen2) {
		t.Fatal("equal specificity should tie-break by ascending name")
	}
}

func TestSortTCPRoutersByPrecedence(t *testing.T) {
	routers := []TCPRouter{
		{Name: "b", RuleExpr: "HostSNI(a.com)"},
		{Name: "explicit", Priority: 5, PrioritySet: true, RuleExpr: "HostSNI(x)"},
		{Name: "a", RuleExpr: "HostSNI(a.com)"},
	}
	sorted := SortTCPRoutersByPrecedence(routers)
	if sorted[0].Name != "explicit" {
		t.Fatalf("expected explicit-priority router first, got %+v", sorted)
	}
	if sorted[1].Name != "a" || sorted[2].Name != "b" {
		t.Fatalf("expected a before b on name tie-break, got %+v", sorted)
	}
}

func TestDetectTCPConflicts_OverlappingCatchAllsRejected(t *testing.T) {
	routers := []TCPRouter{
		{Name: "raw1", Rule: hostSNI("*")},
		{Name: "raw2", Rule: hostSNI("*")},
	}
	if err := DetectTCPConflicts(routers, "web"); err == nil {
		t.Fatal("expected conflict between two equal-priority catch-alls")
	}
}

func TestDetectTCPConflicts_OverlappingConcreteSNIRejected(t *testing.T) {
	routers := []TCPRouter{
		{Name: "r1", Rule: hostSNI("a.com"), TLSPassthrough: true},
		{Name: "r2", Rule: hostSNI("a.com"), TLSPassthrough: true},
	}
	if err := DetectTCPConflicts(routers, "web"); err == nil {
		t.Fatal("expected conflict between two routers matching the identical SNI")
	}
}

func TestDetectTCPConflicts_DistinctPrioritiesStillConflict(t *testing.T) {
	// Envoy filter-chain matching is structural: identical SNI matches are
	// duplicate FilterChainMatch entries that Envoy NACKs regardless of
	// chain order, so explicit priorities cannot disambiguate them.
	routers := []TCPRouter{
		{Name: "r1", Rule: hostSNI("a.com"), TLSPassthrough: true, Priority: 10, PrioritySet: true},
		{Name: "r2", Rule: hostSNI("a.com"), TLSPassthrough: true, Priority: 5, PrioritySet: true},
	}
	if err := DetectTCPConflicts(routers, "web"); err == nil {
		t.Fatal("identical SNI with distinct priorities must still conflict (duplicate Envoy filter-chain match)")
	}
}

func TestTCPFilterChainOverlap(t *testing.T) {
	a := TCPRouter{Name: "a", Rule: hostSNI("x.com"), TLSPassthrough: true, Priority: 10, PrioritySet: true}
	b := TCPRouter{Name: "b", Rule: hostSNI("x.com"), TLSPassthrough: true, Priority: 5, PrioritySet: true}
	if !TCPFilterChainOverlap(a, b) {
		t.Fatal("identical SNI sets must overlap regardless of priority")
	}
	c := TCPRouter{Name: "c", Rule: hostSNI("y.com"), TLSPassthrough: true}
	if TCPFilterChainOverlap(a, c) {
		t.Fatal("disjoint SNI sets must not overlap")
	}
}

func TestDetectTCPConflicts_ConcreteAndCatchAllCoexist(t *testing.T) {
	routers := []TCPRouter{
		{Name: "specific", Rule: hostSNI("a.com"), TLSPassthrough: true},
		{Name: "fallback", Rule: hostSNI("*"), TLSPassthrough: true},
	}
	if err := DetectTCPConflicts(routers, "web"); err != nil {
		t.Fatalf("a concrete match and the catch-all should coexist: %v", err)
	}
}

func TestDetectTCPConflicts_DisjointSNIAllowed(t *testing.T) {
	routers := []TCPRouter{
		{Name: "r1", Rule: hostSNI("a.com"), TLSPassthrough: true},
		{Name: "r2", Rule: hostSNI("b.com"), TLSPassthrough: true},
	}
	if err := DetectTCPConflicts(routers, "web"); err != nil {
		t.Fatalf("disjoint SNI values should not conflict: %v", err)
	}
}

func TestDetectTCPConflicts_DifferentTLSModesNeverOverlap(t *testing.T) {
	routers := []TCPRouter{
		{Name: "raw", Rule: hostSNI("*"), TLSPassthrough: false},
		{Name: "passthrough", Rule: hostSNI("*"), TLSPassthrough: true},
	}
	if err := DetectTCPConflicts(routers, "web"); err != nil {
		t.Fatalf("raw and passthrough catch-alls occupy disjoint Envoy transport_protocol matches: %v", err)
	}
}

func TestDetectTCPConflicts_IsDeterministicAcrossOrderings(t *testing.T) {
	a := TCPRouter{Name: "aaa", Rule: hostSNI("dup.com"), TLSPassthrough: true}
	b := TCPRouter{Name: "bbb", Rule: hostSNI("dup.com"), TLSPassthrough: true}
	err1 := DetectTCPConflicts([]TCPRouter{a, b}, "web")
	err2 := DetectTCPConflicts([]TCPRouter{b, a}, "web")
	if err1 == nil || err2 == nil {
		t.Fatal("expected both orderings to detect the conflict")
	}
	if err1.Error() != err2.Error() {
		t.Fatalf("conflict message must be deterministic regardless of input order: %q vs %q", err1, err2)
	}
}
