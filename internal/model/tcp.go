package model

import (
	"fmt"
	"sort"
	"strings"
)

// tcpRouterLabelPrefix is the label namespace TCP routers live under. It is
// declared here (rather than in dockerwatch) so model validation messages can
// reference the exact label a user must set.
const tcpRouterLabelPrefix = "envoy.tcp.routers."

// TCPRouter describes one label-driven TCP router: a boolean SNI rule, the
// named TCP service it forwards to, the entrypoint names it is served on, an
// optional explicit priority, and whether the traffic is TLS passthrough.
//
// A TCP router is the TCP analogue of an HTTP router (Route): it is
// discovered from envoy.tcp.routers.<name>.* labels and translated by the
// xDS layer into listener filter chains. Unlike HTTP routes it never touches
// the HTTP connection manager: passthrough and raw chains carry only a
// tcp_proxy (and, for passthrough, a TLS transport socket + inspector).
type TCPRouter struct {
	// Name is the router's label name (the <name> in
	// envoy.tcp.routers.<name>.*), used as the stable tie-breaker in
	// precedence ordering and in conflict diagnostics.
	Name string
	// Rule is the parsed SNI rule (HostSNI atoms only). Empty (Node == nil)
	// is rejected at parse time: a TCP router must have a rule.
	Rule Rule
	// RuleExpr is the original rule expression string, kept for logging.
	RuleExpr string
	// ServiceName references a separately modeled named TCP service.
	ServiceName string
	// Entrypoints is the list of TCP entrypoint names this router is served
	// on. Empty means the default entrypoint (the first configured one).
	Entrypoints []string
	// Priority is an explicit integer priority; higher wins. A router with
	// PrioritySet=true always beats one without, regardless of rule length.
	Priority    int
	PrioritySet bool
	// TLSPassthrough selects TLS passthrough (encrypted bytes forwarded
	// untouched, matched on SNI via the TLS inspector) over raw TCP.
	TLSPassthrough bool
	// Origin is a human-readable identifier of what produced this router
	// (container name + router name) for log messages.
	Origin string
}

// String renders the router for diagnostics.
func (r TCPRouter) String() string {
	mode := "raw"
	if r.TLSPassthrough {
		mode = "tls-passthrough"
	}
	return fmt.Sprintf("tcp router %q (%s, service %s, entrypoints %v)", r.Name, mode, r.ServiceName, r.Entrypoints)
}

// SNIValues returns the sorted set of concrete SNI values in the rule
// (across the whole tree, ignoring negation). The catch-all "*" is included
// when present. Deterministic order.
func (r TCPRouter) SNIValues() []string {
	seen := map[string]bool{}
	var walk func(n *Node)
	walk = func(n *Node) {
		if n == nil {
			return
		}
		switch n.Op {
		case OpAtom:
			if n.Atom != nil && n.Atom.Kind == KindSNI {
				seen[n.Atom.Value] = true
			}
		case OpNot, OpAnd, OpOr:
			walk(n.Left)
			if n.Op != OpNot {
				walk(n.Right)
			}
		}
	}
	walk(r.Rule.Node)
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// HasCatchAll reports whether the rule contains the SNI catch-all "*"
// (ignoring negation). A catch-all router matches any SNI on its entrypoint.
func (r TCPRouter) HasCatchAll() bool {
	for _, s := range r.SNIValues() {
		if s == "*" {
			return true
		}
	}
	return false
}

// Validate checks a TCPRouter's structural invariants.
func (r TCPRouter) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("tcp router name is empty")
	}
	if r.Rule.Node == nil {
		return fmt.Errorf("tcp router %q has no rule (a HostSNI(...) rule is required)", r.Name)
	}
	if err := r.Rule.SNITranslatable(); err != nil {
		return fmt.Errorf("tcp router %q: %w", r.Name, err)
	}
	if r.ServiceName == "" {
		return fmt.Errorf("tcp router %q has no service (set %s%s.service)", r.Name, tcpRouterLabelPrefix, r.Name)
	}
	for _, ep := range r.Entrypoints {
		if strings.TrimSpace(ep) == "" {
			return fmt.Errorf("tcp router %q has an empty entrypoint name", r.Name)
		}
	}
	if !r.TLSPassthrough && !r.isCatchAllOnly() {
		return fmt.Errorf("tcp router %q is raw TCP (tls.passthrough=false) but its rule is not the catch-all HostSNI(*); raw TCP has no TLS inspection and cannot match on SNI. Use HostSNI(*) for raw TCP, or set tls.passthrough=true to match on SNI", r.Name)
	}
	return nil
}

// isCatchAllOnly reports whether the rule is exactly the single atom
// HostSNI(*), with no other structure. Raw TCP routers (no TLS inspection)
// can only ever be the catch-all, since matching a concrete SNI value
// requires the TLS inspector to have read the ClientHello first.
func (r TCPRouter) isCatchAllOnly() bool {
	n := r.Rule.Node
	return n != nil && n.Op == OpAtom && n.Atom != nil && n.Atom.Kind == KindSNI && n.Atom.Value == "*"
}

// SNITranslatable reports whether the rule can be expressed as Envoy
// filter-chain SNI matching, returning an actionable error otherwise. Only
// HostSNI atoms are allowed (HTTP-only matchers like Path/Headers are
// meaningless at the TCP layer), and negation is rejected because Envoy
// filter-chain matching has no invert for server_names.
func (r Rule) SNITranslatable() error {
	if r.Node == nil {
		return fmt.Errorf("rule is empty")
	}
	terms, err := r.ToDNF()
	if err != nil {
		return err
	}
	for _, term := range terms {
		for _, e := range term {
			if e.Negated {
				return fmt.Errorf("negation (!) is not supported in TCP SNI rules; Envoy filter-chain matching cannot express !HostSNI(...). Remove the negation")
			}
			if e.Atom.Kind != KindSNI {
				return fmt.Errorf("%s(...) is an HTTP matcher and cannot be used in a TCP router rule; only HostSNI(...) is supported", e.Atom.Kind.Name())
			}
		}
	}
	return nil
}

// TCPService is a named multi-endpoint TCP backend, the TCP analogue of
// HTTPService. It carries a flat list of endpoints (plain named
// multi-endpoint service is the mandatory form) plus optional weighted
// targets mirroring the HTTP naming, for weighted TCP load balancing.
type TCPService struct {
	Name      string
	Endpoints []Endpoint
	Weighted  []WeightedService
	Origin    string
	// DiscoveryNetwork records the effective Docker network so conflicting
	// discovery policies are not silently merged.
	DiscoveryNetwork string
}

// Validate checks a TCPService's structural invariants.
func (s TCPService) Validate() error {
	if s.Name == "" {
		return fmt.Errorf("tcp service name is empty")
	}
	if len(s.Endpoints) > 0 && len(s.Weighted) > 0 {
		return fmt.Errorf("tcp service %q cannot define both loadbalancer servers and weighted services", s.Name)
	}
	if len(s.Endpoints) == 0 && len(s.Weighted) == 0 {
		return fmt.Errorf("tcp service %q has no servers or weighted services", s.Name)
	}
	for i, ep := range s.Endpoints {
		if ep.Address == "" || ep.Port == 0 {
			return fmt.Errorf("tcp service %q has invalid endpoint %d (%q:%d)", s.Name, i, ep.Address, ep.Port)
		}
	}
	for _, w := range s.Weighted {
		if w.Name == "" || w.Weight == 0 {
			return fmt.Errorf("tcp service %q has invalid weighted target %q with weight %d", s.Name, w.Name, w.Weight)
		}
	}
	return nil
}

// NamedTCPServiceClusterName returns the Envoy cluster name for a named TCP
// service. The "tcp-service/" prefix namespaces it away from HTTP service
// clusters ("http-service/") and legacy route clusters (bare subdomain).
func NamedTCPServiceClusterName(name string) string { return "tcp-service/" + name }

// TCPPrecedence returns a deterministic total order over TCP routers within
// one entrypoint, using the same tiering as the HTTP Precedence function:
// explicit priority (descending), then rule specificity (the length of the
// canonical rule string, descending), then router name (ascending) as a
// stable tie-breaker. It is a total order, safe for sort.SliceStable.
func TCPPrecedence(a, b TCPRouter) bool {
	if a.PrioritySet != b.PrioritySet {
		return a.PrioritySet
	}
	if a.PrioritySet && b.PrioritySet && a.Priority != b.Priority {
		return a.Priority > b.Priority
	}
	la, lb := len(a.RuleExpr), len(b.RuleExpr)
	if la != lb {
		return la > lb
	}
	return a.Name < b.Name
}

// SortTCPRoutersByPrecedence returns the routers sorted so the
// highest-precedence router comes first. The input slice is not mutated.
func SortTCPRoutersByPrecedence(routers []TCPRouter) []TCPRouter {
	out := make([]TCPRouter, len(routers))
	copy(out, routers)
	sort.SliceStable(out, func(i, j int) bool {
		return TCPPrecedence(out[i], out[j])
	})
	return out
}

// samePriorityTier reports whether two TCP routers are in the same
// precedence tier for conflict-detection purposes: both explicit with an
// equal numeric priority, or both implicit (no explicit priority at all).
// A router with an explicit priority never ties with one without, mirroring
// tier 1 of TCPPrecedence.
func samePriorityTier(a, b TCPRouter) bool {
	if a.PrioritySet != b.PrioritySet {
		return false
	}
	if a.PrioritySet {
		return a.Priority == b.Priority
	}
	return true
}

// sniOverlap reports whether two routers would produce ambiguous Envoy
// filter-chain matches within the SAME TLS mode (passthrough or raw):
// either both are pure catch-alls (there can only be one implicit
// "everything else" chain per entrypoint+TLS-mode), or their concrete SNI
// value sets intersect (Envoy's FilterChainMatch has no priority concept,
// so two chains matching the identical server name is a duplicate match
// Envoy itself would reject). Different TLS modes never overlap: passthrough
// chains match transport_protocol "tls" and raw chains match
// transport_protocol "raw_buffer", so they are already mutually exclusive at
// the Envoy filter-chain-match level. A catch-all against a concrete value
// (within the same mode) is NOT an overlap: Envoy's filter-chain matching
// always prefers the more specific (concrete) match over the fallback, with
// no ambiguity and no need for an explicit priority to arbitrate it.
func sniOverlap(a, b TCPRouter) bool {
	if a.TLSPassthrough != b.TLSPassthrough {
		return false
	}
	aCatch, bCatch := a.HasCatchAll(), b.HasCatchAll()
	if aCatch && bCatch {
		return true
	}
	if aCatch != bCatch {
		return false
	}
	av, bv := a.SNIValues(), b.SNIValues()
	bset := make(map[string]bool, len(bv))
	for _, v := range bv {
		bset[v] = true
	}
	for _, v := range av {
		if v == "*" {
			continue
		}
		if bset[v] {
			return true
		}
	}
	return false
}

// DetectTCPConflicts returns a deterministic, actionable error if any two
// routers among the given set (already known to share one entrypoint and TLS
// mode) are in the same precedence tier (see samePriorityTier) with
// overlapping SNI match domains (see sniOverlap): Envoy's filter-chain
// matching would then have no principled way to prefer one over the other,
// and which one an implementation picks must not depend on map iteration
// order. Routers are compared in a name-sorted order so the reported pair
// (and thus the error message) is itself deterministic across runs.
func DetectTCPConflicts(routers []TCPRouter, entrypoint string) error {
	sorted := make([]TCPRouter, len(routers))
	copy(sorted, routers)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			a, b := sorted[i], sorted[j]
			if !samePriorityTier(a, b) {
				continue
			}
			if !sniOverlap(a, b) {
				continue
			}
			tier := "no explicit priority"
			if a.PrioritySet {
				tier = fmt.Sprintf("priority %d", a.Priority)
			}
			return fmt.Errorf(
				"ambiguous TCP routers %q and %q on entrypoint %q: both have %s and overlapping SNI match (%v vs %v); "+
					"set distinct .priority values or make their HostSNI(...) rules non-overlapping",
				a.Name, b.Name, entrypoint, tier, a.SNIValues(), b.SNIValues())
		}
	}
	return nil
}

// TCPConfiguration is the unified TCP routing input: routers and the named
// services they reference. It is carried alongside HTTPConfiguration in the
// watcher's per-update payload.
type TCPConfiguration struct {
	Routers  map[string]TCPRouter
	Services map[string]TCPService
}

// ResolveTCPService expands a named TCP service's weighted targets (if any)
// into a flat, weight-adjusted list of leaf services, mirroring
// HTTPConfiguration.ResolveService. A service with no weighted targets
// resolves to itself with weight 1.
func (c TCPConfiguration) ResolveTCPService(name string) ([]ResolvedService, error) {
	weights := map[string]uint64{}
	stack := map[string]bool{}
	var walk func(string, uint64) error
	walk = func(current string, multiplier uint64) error {
		s, ok := c.Services[current]
		if !ok {
			return fmt.Errorf("tcp service %q references unknown service %q", name, current)
		}
		if stack[current] {
			return fmt.Errorf("weighted tcp service cycle detected at %q while resolving %q", current, name)
		}
		if err := s.Validate(); err != nil {
			return err
		}
		if len(s.Weighted) == 0 {
			weights[current] += multiplier
			return nil
		}
		stack[current] = true
		defer delete(stack, current)
		for _, child := range s.Weighted {
			if err := walk(child.Name, multiplier*uint64(child.Weight)); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(name, 1); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(weights))
	for n := range weights {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]ResolvedService, 0, len(names))
	for _, n := range names {
		out = append(out, ResolvedService{Name: n, Weight: uint32(weights[n])})
	}
	return out, nil
}
