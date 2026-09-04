package model

import "sort"

// Precedence returns a deterministic total order over routes for use as the
// order of generated Envoy routes within a virtual host. Envoy evaluates
// routes top-to-bottom and the first match wins, so the most specific
// (highest-precedence) route must come first.
//
// Ordering, most-precedent first:
//  1. Explicit priority: routes that set a priority sort by it, descending.
//     An explicit priority always wins over a route without one.
//  2. Rule specificity: among routes without an explicit priority, the
//     longer (more specific) rule string sorts first. Legacy subdomain
//     routes (no rule) have specificity 0 and sort last.
//  3. Router name: a stable, deterministic tie-breaker (ascending).
//
// The comparison is a total order, so it is safe to use directly with
// sort.SliceStable / sort.Slice.
func Precedence(a, b Route) bool {
	// Tier 1: explicit priority. A route with an explicit priority beats one
	// without; two explicit priorities compare numerically (higher first).
	if a.PrioritySet != b.PrioritySet {
		return a.PrioritySet
	}
	if a.PrioritySet && b.PrioritySet {
		if a.Priority != b.Priority {
			return a.Priority > b.Priority
		}
		// Equal explicit priority: fall through to specificity/name.
	}
	// Tier 2: rule specificity (length of the canonical rule string).
	la, lb := ruleSpecificity(a), ruleSpecificity(b)
	if la != lb {
		return la > lb
	}
	// Tier 3: stable router-name tie-breaker (ascending).
	return a.RouterName < b.RouterName
}

// ruleSpecificity returns the specificity proxy for a route: the length of
// its rule expression. Legacy subdomain routes (no rule) have specificity 0.
func ruleSpecificity(r Route) int {
	if r.RuleExpr == "" {
		return 0
	}
	return len(r.RuleExpr)
}

// SortByPrecedence returns the routes sorted so the highest-precedence route
// comes first (the order Envoy should evaluate them in). The input slice is
// not mutated.
func SortByPrecedence(routes []Route) []Route {
	out := make([]Route, len(routes))
	copy(out, routes)
	sort.SliceStable(out, func(i, j int) bool {
		return Precedence(out[i], out[j])
	})
	return out
}
