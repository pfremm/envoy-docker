package xds

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	xdscorev3 "github.com/cncf/xds/go/xds/core/v3"
	xdsmatcherv3 "github.com/cncf/xds/go/xds/type/matcher/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	customresponsev3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/custom_response/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	redirectpolicyv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/http/custom_response/redirect_policy/v3"
	statuscodev3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
)

// customResponseFilterName is Envoy's native custom_response HTTP filter,
// used to implement the errors middleware's internal redirect to a named
// error-page service. It must run on the response path before the router
// entry is unwound; ordering relative to other filters does not matter for
// correctness (it inspects the upstream response, not the request), but it
// is placed with the other per-route decorators, before the router filter.
const customResponseFilterName = "envoy.filters.http.custom_response"

// errorPageHostPrefix / errorPageHostSuffix name the synthetic,
// client-unreachable virtual host domain the errors middleware's internal
// redirect targets. Envoy's custom_response redirect_policy internally
// redirects by rewriting the request's :authority and letting the router
// re-match a route, so the target must be an ordinary virtual host in the
// same RDS route configuration; nothing outside this control plane ever
// sees or resolves this domain.
const (
	errorPageHostPrefix = "errorpage--"
	errorPageHostSuffix = ".internal-error-svc"
)

// errorPageHost derives the synthetic internal virtual host domain for a
// named HTTP service used as an errors.service target.
func errorPageHost(serviceName string) string {
	return errorPageHostPrefix + sanitizeClusterName(serviceName) + errorPageHostSuffix
}

// customResponseHTTPFilter is the listener-level filter registration. Its
// own default config is a pass-through (no matcher); every actual behavior
// is installed as a per-route override via TypedPerFilterConfig, exactly
// like the mutation/CORS filters.
func customResponseHTTPFilter() *hcmv3.HttpFilter {
	return &hcmv3.HttpFilter{
		Name:       customResponseFilterName,
		ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: mustAny(&customresponsev3.CustomResponse{})},
	}
}

// statusCodeRange is an inclusive [Start,End] HTTP status range parsed from
// one errors.status entry ("404" parses to {404,404}; "500-599" to
// {500,599}). Validation in the model package already rejected malformed
// entries and out-of-range values, so parse errors here are unreachable in
// practice and are treated defensively (skip the entry) rather than panicking.
type statusCodeRange struct{ start, end int }

func parseStatusEntries(entries []string) []statusCodeRange {
	ranges := make([]statusCodeRange, 0, len(entries))
	for _, s := range entries {
		if start, end, ok := strings.Cut(s, "-"); ok {
			lo, err1 := strconv.Atoi(strings.TrimSpace(start))
			hi, err2 := strconv.Atoi(strings.TrimSpace(end))
			if err1 != nil || err2 != nil {
				continue
			}
			ranges = append(ranges, statusCodeRange{lo, hi})
		} else {
			code, err := strconv.Atoi(strings.TrimSpace(s))
			if err != nil {
				continue
			}
			ranges = append(ranges, statusCodeRange{code, code})
		}
	}
	return ranges
}

// statusCodeFieldMatchers expands parsed status ranges into custom_response
// matcher-list field matchers. A range that exactly spans one HTTP status
// class (e.g. 500-599) uses Envoy's class matcher for a compact, canonical
// config; any other range (including a single code) is expanded into exact
// per-code matchers. All matchers for one errors middleware share the same
// on_match action, so a request matches this middleware's redirect if ANY of
// its status entries match.
func statusCodeFieldMatchers(ranges []statusCodeRange, onMatch *xdsmatcherv3.Matcher_OnMatch) []*xdsmatcherv3.Matcher_MatcherList_FieldMatcher {
	var out []*xdsmatcherv3.Matcher_MatcherList_FieldMatcher
	seenExact := map[int]bool{}
	seenClass := map[int]bool{}
	for _, r := range ranges {
		if r.start%100 == 0 && r.end == r.start+99 {
			class := r.start / 100
			if seenClass[class] {
				continue
			}
			seenClass[class] = true
			out = append(out, fieldMatcher(classMatchInput(), fmt.Sprintf("%dxx", class), onMatch))
			continue
		}
		for code := r.start; code <= r.end; code++ {
			if seenExact[code] {
				continue
			}
			seenExact[code] = true
			out = append(out, fieldMatcher(statusMatchInput(), strconv.Itoa(code), onMatch))
		}
	}
	return out
}

func statusMatchInput() *xdscorev3.TypedExtensionConfig {
	return &xdscorev3.TypedExtensionConfig{
		Name:        "envoy.matching.inputs.status_code",
		TypedConfig: mustAny(&statuscodev3.HttpResponseStatusCodeMatchInput{}),
	}
}

func classMatchInput() *xdscorev3.TypedExtensionConfig {
	return &xdscorev3.TypedExtensionConfig{
		Name:        "envoy.matching.inputs.status_code_class",
		TypedConfig: mustAny(&statuscodev3.HttpResponseStatusCodeClassMatchInput{}),
	}
}

func fieldMatcher(input *xdscorev3.TypedExtensionConfig, exact string, onMatch *xdsmatcherv3.Matcher_OnMatch) *xdsmatcherv3.Matcher_MatcherList_FieldMatcher {
	return &xdsmatcherv3.Matcher_MatcherList_FieldMatcher{
		Predicate: &xdsmatcherv3.Matcher_MatcherList_Predicate{
			MatchType: &xdsmatcherv3.Matcher_MatcherList_Predicate_SinglePredicate_{
				SinglePredicate: &xdsmatcherv3.Matcher_MatcherList_Predicate_SinglePredicate{
					Input: input,
					Matcher: &xdsmatcherv3.Matcher_MatcherList_Predicate_SinglePredicate_ValueMatch{
						ValueMatch: &xdsmatcherv3.StringMatcher{MatchPattern: &xdsmatcherv3.StringMatcher_Exact{Exact: exact}},
					},
				},
			},
		},
		OnMatch: onMatch,
	}
}

// customResponsePerRoute builds the errors middleware's per-route
// custom_response override: a matcher list over the configured status
// codes/ranges, each entry redirecting internally to the named error
// service's synthetic virtual host. query, when set, becomes the fixed
// path of the redirected request; when empty the original request path is
// preserved (RedirectAction leaves an unset path specifier unchanged).
func customResponsePerRoute(e *model.ErrorsMiddleware) *customresponsev3.CustomResponse {
	redirectAction := &routev3.RedirectAction{
		HostRedirect: errorPageHost(e.Service),
	}
	if e.Query != "" {
		redirectAction.PathRewriteSpecifier = &routev3.RedirectAction_PathRedirect{PathRedirect: e.Query}
	}
	action := &xdsmatcherv3.Matcher_OnMatch{
		OnMatch: &xdsmatcherv3.Matcher_OnMatch_Action{
			Action: &xdscorev3.TypedExtensionConfig{
				Name: "action",
				TypedConfig: mustAny(&redirectpolicyv3.RedirectPolicy{
					RedirectActionSpecifier: &redirectpolicyv3.RedirectPolicy_RedirectAction{RedirectAction: redirectAction},
				}),
			},
		},
	}
	ranges := parseStatusEntries(e.Status)
	matchers := statusCodeFieldMatchers(ranges, action)
	return &customresponsev3.CustomResponse{
		CustomResponseMatcher: &xdsmatcherv3.Matcher{
			MatcherType: &xdsmatcherv3.Matcher_MatcherList_{
				MatcherList: &xdsmatcherv3.Matcher_MatcherList{Matchers: matchers},
			},
		},
	}
}

// errorServiceVirtualHosts builds one synthetic, client-unreachable virtual
// host per distinct named service referenced by an errors middleware, each
// with a single catch-all route to that service's cluster. resolveCluster
// maps a named errors.service target to its Envoy cluster name; it returns
// ok=false for an unresolvable name, which is a programming error by the
// time this is called (validation upstream already required errors.service
// to resolve) and is treated defensively by skipping that entry.
func errorServiceVirtualHosts(serviceNames []string, resolveCluster func(name string) (clusterName string, ok bool)) []*routev3.VirtualHost {
	names := append([]string(nil), serviceNames...)
	sort.Strings(names)
	names = dedupStrings(names)

	vhosts := make([]*routev3.VirtualHost, 0, len(names))
	for _, name := range names {
		clusterName, ok := resolveCluster(name)
		if !ok {
			continue
		}
		host := errorPageHost(name)
		vhosts = append(vhosts, &routev3.VirtualHost{
			Name:    "error_page_" + sanitizeClusterName(name),
			Domains: []string{host},
			Routes: []*routev3.Route{
				{
					Name:  "error_page_" + sanitizeClusterName(name),
					Match: &routev3.RouteMatch{PathSpecifier: &routev3.RouteMatch_Prefix{Prefix: "/"}},
					Action: &routev3.Route_Route{
						Route: &routev3.RouteAction{
							ClusterSpecifier: &routev3.RouteAction_Cluster{Cluster: clusterName},
						},
					},
				},
			},
		})
	}
	return vhosts
}

func dedupStrings(sorted []string) []string {
	out := sorted[:0:0]
	var prev string
	for i, s := range sorted {
		if i == 0 || s != prev {
			out = append(out, s)
		}
		prev = s
	}
	return out
}

// validateNoErrorRecursion enforces that a named HTTP service used as an
// errors.service target is never itself served by an application route that
// carries its own errors middleware. Without this, an error page backend
// that itself errors could re-trigger custom_response handling indefinitely
// (or at least unpredictably), which the task requires be rejected outright
// rather than silently allowed.
func validateNoErrorRecursion(routes map[string]model.Route) error {
	// errorTargets maps a named service used as an error target to the
	// middleware/route that references it, for actionable error messages.
	errorTargets := map[string]string{}
	names := sortedSubdomains(routes)
	for _, name := range names {
		route := routes[name]
		for _, m := range route.Middlewares {
			if m.Errors != nil {
				if prior, exists := errorTargets[m.Errors.Service]; exists && prior != m.Name {
					// Multiple middlewares may legitimately target the same
					// error service; only record the first for messaging.
					continue
				}
				errorTargets[m.Errors.Service] = m.Name
			}
		}
	}
	if len(errorTargets) == 0 {
		return nil
	}
	for _, name := range names {
		route := routes[name]
		if route.ServiceName == "" {
			continue
		}
		if _, isErrorTarget := errorTargets[route.ServiceName]; !isErrorTarget {
			continue
		}
		for _, m := range route.Middlewares {
			if m.Errors != nil {
				return fmt.Errorf(
					"router %q serves named service %q, which is also the errors.service target of middleware %q; an error-page service cannot itself carry an errors middleware (no recursive error handling)",
					route.RouterName, route.ServiceName, errorTargets[route.ServiceName])
			}
		}
	}
	return nil
}
