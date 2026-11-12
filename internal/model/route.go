// Package model holds the route representation shared between the docker
// watcher, the static config loader, and the xDS snapshot builder.
package model

import (
	"fmt"
	"time"
)

// Endpoint is a single backend address:port a route can be load balanced to.
type Endpoint struct {
	Address string
	Port    uint32
}

// Source identifies where a Route was discovered, for logging/diagnostics.
type Source string

const (
	SourceDocker Source = "docker"
	SourceStatic Source = "static"
)

// Route describes one subdomain's worth of routing: the unique subdomain
// label and the set of backend endpoints to load balance across.
//
// Milestone 1 extends Route with an optional typed matcher AST (Rule), the
// original rule expression (RuleExpr), an optional explicit integer
// priority (Priority/PrioritySet), and the originating router name
// (RouterName). These fields are empty for legacy subdomain-only routes,
// which match every path on their subdomain (catch-all prefix "/").
type Route struct {
	Subdomain string
	Endpoints []Endpoint
	Source    Source
	// Origin is a human-readable identifier of what produced this route
	// (container name, or static config entry index) used in log messages.
	Origin string

	// Rule is the parsed, typed matcher expression for this route. It is
	// empty (Rule.Node == nil) for legacy subdomain-only routes. When set,
	// it fully determines which requests the route handles.
	Rule Rule
	// RuleExpr is the original rule expression string, kept for logging and
	// as a deterministic specificity proxy when no explicit priority is set.
	RuleExpr string
	// Priority is an explicit integer priority. Higher wins. A route with
	// PrioritySet=true always beats one without, regardless of rule length.
	Priority    int
	PrioritySet bool
	// RouterName is the router's label name (the <name> in
	// envoy.http.routers.<name>.*). Used as the stable tie-breaker in
	// precedence ordering.
	RouterName string

	// ServiceName references a separately modeled named HTTP service. Empty
	// preserves the legacy implicit service represented by Endpoints.
	ServiceName string
	Timeout     *time.Duration
	IdleTimeout *time.Duration
	Retry       *RetryPolicy
	// WebSocketDisabled is the .websocket=false opt-out. WebSocket upgrades
	// are enabled on every HTTP connection manager by default; when set, the
	// router's routes disable the websocket upgrade at route level.
	WebSocketDisabled bool
	// MiddlewareNames preserves the router label's explicit chain. Middlewares
	// contains the validated typed definitions in the same execution order.
	MiddlewareNames []string
	Middlewares     []Middleware
	// DiscoveryNetwork records the effective Docker network so replica
	// definitions with conflicting discovery policy are not silently merged.
	DiscoveryNetwork string

	// Entrypoints is the list of HTTP entrypoint names this router is served
	// on, from the .entrypoints label. Entrypoint names are a daemon/operator
	// configuration (HTTP_ENTRYPOINTS); a label can only select among them,
	// never bind a new host socket. Empty means the default HTTP/HTTPS
	// entrypoints (legacy behavior).
	Entrypoints []string
	// Tracing carries the per-route tracing hooks (.tracing /
	// .tracing.operationname). A nil Tracing means the hook is unset: tracing
	// follows the listener/HCM default.
	Tracing *TracingConfig
	// AccessLog, when non-nil, records the .accesslog hook (true|false). It is
	// carried as route metadata: Envoy access logging is listener-scoped (there
	// is no per-route access-log field in the pinned API), so this is a
	// declarative carrier of intent, not a per-route log toggle (see LABELS.md
	// limitations).
	AccessLog *bool

	// ClusterKey, when non-empty, overrides the derived Envoy cluster and
	// endpoint (CLA) name for this route (see ClusterName). Discovery sets
	// it when several DISTINCT routers share one subdomain: every router is
	// preserved through to xDS precedence evaluation, so each needs its own
	// cluster instead of colliding on the shared subdomain name. Empty means
	// the legacy behavior (cluster named after the subdomain).
	ClusterKey string

	// SSOProfile, when non-empty, is the .sso label: the name of an operator
	// SSO profile (SSO_CONFIG_PATH) that puts this router's whole virtual
	// host behind Envoy's oauth2 + jwt_authn filters. Empty means public.
	SSOProfile string
}

// TracingConfig is the per-route tracing configuration parsed from the
// .tracing and .tracing.operationname router labels.
type TracingConfig struct {
	// Enabled is the .tracing hook (true|false). When false the route
	// disables tracing for its traffic (0% sampling); when true it forces
	// tracing (100% sampling).
	Enabled bool
	// OperationName is the .tracing.operationname hook: the span operation
	// name for this route (the per-route analog of the route decorator).
	OperationName string
}

func (r Route) String() string {
	return fmt.Sprintf("%s (%s, %d endpoint(s), from %s)", r.Subdomain, r.Source, len(r.Endpoints), r.Origin)
}

// ClusterName returns the Envoy cluster/route name for this route. The
// highest-precedence route of a subdomain keeps the legacy behavior (the
// subdomain itself, which is unique per snapshot); a preserved
// lower-precedence route sharing that subdomain carries its own derived
// name in ClusterKey so both routes get distinct clusters/endpoints.
func (r Route) ClusterName() string {
	if r.ClusterKey != "" {
		return r.ClusterKey
	}
	return r.Subdomain
}
