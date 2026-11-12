// Package xds builds Envoy xDS resources (LDS/RDS/CDS/EDS) from a route map
// and serves them over ADS.
package xds

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	corsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/cors/v3"
	luav3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	routerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	xffv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/http/original_ip_detection/xff/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	cachetypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
	"github.com/bryanpfremm/envoy-control-plane/internal/sso"
)

const (
	httpsRouteConfigName = "https_routes"
	httpListenerName     = "http_listener"
	httpsListenerName    = "https_listener"

	transportSocketTLS = "envoy.transport_sockets.tls"
)

// Config is the static (non-route) input needed to build a snapshot.
type Config struct {
	BaseDomain         string
	HTTPPort           uint32
	HTTPSPort          uint32
	CertSecretName     string
	ACMESDSClusterName string

	// TCPEntrypoints maps a statically configured TCP entrypoint name to the
	// port its listener binds. Entrypoint addresses/ports are daemon
	// (operator) configuration, never derived from untrusted container
	// labels: a label can only select an entrypoint by name via
	// envoy.tcp.routers.<name>.entrypoints, never bind a new host socket.
	TCPEntrypoints map[string]uint32
	// DefaultTCPEntrypoint is the entrypoint name a TCP router with no
	// explicit .entrypoints label is served on. Empty means "the router
	// must set .entrypoints explicitly" (no implicit default).
	DefaultTCPEntrypoint string

	// HTTPEntrypoints maps a statically configured HTTP entrypoint name to
	// the port its listener binds. Entrypoint addresses/ports are daemon
	// (operator) configuration, never derived from untrusted container
	// labels: a label can only select an entrypoint by name via
	// envoy.http.routers.<name>.entrypoints, never bind a new host socket.
	// The default HTTP/HTTPS entrypoints (HTTPPort/HTTPSPort) always exist
	// and are the fallback for legacy routers that set no .entrypoints.
	HTTPEntrypoints map[string]uint32
	// DefaultHTTPEntrypoint is the entrypoint name an HTTP router with no
	// explicit .entrypoints label is served on. Empty means the router is
	// served on the default HTTP/HTTPS entrypoints (legacy behavior).
	DefaultHTTPEntrypoint string
	// DefaultHTTPEntrypoints is the ordered default list. The singular field
	// is retained for compatibility with existing callers.
	DefaultHTTPEntrypoints []string

	// Logger, when non-nil, receives warnings for label-derived problems
	// that are handled by skipping the offending router (unknown
	// entrypoint names, overlapping TCP filter-chain matches,
	// untranslatable rules). Label-derived input is untrusted, so such
	// problems never fail the whole snapshot: one bad container label must
	// not wedge config updates for every other container. A nil Logger
	// skips silently.
	Logger *slog.Logger

	// SSO is the operator's SSO profile config (SSO_CONFIG_PATH). Nil means
	// SSO is not configured: routers with an .sso label are rejected.
	SSO *sso.Config
}

// Merge combines docker-derived and static routes into one map keyed by
// subdomain. Static routes win on collision, since they represent explicit,
// deliberate configuration for non-docker backends rather than incidental
// container labeling.
func Merge(dockerRoutes, staticRoutes map[string]model.Route, logger *slog.Logger) map[string]model.Route {
	merged := make(map[string]model.Route, len(dockerRoutes)+len(staticRoutes))
	for subdomain, route := range staticRoutes {
		merged[subdomain] = route
	}
	for subdomain, route := range dockerRoutes {
		if existing, ok := merged[subdomain]; ok {
			logger.Warn("subdomain collision, keeping the static/first entry",
				"subdomain", subdomain, "kept_source", existing.Source, "kept_origin", existing.Origin,
				"skipped_source", route.Source, "skipped_origin", route.Origin)
			continue
		}
		merged[subdomain] = route
	}
	return merged
}

// BuildSnapshot turns a merged route map into a full xDS resource snapshot.
func BuildSnapshot(version string, routes map[string]model.Route, cfg Config) (cachev3.ResourceSnapshot, error) {
	return BuildSnapshotWithLogger(version, routes, cfg, nil)
}

// BuildSnapshotWithLogger is BuildSnapshot with an optional logger. When
// logger is non-nil, subdomains whose rule cannot be translated to an Envoy
// route match (e.g. ClientIP, or negation on a non-header matcher) are
// skipped with an actionable warning instead of failing the whole snapshot.
func BuildSnapshotWithLogger(version string, routes map[string]model.Route, cfg Config, logger *slog.Logger) (cachev3.ResourceSnapshot, error) {
	return BuildSnapshotWithLoggerAndTCP(version, routes, model.TCPConfiguration{}, cfg, logger)
}

// BuildSnapshotWithLoggerAndTCP extends BuildSnapshotWithLogger with TCP
// routers/services, contributing their own listeners and clusters/endpoints
// alongside the legacy HTTP-route-map path.
func BuildSnapshotWithLoggerAndTCP(version string, routes map[string]model.Route, tcpCfg model.TCPConfiguration, cfg Config, logger *slog.Logger) (cachev3.ResourceSnapshot, error) {
	if err := validateEntrypointPorts(cfg); err != nil {
		return nil, err
	}
	if err := validateNoErrorRecursion(routes); err != nil {
		return nil, err
	}

	// Group the routes by HTTP entrypoint. The default entrypoint (the
	// legacy HTTP/HTTPS pair) always exists and carries every router that
	// sets no .entrypoints label; each configured extra entrypoint carries
	// only the routers that explicitly select it. A router selecting an
	// entrypoint the daemon did not configure is skipped on that entrypoint
	// with a warning: entrypoint addresses/ports are operator
	// configuration, so a label can only SELECT among them, never conjure
	// a new bound socket — and an invalid selection must not wedge the
	// whole snapshot.
	if logger == nil {
		logger = cfg.Logger
	}
	routes = dedupeRouteNames(routes, logger)
	routes = filterSSORoutes(routes, cfg, logger)
	byEntrypoint, entrypointNames := groupRoutesByEntrypoint(routes, cfg, logger)

	// One RDS route configuration per entrypoint. The default entrypoint
	// keeps the legacy resource name (https_routes); extra entrypoints get
	// a namespaced name (https_routes__<entrypoint>).
	routeConfigs := make([]*routev3.RouteConfiguration, 0, len(entrypointNames))
	for _, ep := range entrypointNames {
		epRoutes := byEntrypoint[ep]
		name := httpsRouteConfigName
		if ep != defaultEntrypointName {
			name = httpsRouteConfigName + "__" + ep
		}
		rc := buildHTTPSRouteConfiguration(epRoutes, sortedSubdomains(epRoutes), cfg.BaseDomain, logger)
		rc.Name = name
		routeConfigs = append(routeConfigs, rc)
	}

	// The published set is the union across every entrypoint's route config:
	// a route is published (and gets a cluster/endpoint) if it is served on
	// any entrypoint.
	published := make(map[string]model.Route)
	for _, rc := range routeConfigs {
		for subdomain, route := range publishedRoutes(routes, rc) {
			published[subdomain] = route
		}
	}

	plan, err := planSecurity(published)
	if err != nil {
		return nil, fmt.Errorf("planning security middleware: %w", err)
	}

	clusters := make([]cachetypes.Resource, 0, len(published)+len(plan.authClusters))
	endpoints := make([]cachetypes.Resource, 0, len(published))
	clusterOwners := make(map[string]string, len(published)+len(plan.authClusters))
	for _, name := range sortedSubdomains(published) {
		route := published[name]
		if owner, exists := clusterOwners[route.ClusterName()]; exists {
			return nil, fmt.Errorf("xDS cluster name %q collides between %s and application route %q", route.ClusterName(), owner, name)
		}
		clusterOwners[route.ClusterName()] = fmt.Sprintf("application route %q", name)
		clusters = append(clusters, buildCluster(route.ClusterName()))
		endpoints = append(endpoints, buildClusterLoadAssignment(route))
	}
	for _, c := range plan.authClusters {
		if owner, exists := clusterOwners[c.Name]; exists {
			return nil, fmt.Errorf("xDS cluster name %q collides between %s and a forwardauth service", c.Name, owner)
		}
		clusterOwners[c.Name] = "forwardauth service"
		clusters = append(clusters, c)
	}

	// Circuit breakers are cluster-scoped: derive deterministic variant
	// clusters for routes whose circuitbreaker middleware policy differs
	// from sibling routes sharing the same base cluster, and apply the
	// policy directly when every sharer agrees (no variant needed).
	baseClusters := map[string]*clusterv3.Cluster{}
	baseEndpoints := map[string]*endpointv3.ClusterLoadAssignment{}
	for _, res := range clusters {
		if c, ok := res.(*clusterv3.Cluster); ok {
			baseClusters[c.Name] = c
		}
	}
	for _, res := range endpoints {
		if ep, ok := res.(*endpointv3.ClusterLoadAssignment); ok {
			baseEndpoints[ep.ClusterName] = ep
		}
	}
	var cbRefs []circuitBreakerRef
	for _, name := range sortedSubdomains(published) {
		route := published[name]
		for _, m := range route.Middlewares {
			if m.CircuitBreaker != nil {
				cbRefs = append(cbRefs, circuitBreakerRef{
					routeKey:    routeResourceName(route),
					baseCluster: route.ClusterName(),
					policy:      m.CircuitBreaker,
				})
			}
		}
	}
	if len(cbRefs) > 0 {
		variantClusters, variantEndpoints, routeOverride, err := planCircuitBreakerVariants(cbRefs, baseClusters, baseEndpoints)
		if err != nil {
			return nil, fmt.Errorf("planning circuit breaker variants: %w", err)
		}
		for _, c := range variantClusters {
			clusters = append(clusters, c)
		}
		for _, ep := range variantEndpoints {
			endpoints = append(endpoints, ep)
		}
		if len(routeOverride) > 0 {
			// A route name can appear in more than one entrypoint's route
			// config (a router served on several entrypoints); redirect every
			// occurrence to the same variant cluster.
			for _, rc := range routeConfigs {
				redirectRouteClusters(rc, routeOverride)
			}
		}
	}

	if len(plan.errorServiceNames) > 0 {
		errorVHosts := errorServiceVirtualHosts(plan.errorServiceNames, func(name string) (string, bool) {
			for _, r := range routes {
				if r.ServiceName == "" && r.Subdomain == name {
					return r.ClusterName(), true
				}
			}
			return "", false
		})
		// The error-service virtual hosts are attached to every entrypoint's
		// route config so error responses resolve on any entrypoint.
		for _, rc := range routeConfigs {
			rc.VirtualHosts = append(rc.VirtualHosts, errorVHosts...)
		}
	}

	// SSO runs after the error-service virtual hosts exist (so they get the
	// disabled overrides too) and before the security defaults (so the
	// synthesized callback routes get the ext_authz disabled override).
	ssoP := planSSO(routeConfigs, published, cfg, logger)
	for _, c := range ssoP.clusters {
		if owner, exists := clusterOwners[c.Name]; exists {
			return nil, fmt.Errorf("xDS cluster name %q collides between %s and an SSO profile IdP cluster", c.Name, owner)
		}
		clusterOwners[c.Name] = "SSO profile IdP cluster"
		clusters = append(clusters, c)
	}
	applySecurityDefaultsToAll(routeConfigs, plan)
	for _, rc := range routeConfigs {
		applyHSTS(rc)
	}

	// The default entrypoint's listeners are the legacy http_listener (plain
	// HTTP -> HTTPS redirect) and https_listener (TLS, RDS). Each extra
	// entrypoint gets its own TLS listener on its configured port, serving
	// its own RDS route config.
	listeners := []cachetypes.Resource{
		buildHTTPListener(cfg.HTTPPort, cfg.HTTPSPort),
		buildHTTPSListener(httpsListenerName, cfg.HTTPSPort, httpsRouteConfigName, cfg.CertSecretName, cfg.ACMESDSClusterName, plan, ssoP.byRouteConfig[httpsRouteConfigName]),
	}
	for _, ep := range entrypointNames {
		if ep == defaultEntrypointName {
			continue
		}
		port, ok := cfg.HTTPEntrypoints[ep]
		if !ok {
			return nil, fmt.Errorf("internal error: entrypoint %q has no configured port", ep)
		}
		listeners = append(listeners, buildHTTPSListener(
			httpsListenerName+"__"+ep, port, httpsRouteConfigName+"__"+ep,
			cfg.CertSecretName, cfg.ACMESDSClusterName, plan, ssoP.byRouteConfig[httpsRouteConfigName+"__"+ep]))
	}

	tcpListeners, tcpClusters, tcpEndpoints, err := buildTCPResources(tcpCfg, cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("building tcp resources: %w", err)
	}
	for _, c := range tcpClusters {
		name := c.(*clusterv3.Cluster).Name
		if owner, exists := clusterOwners[name]; exists {
			return nil, fmt.Errorf("xDS cluster name %q collides between %s and a tcp resource", name, owner)
		}
		clusterOwners[name] = "tcp resource"
	}
	clusters = append(clusters, tcpClusters...)
	endpoints = append(endpoints, tcpEndpoints...)
	listeners = append(listeners, tcpListeners...)

	routeConfigResources := make([]cachetypes.Resource, 0, len(routeConfigs))
	for _, rc := range routeConfigs {
		routeConfigResources = append(routeConfigResources, rc)
	}

	resources := map[resourcev3.Type][]cachetypes.Resource{
		resourcev3.ClusterType:  clusters,
		resourcev3.EndpointType: endpoints,
		resourcev3.RouteType:    routeConfigResources,
		resourcev3.ListenerType: listeners,
	}

	snap, err := cachev3.NewSnapshot(version, resources)
	if err != nil {
		return nil, fmt.Errorf("building snapshot: %w", err)
	}
	return snap, nil
}

// defaultEntrypointName is the internal name of the legacy HTTP/HTTPS
// entrypoint pair (HTTP_PORT/HTTPS_PORT). Routers that set no .entrypoints
// label are served on it.
const defaultEntrypointName = "default"

func validateEntrypointPorts(cfg Config) error {
	if cfg.HTTPPort == cfg.HTTPSPort {
		return fmt.Errorf("default HTTP and HTTPS listeners both use port %d", cfg.HTTPPort)
	}
	used := map[uint32]string{cfg.HTTPPort: "default HTTP", cfg.HTTPSPort: "default HTTPS"}
	for name, port := range cfg.HTTPEntrypoints {
		if prior, ok := used[port]; ok {
			return fmt.Errorf("HTTP entrypoint %q port %d collides with %s", name, port, prior)
		}
		used[port] = "HTTP entrypoint " + name
	}
	for name, port := range cfg.TCPEntrypoints {
		if prior, ok := used[port]; ok {
			return fmt.Errorf("TCP entrypoint %q port %d collides with %s", name, port, prior)
		}
		used[port] = "TCP entrypoint " + name
	}
	for _, ep := range cfg.DefaultHTTPEntrypoints {
		if ep != defaultEntrypointName {
			if _, ok := cfg.HTTPEntrypoints[ep]; !ok {
				return fmt.Errorf("default HTTP entrypoint %q is not configured", ep)
			}
		}
	}
	return nil
}

// groupRoutesByEntrypoint resolves each route's effective HTTP entrypoint
// list (explicit .entrypoints, or the configured default, or the implicit
// default entrypoint) and groups the routes by entrypoint. A route selecting
// an entrypoint the daemon did not configure is skipped for that entrypoint
// with a warning (label-derived input must never fail the whole snapshot —
// one bad container label must not wedge config updates for every other
// container); it is still served on any valid entrypoints it also names.
// The returned entrypointNames is sorted and always includes the default
// entrypoint, even when it carries no routes: the default https_listener is
// always published and references the default route configuration by name,
// so that RDS resource must always exist (an Envoy listener whose Rds
// resource is absent from the snapshot would warm forever, and a route
// configuration that disappears from a later snapshot is not withdrawn by
// SOTW RDS, leaving stale routes behind).
func groupRoutesByEntrypoint(routes map[string]model.Route, cfg Config, logger *slog.Logger) (map[string]map[string]model.Route, []string) {
	byEntrypoint := map[string]map[string]model.Route{defaultEntrypointName: {}}
	for _, name := range sortedSubdomains(routes) {
		route := routes[name]
		eps := route.Entrypoints
		if len(eps) == 0 {
			if len(cfg.DefaultHTTPEntrypoints) > 0 {
				eps = append([]string(nil), cfg.DefaultHTTPEntrypoints...)
			} else if cfg.DefaultHTTPEntrypoint != "" {
				eps = []string{cfg.DefaultHTTPEntrypoint}
			} else {
				eps = []string{defaultEntrypointName}
			}
		}
		for _, ep := range eps {
			if ep != defaultEntrypointName {
				if _, ok := cfg.HTTPEntrypoints[ep]; !ok {
					if logger != nil {
						logger.Warn("skipping router on unknown entrypoint",
							"router", route.RouterName, "subdomain", name, "origin", route.Origin,
							"entrypoint", ep, "configured_entrypoints", sortedEntrypointNames(cfg.HTTPEntrypoints))
					}
					continue
				}
			}
			if byEntrypoint[ep] == nil {
				byEntrypoint[ep] = map[string]model.Route{}
			}
			byEntrypoint[ep][name] = route
		}
	}
	names := make([]string, 0, len(byEntrypoint))
	for ep := range byEntrypoint {
		if len(byEntrypoint[ep]) == 0 && ep != defaultEntrypointName {
			// An extra entrypoint only earns a route config and listener
			// when a route is actually served on it. The default
			// entrypoint is ALWAYS emitted (see doc comment above): its
			// listener is unconditional, so its RDS resource must be too.
			continue
		}
		names = append(names, ep)
	}
	sort.Strings(names)
	return byEntrypoint, names
}

// dedupeRouteNames enforces global uniqueness of xDS route resource names
// (routeResourceName: the router label name, or the subdomain when unnamed)
// across the whole route map. Router names are per-container label
// namespaces, so two unrelated compose stacks both calling their router
// "web" is common; letting the collision reach the byRouteName check would
// reject the WHOLE snapshot and wedge every future update (the discovery
// layer has the same guard, this one also covers the static-config path).
// The first claimant in sorted-subdomain order wins (deterministic); later
// routers are skipped with a warning.
func dedupeRouteNames(routes map[string]model.Route, logger *slog.Logger) map[string]model.Route {
	byName := map[string]string{}
	out := make(map[string]model.Route, len(routes))
	for _, subdomain := range sortedSubdomains(routes) {
		route := routes[subdomain]
		name := routeResourceName(route)
		if prior, exists := byName[name]; exists {
			if logger != nil {
				logger.Warn("skipping router: duplicate router name across containers",
					"router", name, "subdomain", subdomain, "origin", route.Origin,
					"claimed_by_subdomain", prior)
			}
			continue
		}
		byName[name] = subdomain
		out[subdomain] = route
	}
	return out
}

// redirectRouteClusters rewrites RouteAction.Cluster for every route whose
// resource name appears in routeOverride, pointing it at the derived
// circuit-breaker variant cluster instead of its base cluster.
func redirectRouteClusters(rc *routev3.RouteConfiguration, routeOverride map[string]string) {
	for _, vh := range rc.VirtualHosts {
		for _, er := range vh.Routes {
			variant, ok := routeOverride[er.Name]
			if !ok {
				continue
			}
			if ra := er.GetRoute(); ra != nil {
				ra.ClusterSpecifier = &routev3.RouteAction_Cluster{Cluster: variant}
			}
		}
	}
}

func buildCluster(name string) *clusterv3.Cluster {
	return &clusterv3.Cluster{
		Name:                 name,
		ConnectTimeout:       durationpb.New(5 * time.Second),
		ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_EDS},
		EdsClusterConfig: &clusterv3.Cluster_EdsClusterConfig{
			EdsConfig: adsConfigSource(),
		},
		LbPolicy: clusterv3.Cluster_ROUND_ROBIN,
	}
}

func buildClusterLoadAssignment(route model.Route) *endpointv3.ClusterLoadAssignment {
	lbEndpoints := make([]*endpointv3.LbEndpoint, 0, len(route.Endpoints))
	for _, ep := range route.Endpoints {
		lbEndpoints = append(lbEndpoints, &endpointv3.LbEndpoint{
			HostIdentifier: &endpointv3.LbEndpoint_Endpoint{
				Endpoint: &endpointv3.Endpoint{
					Address: &corev3.Address{
						Address: &corev3.Address_SocketAddress{
							SocketAddress: &corev3.SocketAddress{
								Address: ep.Address,
								PortSpecifier: &corev3.SocketAddress_PortValue{
									PortValue: ep.Port,
								},
							},
						},
					},
				},
			},
		})
	}

	return &endpointv3.ClusterLoadAssignment{
		ClusterName: route.ClusterName(),
		Endpoints: []*endpointv3.LocalityLbEndpoints{
			{LbEndpoints: lbEndpoints},
		},
	}
}

// buildHTTPSRouteConfiguration builds the RDS route configuration. Routes are
// grouped into virtual hosts by their effective host:
//
//   - A rule-based route is served by the virtual host of its rule's first
//     Host(...) atom (Hosts() is sorted, so this is deterministic). This is
//     what lets several routes (routers) share one host and be evaluated by
//     precedence.
//   - A legacy subdomain-only route (no rule) keeps the existing behavior:
//     its own virtual host <subdomain>.<baseDomain> with a catch-all route.
//
// Within a virtual host, routes are ordered by model.SortByPrecedence (the
// deterministic precedence: explicit priority, then rule specificity, then
// router name), because Envoy evaluates routes top-to-bottom and the first
// match wins.
//
// When any rule-based route exists, every legacy route still keeps its own
// exact-domain virtual host (restoring host isolation between legacy
// subdomains: Envoy always prefers an exact domain match over the "*"
// fallback), and a final catch-all virtual host with domain "*"
// additionally carries the legacy subdomain routes, so a request that
// matches no virtual host at all still reaches the legacy catch-all routes
// (the documented additive-catch-all behavior). Without rule-based routes
// the configuration is exactly the legacy shape (one virtual host per
// subdomain, no catch-all), preserving backward compatibility.
func buildHTTPSRouteConfiguration(routes map[string]model.Route, names []string, baseDomain string, logger *slog.Logger) *routev3.RouteConfiguration {
	byHost := map[string][]model.Route{}
	var legacy []model.Route
	for _, name := range names {
		route := routes[name]
		if route.Rule.Node == nil {
			legacy = append(legacy, route)
			continue
		}
		hosts := route.Rule.Hosts()
		host := subdomainHost(route, baseDomain)
		if len(hosts) > 0 {
			host = hosts[0]
		}
		byHost[host] = append(byHost[host], route)
	}

	// A legacy route whose <subdomain>.<baseDomain> host is ALSO claimed by
	// a rule-based virtual host joins that virtual host (arbitrated by the
	// shared precedence order) instead of creating a second virtual host
	// with a duplicate domain, which Envoy rejects at the RDS layer.
	remaining := legacy[:0]
	for _, route := range legacy {
		host := subdomainHost(route, baseDomain)
		if _, shared := byHost[host]; shared {
			byHost[host] = append(byHost[host], route)
			continue
		}
		remaining = append(remaining, route)
	}
	legacy = remaining

	vhosts := make([]*routev3.VirtualHost, 0, len(byHost)+1+len(legacy))
	hostNames := make([]string, 0, len(byHost))
	for h := range byHost {
		hostNames = append(hostNames, h)
	}
	sort.Strings(hostNames)
	for _, h := range hostNames {
		vh := buildVirtualHost(h, model.SortByPrecedence(byHost[h]), logger)
		if vh != nil {
			vhosts = append(vhosts, vh)
		}
	}

	// Legacy shape in every configuration: one exact-domain virtual host
	// per legacy subdomain. This must hold even when rule-based routes
	// exist — a legacy route emitted ONLY into the "*" catch-all would be
	// an unconstrained prefix-/ route with no host discrimination, so the
	// first legacy route would capture traffic for every sibling legacy
	// subdomain (cross-host traffic bleed).
	//
	// Several DISTINCT legacy routers may share one subdomain (discovery
	// preserves them all so precedence is decided here, not there). They
	// must collapse into ONE virtual host ordered by precedence: two
	// virtual hosts with the same domain in one route configuration is a
	// duplicate-domain error Envoy rejects, which would wedge the whole
	// snapshot.
	legacyByHost := map[string][]model.Route{}
	legacyHosts := make([]string, 0, len(legacy))
	for _, route := range legacy {
		host := subdomainHost(route, baseDomain)
		if _, seen := legacyByHost[host]; !seen {
			legacyHosts = append(legacyHosts, host)
		}
		legacyByHost[host] = append(legacyByHost[host], route)
	}
	sort.Strings(legacyHosts)
	for _, host := range legacyHosts {
		vh := buildVirtualHost(host, model.SortByPrecedence(legacyByHost[host]), logger)
		if vh != nil {
			vhosts = append(vhosts, vh)
		}
	}

	if len(byHost) > 0 {
		// Additionally carry the legacy routes in the catch-all virtual
		// host, evaluated only for hosts no exact-domain virtual host
		// claimed (Envoy prefers exact domains over "*"). Each copy is
		// constrained to its own host via an :authority matcher: an
		// unconstrained prefix-/ copy would let the first legacy route
		// capture EVERY unmatched host (scanners, wrong DNS, sibling
		// hosts), which is a cross-host traffic bleed, not a fallback.
		catchAll := buildLegacyCatchAllVirtualHost(legacy, baseDomain, logger)
		if catchAll != nil {
			vhosts = append(vhosts, catchAll)
		}
	}

	return &routev3.RouteConfiguration{
		Name:         httpsRouteConfigName,
		VirtualHosts: vhosts,
		// Envoy matches the full :authority, including a non-standard
		// port, unless told otherwise. With HTTPS on a port other than
		// 443 (e.g. HTTPS_PORT=8443 behind a host port mapping), every
		// request's authority carries :port and would 404 against these
		// exact-domain virtual hosts. Strip the port for matching so
		// behavior is identical on standard and non-standard ports.
		IgnorePortInHostMatching: true,
	}
}

// catchAllVHName is the internal name of the catch-all virtual host;
// catchAllDomain is its domain: a literal "*" matches every host that no
// rule-based virtual host claimed.
const (
	catchAllVHName = "catch_all"
	catchAllDomain = "*"
)

// subdomainHost returns the legacy virtual host domain for a route:
// <subdomain>.<baseDomain>.
func subdomainHost(route model.Route, baseDomain string) string {
	return route.Subdomain + "." + baseDomain
}

// buildLegacyCatchAllVirtualHost builds the "*" catch-all virtual host that
// additionally carries the legacy routes when rule-based routes exist. Each
// legacy route's copy is constrained to its own <subdomain>.<baseDomain>
// authority (case-insensitive, port-tolerant): the catch-all exists so a
// request whose Host no rule-based virtual host claimed still reaches its
// legacy route, NOT so the first legacy route swallows every unknown host.
func buildLegacyCatchAllVirtualHost(legacy []model.Route, baseDomain string, logger *slog.Logger) *routev3.VirtualHost {
	var vhRoutes []*routev3.Route
	for _, route := range model.SortByPrecedence(legacy) {
		generated := buildRoutesForRoute(route, logger)
		if generated == nil {
			continue
		}
		host := subdomainHost(route, baseDomain)
		for _, er := range generated {
			if er.Match == nil {
				er.Match = &routev3.RouteMatch{}
			}
			er.Match.Headers = append(er.Match.Headers, &routev3.HeaderMatcher{
				Name: ":authority",
				HeaderMatchSpecifier: &routev3.HeaderMatcher_StringMatch{
					StringMatch: &matcher.StringMatcher{
						// Exact, case-insensitive :authority match on the
						// route's own legacy host. A request for an
						// entirely unknown host therefore matches NO route
						// (clean 404) instead of being routed to the first
						// legacy backend.
						MatchPattern: &matcher.StringMatcher_Exact{Exact: host},
						IgnoreCase:   true,
					},
				},
			})
		}
		vhRoutes = append(vhRoutes, generated...)
	}
	if len(vhRoutes) == 0 {
		return nil
	}
	return &routev3.VirtualHost{
		Name:    catchAllVHName,
		Domains: []string{catchAllDomain},
		Routes:  vhRoutes,
	}
}

// buildVirtualHost builds one Envoy virtual host. Its routes are the given
// routes (already ordered by precedence); each contributes one or more
// generated routes (one per DNF term) pointing at its own cluster. Routes
// whose rule cannot be translated to an Envoy route match (ClientIP, negation
// on a non-header matcher, pathological DNF) are skipped with an actionable
// warning when logger is non-nil, so one bad router never breaks the host.
func buildVirtualHost(domain string, routes []model.Route, logger *slog.Logger) *routev3.VirtualHost {
	var vhRoutes []*routev3.Route
	for _, route := range routes {
		generated := buildRoutesForRoute(route, logger)
		if generated == nil {
			continue
		}
		vhRoutes = append(vhRoutes, generated...)
	}
	if len(vhRoutes) == 0 {
		return nil
	}
	return &routev3.VirtualHost{
		Name:    domain,
		Domains: []string{domain},
		Routes:  vhRoutes,
	}
}

// buildRoutesForRoute derives the Envoy routes for one model.Route. It
// returns nil (meaning: skip this subdomain's virtual host) when the rule
// cannot be translated, and emits a warning via logger when provided.
func buildRoutesForRoute(route model.Route, logger *slog.Logger) []*routev3.Route {
	// Legacy: no rule -> single catch-all prefix "/" route.
	if route.Rule.Node == nil {
		er := &routev3.Route{
			Name: routeResourceName(route),
			Match: &routev3.RouteMatch{
				PathSpecifier: &routev3.RouteMatch_Prefix{Prefix: "/"},
			},
			Action: &routev3.Route_Route{
				Route: &routev3.RouteAction{
					ClusterSpecifier: &routev3.RouteAction_Cluster{Cluster: route.ClusterName()},
				},
			},
		}
		if err := applyRouteMiddlewares(er, route.Middlewares); err != nil {
			if logger != nil {
				logger.Warn("skipping router: invalid middleware chain", "router", route.RouterName, "error", err)
			}
			return nil
		}
		applyRouteSecurity(er, route.Middlewares)
		applyRouteObservability(er, route)
		return []*routev3.Route{er}
	}

	// Reject rules that cannot be expressed as Envoy route matches.
	if err := route.Rule.Translatable(); err != nil {
		if logger != nil {
			logger.Warn("skipping subdomain: rule cannot be translated to an Envoy route match",
				"subdomain", route.Subdomain, "origin", route.Origin, "rule", route.RuleExpr, "error", err)
		}
		return nil
	}

	terms, err := route.Rule.ToDNF()
	if err != nil {
		if logger != nil {
			logger.Warn("skipping subdomain: rule DNF expansion failed",
				"subdomain", route.Subdomain, "origin", route.Origin, "rule", route.RuleExpr, "error", err)
		}
		return nil
	}

	// Order the generated routes most-specific-first. Envoy evaluates routes
	// within a virtual host top-to-bottom with first-match-wins, so a broader
	// term (e.g. PathPrefix(/)) must not precede a narrower one it would
	// otherwise shadow (e.g. Path(/api)). This is the deterministic
	// precedence the task requires, applied at the xDS layer.
	terms = orderDNFTerms(terms)

	out := make([]*routev3.Route, 0, len(terms))
	for i, term := range terms {
		match, err := buildRouteMatchFromTerm(term)
		if err != nil {
			if logger != nil {
				logger.Warn("skipping subdomain: DNF term cannot be translated",
					"subdomain", route.Subdomain, "origin", route.Origin, "rule", route.RuleExpr,
					"term", i, "error", err)
			}
			return nil
		}
		er := &routev3.Route{
			Name:  routeResourceName(route),
			Match: match,
			Action: &routev3.Route_Route{
				Route: &routev3.RouteAction{
					ClusterSpecifier: &routev3.RouteAction_Cluster{Cluster: route.ClusterName()},
				},
			},
		}
		if err := applyRouteMiddlewares(er, route.Middlewares); err != nil {
			if logger != nil {
				logger.Warn("skipping router: invalid middleware chain", "router", route.RouterName, "error", err)
			}
			return nil
		}
		applyRouteSecurity(er, route.Middlewares)
		applyRouteObservability(er, route)
		out = append(out, er)
	}
	return out
}

func routeResourceName(route model.Route) string {
	if route.RouterName != "" {
		return route.RouterName
	}
	return route.Subdomain
}

// observabilityMetadataNamespace is the Envoy route-metadata namespace this
// control plane uses to carry the .accesslog hook. It is a declarative carrier
// of intent: Envoy access logging is listener-scoped (the pinned API has no
// per-route access-log field), so this metadata records the operator's intent
// without altering routing behavior. It never carries secrets or raw auth
// headers (see LABELS.md limitations).
const observabilityMetadataNamespace = "envoy-control-plane.observability"

// applyRouteObservability applies a route's per-route observability hooks to a
// generated Envoy route:
//
//   - .tracing.operationname -> Route.Tracing.Operation: the per-route span
//     name (the pinned API's per-route tracing field; it takes precedence over
//     the route decorator and the HCM tracing operation).
//   - .tracing=true|false -> Route.Tracing sampling: true forces 100% sampling,
//     false disables tracing for the route's traffic (0% sampling).
//   - .accesslog=true|false -> route metadata under the observability namespace
//     (a declarative carrier; access logging itself is listener-scoped).
//
// A nil route.Tracing leaves tracing at the listener/HCM default. Only the
// fields the operator set are emitted, so an unset hook never overrides the
// listener-level configuration.
func applyRouteObservability(er *routev3.Route, route model.Route) {
	if route.Tracing != nil {
		tr := &routev3.Tracing{}
		if route.Tracing.OperationName != "" {
			tr.Operation = route.Tracing.OperationName
		}
		if route.Tracing.Enabled {
			tr.OverallSampling = &typev3.FractionalPercent{
				Numerator:   100,
				Denominator: typev3.FractionalPercent_HUNDRED,
			}
		} else {
			tr.OverallSampling = &typev3.FractionalPercent{
				Numerator:   0,
				Denominator: typev3.FractionalPercent_HUNDRED,
			}
		}
		er.Tracing = tr
	}
	if route.AccessLog != nil {
		enabled := *route.AccessLog
		md := er.Metadata
		if md == nil {
			md = &corev3.Metadata{FilterMetadata: map[string]*structpb.Struct{}}
		}
		if md.FilterMetadata == nil {
			md.FilterMetadata = map[string]*structpb.Struct{}
		}
		st, err := structpb.NewStruct(map[string]any{
			"accesslog": enabled,
			"subdomain": route.Subdomain,
			"router":    routeResourceName(route),
		})
		if err != nil {
			// The struct is built from fixed string/bool values; failure is a
			// programming error, not a runtime condition.
			panic(fmt.Sprintf("xds: building observability metadata: %v", err))
		}
		md.FilterMetadata[observabilityMetadataNamespace] = st
		er.Metadata = md
	}
}

func publishedRoutes(routes map[string]model.Route, rc *routev3.RouteConfiguration) map[string]model.Route {
	publishedNames := map[string]struct{}{}
	for _, vh := range rc.VirtualHosts {
		for _, er := range vh.Routes {
			publishedNames[er.Name] = struct{}{}
		}
	}
	published := make(map[string]model.Route, len(publishedNames))
	for key, route := range routes {
		if _, ok := publishedNames[routeResourceName(route)]; ok {
			published[key] = route
		}
	}
	return published
}

// orderDNFTerms returns the terms sorted so the most specific term comes
// first, the order Envoy must evaluate them in (first match wins). Specificity
// is the number of atoms in the term (more constraints = more specific); ties
// are broken by the term's canonical string for a stable, deterministic order.
// The input slice is not mutated.
func orderDNFTerms(terms []model.DNFTerm) []model.DNFTerm {
	out := make([]model.DNFTerm, len(terms))
	copy(out, terms)
	sort.SliceStable(out, func(i, j int) bool {
		if len(out[i]) != len(out[j]) {
			return len(out[i]) > len(out[j])
		}
		return termString(out[i]) < termString(out[j])
	})
	return out
}

// termString renders a DNF term (a conjunction of atoms) deterministically for
// use as a tie-breaker in route ordering.
func termString(term model.DNFTerm) string {
	var b strings.Builder
	for i, e := range term {
		if i > 0 {
			b.WriteString(" && ")
		}
		if e.Negated {
			b.WriteString("!")
		}
		b.WriteString(e.Atom.String())
	}
	return b.String()
}

// buildRouteMatchFromTerm translates one DNF term (a conjunction of possibly
// negated atoms) into an Envoy RouteMatch. Non-path atoms become header or
// query matchers; the path (or prefix) becomes the RouteMatch path specifier.
// A term with no path specifier defaults to prefix "/".
//
// Host atoms are not emitted as route matchers: Envoy matches the request
// Host at the virtual-host level (via the virtual host's domains), and this
// control plane already scopes each subdomain to its own virtual host
// (<subdomain>.<baseDomain>). A Host(...) atom inside a rule is therefore
// satisfied by the virtual host's domain match and is redundant at the route
// level. (Host matching is case-insensitive, as required.)
func buildRouteMatchFromTerm(term model.DNFTerm) (*routev3.RouteMatch, error) {
	match := &routev3.RouteMatch{}

	var path, pathPrefix string
	headerMatchers := make([]*routev3.HeaderMatcher, 0, len(term))
	queryMatchers := make([]*routev3.QueryParameterMatcher, 0, len(term))

	for _, e := range term {
		switch e.Atom.Kind {
		case model.KindHost:
			// Satisfied by the virtual host domain; no route-level matcher.
		case model.KindPath:
			path = e.Atom.Value
		case model.KindPathPrefix:
			pathPrefix = e.Atom.Value
		case model.KindHeader:
			hm := &routev3.HeaderMatcher{
				Name: e.Atom.Name,
				HeaderMatchSpecifier: &routev3.HeaderMatcher_StringMatch{
					StringMatch: &matcher.StringMatcher{
						MatchPattern: &matcher.StringMatcher_Exact{Exact: e.Atom.Value},
					},
				},
			}
			if e.Negated {
				hm.InvertMatch = true
				hm.TreatMissingHeaderAsEmpty = true
			}
			headerMatchers = append(headerMatchers, hm)
		case model.KindMethod:
			hm := &routev3.HeaderMatcher{
				Name: ":method",
				HeaderMatchSpecifier: &routev3.HeaderMatcher_StringMatch{
					StringMatch: &matcher.StringMatcher{
						MatchPattern: &matcher.StringMatcher_Exact{Exact: e.Atom.Value},
					},
				},
			}
			if e.Negated {
				hm.InvertMatch = true
				hm.TreatMissingHeaderAsEmpty = true
			}
			headerMatchers = append(headerMatchers, hm)
		case model.KindQuery:
			qm := &routev3.QueryParameterMatcher{Name: e.Atom.Name}
			if e.Negated {
				return nil, fmt.Errorf("negation on Query(%s) is not supported", e.Atom.Name)
			}
			if e.Atom.Value == "" {
				// Presence match: the parameter is present (any value).
				qm.QueryParameterMatchSpecifier = &routev3.QueryParameterMatcher_PresentMatch{PresentMatch: true}
			} else {
				qm.QueryParameterMatchSpecifier = &routev3.QueryParameterMatcher_StringMatch{
					StringMatch: &matcher.StringMatcher{
						MatchPattern: &matcher.StringMatcher_Exact{Exact: e.Atom.Value},
					},
				}
			}
			queryMatchers = append(queryMatchers, qm)
		case model.KindClientIP:
			return nil, fmt.Errorf("ClientIP(%s) cannot be expressed as an Envoy route match in this version", e.Atom.Value)
		}
	}

	// Path specifier: an exact Path wins over a PathPrefix (the exact path is
	// strictly more specific and subsumes the prefix when both hold).
	switch {
	case path != "":
		match.PathSpecifier = &routev3.RouteMatch_Path{Path: path}
	case pathPrefix != "":
		match.PathSpecifier = &routev3.RouteMatch_Prefix{Prefix: pathPrefix}
	default:
		match.PathSpecifier = &routev3.RouteMatch_Prefix{Prefix: "/"}
	}

	if len(headerMatchers) > 0 {
		match.Headers = headerMatchers
	}
	if len(queryMatchers) > 0 {
		match.QueryParameters = queryMatchers
	}
	return match, nil
}

// buildHTTPListener returns the plain-HTTP listener that unconditionally
// redirects every request to HTTPS on the same host.
func buildHTTPListener(port, httpsPort uint32) *listenerv3.Listener {
	// Redirect to HTTPS. When HTTPS runs on a different port than HTTP
	// (e.g. 8080 -> 8443 behind host port mappings), a bare https://
	// scheme rewrite would send clients back to the HTTP port; name the
	// HTTPS port explicitly. When both are the same, leave PortRedirect
	// unset (0) so the Location header stays clean.
	var portRedirect uint32
	if port != httpsPort {
		portRedirect = httpsPort
	}
	routeConfig := &routev3.RouteConfiguration{
		Name: "http_redirect_routes",
		VirtualHosts: []*routev3.VirtualHost{
			{
				Name:    "redirect_all",
				Domains: []string{"*"},
				Routes: []*routev3.Route{
					{
						Match: &routev3.RouteMatch{
							PathSpecifier: &routev3.RouteMatch_Prefix{Prefix: "/"},
						},
						Action: &routev3.Route_Redirect{
							Redirect: &routev3.RedirectAction{
								SchemeRewriteSpecifier: &routev3.RedirectAction_HttpsRedirect{HttpsRedirect: true},
								PortRedirect:           portRedirect,
							},
						},
					},
				},
			},
		},
	}

	hcm := &hcmv3.HttpConnectionManager{
		StatPrefix:     "http_redirect",
		RouteSpecifier: &hcmv3.HttpConnectionManager_RouteConfig{RouteConfig: routeConfig},
		HttpFilters:    []*hcmv3.HttpFilter{routerHTTPFilter()},
	}

	return &listenerv3.Listener{
		Name:    httpListenerName,
		Address: listenerAddress(port),
		FilterChains: []*listenerv3.FilterChain{
			{
				Filters: []*listenerv3.Filter{
					{
						Name:       wellknown.HTTPConnectionManager,
						ConfigType: &listenerv3.Filter_TypedConfig{TypedConfig: mustAny(hcm)},
					},
				},
			},
		},
	}
}

// buildHTTPSListener returns a TLS listener that serves routed traffic. Its
// routes come from RDS (dynamic, via ADS) under routeConfigName; its
// certificate comes from SDS served by the separate envoy-acme control plane,
// referenced here only by cluster name + secret name. listenerName names the
// generated listener (the default entrypoint uses the legacy "https_listener";
// extra entrypoints use "https_listener__<entrypoint>").
func buildHTTPSListener(listenerName string, port uint32, routeConfigName, certSecretName, acmeSDSClusterName string, plan *securityPlan, ssoProfiles []sso.Profile) *listenerv3.Listener {
	// SSO (oauth2 per profile, then jwt_authn) runs first: an unauthenticated
	// request is redirected to the IdP before any other filter acts on it.
	// Listeners with no opted-in router get no SSO filters at all.
	filters := ssoHTTPFilters(ssoProfiles)
	var extAuthzFilter, basicAuthRemoveFilter *hcmv3.HttpFilter
	for _, filter := range plan.listenerFilters {
		switch filter.Name {
		case extAuthzFilterName:
			extAuthzFilter = filter
		case basicAuthRemoveFilterName:
			basicAuthRemoveFilter = filter
		default:
			filters = append(filters, filter)
		}
	}
	// Request mutations precede ForwardAuth so the authorization decision is
	// made against exactly the path and headers the upstream would receive.
	filters = append(filters, mutationHTTPFilter())
	if extAuthzFilter != nil {
		filters = append(filters, extAuthzFilter)
	}
	// BasicAuth credential cleanup must run after every auth filter but before
	// CORS/router dispatch so removeheader cannot be undone by an earlier Lua
	// mutation or hide credentials from ForwardAuth in a composed chain.
	if basicAuthRemoveFilter != nil {
		filters = append(filters, basicAuthRemoveFilter)
	}
	// gRPC-Web must run before CORS: it rewrites the gRPC-Web request into
	// standard gRPC framing on the way in and translates the trailers-only
	// gRPC response back on the way out, and CORS preflight handling for a
	// browser-originated gRPC-Web call must see the grpc-web request shape.
	if plan.needGRPCWeb {
		filters = append(filters, grpcWebHTTPFilter())
	}
	// Compression runs late (after routing decisions are effectively fixed
	// but before the router itself) so it compresses exactly the response
	// bytes the client will receive, after any other response mutation.
	filters = append(filters, buildCompressorFilters(plan.compressConfig)...)
	if plan.needCustomResponse {
		filters = append(filters, customResponseHTTPFilter())
	}
	filters = append(filters, corsHTTPFilter(), routerHTTPFilter())

	hcm := &hcmv3.HttpConnectionManager{
		StatPrefix: "https",
		RouteSpecifier: &hcmv3.HttpConnectionManager_Rds{
			Rds: &hcmv3.Rds{
				RouteConfigName: routeConfigName,
				ConfigSource:    adsConfigSource(),
			},
		},
		HttpFilters: filters,
	}
	if plan.xffNumTrustedHops > 0 {
		// Honor the ipstrategy.depth of the IP allow/deny middleware: trust
		// that many X-Forwarded-For hops so RemoteIp-based RBAC principals
		// resolve to the originating client, not the edge proxy.
		hcm.XffNumTrustedHops = plan.xffNumTrustedHops
		hcm.UseRemoteAddress = wrapperspb.Bool(true)
	} else if len(plan.xffTrustedCIDRs) > 0 {
		hcm.OriginalIpDetectionExtensions = []*corev3.TypedExtensionConfig{{
			Name: "envoy.http.original_ip_detection.xff",
			TypedConfig: mustAny(&xffv3.XffConfig{XffTrustedCidrs: &xffv3.XffTrustedCidrs{
				Cidrs: cidrRanges(plan.xffTrustedCIDRs),
			}}),
		}}
	}

	tlsContext := &tlsv3.DownstreamTlsContext{
		CommonTlsContext: &tlsv3.CommonTlsContext{
			TlsCertificateSdsSecretConfigs: []*tlsv3.SdsSecretConfig{
				{
					Name:      certSecretName,
					SdsConfig: acmeSDSConfigSource(acmeSDSClusterName),
				},
			},
		},
	}

	return &listenerv3.Listener{
		Name:    listenerName,
		Address: listenerAddress(port),
		FilterChains: []*listenerv3.FilterChain{
			{
				TransportSocket: &corev3.TransportSocket{
					Name:       transportSocketTLS,
					ConfigType: &corev3.TransportSocket_TypedConfig{TypedConfig: mustAny(tlsContext)},
				},
				Filters: []*listenerv3.Filter{
					{
						Name:       wellknown.HTTPConnectionManager,
						ConfigType: &listenerv3.Filter_TypedConfig{TypedConfig: mustAny(hcm)},
					},
				},
			},
		},
	}
}

func corsHTTPFilter() *hcmv3.HttpFilter {
	return &hcmv3.HttpFilter{Name: corsFilterName, ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: mustAny(&corsv3.Cors{})}}
}

func mutationHTTPFilter() *hcmv3.HttpFilter {
	noop := &corev3.DataSource{Specifier: &corev3.DataSource_InlineString{InlineString: "function envoy_on_request(handle) end\n"}}
	return &hcmv3.HttpFilter{Name: mutationFilterName, ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: mustAny(&luav3.Lua{DefaultSourceCode: noop, ClearRouteCache: wrapperspb.Bool(false)})}}
}

func routerHTTPFilter() *hcmv3.HttpFilter {
	return &hcmv3.HttpFilter{
		Name:       wellknown.Router,
		ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: mustAny(&routerv3.Router{})},
	}
}

func listenerAddress(port uint32) *corev3.Address {
	return &corev3.Address{
		Address: &corev3.Address_SocketAddress{
			SocketAddress: &corev3.SocketAddress{
				Address: "0.0.0.0",
				PortSpecifier: &corev3.SocketAddress_PortValue{
					PortValue: port,
				},
			},
		},
	}
}

// adsConfigSource references this control plane's own aggregated stream, for
// resources (RDS, EDS) fetched dynamically from it.
func adsConfigSource() *corev3.ConfigSource {
	return &corev3.ConfigSource{
		ResourceApiVersion:    corev3.ApiVersion_V3,
		ConfigSourceSpecifier: &corev3.ConfigSource_Ads{Ads: &corev3.AggregatedConfigSource{}},
	}
}

// acmeSDSConfigSource references a *separate* gRPC cluster (defined
// statically in Envoy's bootstrap, not by this control plane) that the
// envoy-acme control plane serves SDS from.
func acmeSDSConfigSource(clusterName string) *corev3.ConfigSource {
	return &corev3.ConfigSource{
		ResourceApiVersion: corev3.ApiVersion_V3,
		ConfigSourceSpecifier: &corev3.ConfigSource_ApiConfigSource{
			ApiConfigSource: &corev3.ApiConfigSource{
				ApiType:             corev3.ApiConfigSource_GRPC,
				TransportApiVersion: corev3.ApiVersion_V3,
				GrpcServices: []*corev3.GrpcService{
					{
						TargetSpecifier: &corev3.GrpcService_EnvoyGrpc_{
							EnvoyGrpc: &corev3.GrpcService_EnvoyGrpc{ClusterName: clusterName},
						},
					},
				},
			},
		},
	}
}

// mustAny marshals a proto message we constructed ourselves into an Any.
// The only way this fails is a programming error (e.g. a nil message), so a
// panic here surfaces a bug immediately rather than needing to be threaded
// through every caller as a runtime error.
func mustAny(msg proto.Message) *anypb.Any {
	any, err := anypb.New(msg)
	if err != nil {
		panic(fmt.Sprintf("xds: marshaling %T: %v", msg, err))
	}
	return any
}

func sortedSubdomains(routes map[string]model.Route) []string {
	names := make([]string, 0, len(routes))
	for name := range routes {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
