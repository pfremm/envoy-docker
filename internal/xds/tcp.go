// TCP router/service xDS generation: listener filter chains (raw TCP and
// TLS passthrough) plus TCP cluster/endpoint resources. Never touches the
// HTTP connection manager: a TCP filter chain carries only a tcp_proxy
// network filter and, for passthrough, a TLS-inspector-gated filter-chain
// match. No TCP middlewares in this milestone (fixed contract).
package xds

import (
	"fmt"
	"log/slog"
	"sort"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	tlsinspectorv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	tcpproxyv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	cachetypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
)

// tcpListenerNamePrefix / tcpFilterChainNamePrefix name the generated
// per-entrypoint TCP listener and its filter chains, namespaced away from
// the HTTP listener names (http_listener/https_listener) and from each
// other by entrypoint.
const tcpListenerNamePrefix = "tcp_listener__"

// buildTCPResources validates a TCPConfiguration against the configured
// static entrypoints and turns it into one Envoy listener per entrypoint
// (each carrying one filter chain per surviving router, ordered by
// precedence, with label-derived problems — unknown entrypoints,
// overlapping SNI matches — degraded to deterministic per-router skips)
// plus the named TCP service clusters and endpoints they reference. It
// never emits an HTTP connection manager: raw and passthrough filter chains
// carry only a tcp_proxy network filter.
func buildTCPResources(tcpCfg model.TCPConfiguration, cfg Config, logger *slog.Logger) (listeners []cachetypes.Resource, clusters []cachetypes.Resource, endpoints []cachetypes.Resource, err error) {
	if len(tcpCfg.Routers) == 0 {
		return nil, nil, nil, nil
	}

	for name, svc := range tcpCfg.Services {
		if svc.Name != name {
			return nil, nil, nil, fmt.Errorf("TCP service map key %q does not match service name %q", name, svc.Name)
		}
		if err := svc.Validate(); err != nil {
			return nil, nil, nil, fmt.Errorf("invalid TCP service %q: %w", name, err)
		}
	}

	routerNames := make([]string, 0, len(tcpCfg.Routers))
	for name, r := range tcpCfg.Routers {
		if r.Name != name {
			return nil, nil, nil, fmt.Errorf("TCP router map key %q does not match router name %q", name, r.Name)
		}
		if err := r.Validate(); err != nil {
			return nil, nil, nil, fmt.Errorf("invalid TCP router %q: %w", name, err)
		}
		if _, err := tcpCfg.ResolveTCPService(r.ServiceName); err != nil {
			return nil, nil, nil, fmt.Errorf("tcp router %q: %w", name, err)
		}
		routerNames = append(routerNames, name)
	}
	sort.Strings(routerNames)

	// Resolve each router's effective entrypoint list (explicit, or the
	// configured default) and group by entrypoint. A router naming an
	// entrypoint the daemon did not configure — or naming none when no
	// default is configured — is skipped with a warning: entrypoint
	// addresses/ports are operator configuration, so a label can only
	// SELECT among them, never conjure a new bound socket, and a bad
	// label-derived selection must never wedge the whole snapshot.
	byEntrypoint := map[string][]model.TCPRouter{}
	for _, name := range routerNames {
		r := tcpCfg.Routers[name]
		eps := r.Entrypoints
		if len(eps) == 0 {
			if cfg.DefaultTCPEntrypoint == "" {
				if logger != nil {
					logger.Warn("skipping tcp router: no .entrypoints and no default TCP entrypoint configured", "router", name)
				}
				continue
			}
			eps = []string{cfg.DefaultTCPEntrypoint}
		}
		for _, ep := range eps {
			if _, ok := cfg.TCPEntrypoints[ep]; !ok {
				if logger != nil {
					logger.Warn("skipping tcp router on unknown entrypoint",
						"router", name, "entrypoint", ep, "configured_entrypoints", sortedEntrypointNames(cfg.TCPEntrypoints))
				}
				continue
			}
			byEntrypoint[ep] = append(byEntrypoint[ep], r)
		}
	}

	entrypointNames := make([]string, 0, len(byEntrypoint))
	for ep := range byEntrypoint {
		entrypointNames = append(entrypointNames, ep)
	}
	sort.Strings(entrypointNames)

	clusterNames := map[string]string{}
	for _, ep := range entrypointNames {
		routers := byEntrypoint[ep]
		// Envoy filter-chain matching is structural: two chains with
		// overlapping server_names (or two catch-alls) in the same TLS
		// mode are duplicate matches Envoy rejects with an LDS NACK,
		// regardless of chain order or router .priority — and a NACK
		// refuses the entire listener update. Keep the highest-precedence
		// router of each overlapping set and skip the rest with a warning
		// (deterministic: precedence order), so one conflicting label
		// never wedges the snapshot.
		ordered := make([]model.TCPRouter, 0, len(routers))
		for _, r := range model.SortTCPRoutersByPrecedence(routers) {
			conflicted := false
			for _, kept := range ordered {
				if model.TCPFilterChainOverlap(kept, r) {
					if logger != nil {
						logger.Warn("skipping tcp router: overlapping SNI match would produce a duplicate Envoy filter-chain match",
							"entrypoint", ep, "skipped", r.Name, "kept", kept.Name,
							"skipped_sni", r.SNIValues(), "kept_sni", kept.SNIValues())
					}
					conflicted = true
					break
				}
			}
			if !conflicted {
				ordered = append(ordered, r)
			}
		}
		if len(ordered) == 0 {
			continue
		}

		listener, err := buildTCPListener(ep, cfg.TCPEntrypoints[ep], ordered, tcpCfg)
		if err != nil {
			return nil, nil, nil, err
		}
		listeners = append(listeners, listener)

		for _, r := range ordered {
			resolved, rerr := tcpCfg.ResolveTCPService(r.ServiceName)
			if rerr != nil {
				return nil, nil, nil, fmt.Errorf("tcp router %q: %w", r.Name, rerr)
			}
			for _, target := range resolved {
				svc := tcpCfg.Services[target.Name]
				cname := model.NamedTCPServiceClusterName(svc.Name)
				if prior, exists := clusterNames[cname]; exists {
					if prior != "tcp service "+svc.Name {
						return nil, nil, nil, fmt.Errorf("xDS cluster name %q collides between %s and tcp service %q", cname, prior, svc.Name)
					}
					continue
				}
				clusterNames[cname] = "tcp service " + svc.Name
				clusters = append(clusters, buildCluster(cname))
				endpoints = append(endpoints, buildTCPServiceLoadAssignment(svc))
			}
		}
	}

	return listeners, clusters, endpoints, nil
}

func sortedEntrypointNames(m map[string]uint32) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// buildTCPListener builds one Envoy listener for a TCP entrypoint: one
// filter chain per router (ordered by precedence, most specific first, so a
// concrete-SNI passthrough chain is listed before a catch-all one), each
// carrying a tcp_proxy pointed at the router's service cluster (or a
// weighted_clusters split for a weighted named service). Passthrough chains
// additionally match on transport_protocol "tls" and server_names, relying
// on the listener-level TLS inspector to have read the SNI first; raw
// chains match transport_protocol "raw_buffer" with no server name
// constraint (and are validated at the model layer to be catch-all only).
// The HTTP connection manager is never attached to any chain here.
func buildTCPListener(entrypoint string, port uint32, routers []model.TCPRouter, tcpCfg model.TCPConfiguration) (*listenerv3.Listener, error) {
	needsTLSInspector := false
	chains := make([]*listenerv3.FilterChain, 0, len(routers))
	for _, r := range routers {
		proxy, err := buildTCPProxy(r, tcpCfg)
		if err != nil {
			return nil, fmt.Errorf("tcp router %q: %w", r.Name, err)
		}
		filter := &listenerv3.Filter{
			Name:       wellknown.TCPProxy,
			ConfigType: &listenerv3.Filter_TypedConfig{TypedConfig: mustAny(proxy)},
		}
		chain := &listenerv3.FilterChain{
			Name:    "tcp_router__" + r.Name,
			Filters: []*listenerv3.Filter{filter},
		}
		if r.TLSPassthrough {
			needsTLSInspector = true
			match := &listenerv3.FilterChainMatch{TransportProtocol: "tls"}
			if !r.HasCatchAll() {
				match.ServerNames = r.SNIValues()
			}
			chain.FilterChainMatch = match
			// Passthrough forwards the encrypted bytes untouched: no
			// TransportSocket is set on the downstream chain, so Envoy
			// proxies the raw TLS record stream without terminating it.
		} else {
			chain.FilterChainMatch = &listenerv3.FilterChainMatch{TransportProtocol: "raw_buffer"}
		}
		chains = append(chains, chain)
	}

	listener := &listenerv3.Listener{
		Name:         tcpListenerNamePrefix + entrypoint,
		Address:      listenerAddress(port),
		FilterChains: chains,
	}
	if needsTLSInspector {
		listener.ListenerFilters = []*listenerv3.ListenerFilter{
			{
				Name:       wellknown.TLSInspector,
				ConfigType: &listenerv3.ListenerFilter_TypedConfig{TypedConfig: mustAny(&tlsinspectorv3.TlsInspector{})},
			},
		}
	}
	return listener, nil
}

// buildTCPProxy builds the tcp_proxy network filter config for one router:
// a single-cluster proxy for a plain or single-resolved-target service, or
// a weighted_clusters proxy when the named service resolves to more than
// one weighted target.
func buildTCPProxy(r model.TCPRouter, tcpCfg model.TCPConfiguration) (*tcpproxyv3.TcpProxy, error) {
	resolved, err := tcpCfg.ResolveTCPService(r.ServiceName)
	if err != nil {
		return nil, err
	}
	proxy := &tcpproxyv3.TcpProxy{StatPrefix: "tcp_" + sanitizeClusterName(r.Name)}
	if len(resolved) == 1 {
		proxy.ClusterSpecifier = &tcpproxyv3.TcpProxy_Cluster{Cluster: model.NamedTCPServiceClusterName(resolved[0].Name)}
		return proxy, nil
	}
	wc := &tcpproxyv3.TcpProxy_WeightedCluster{}
	for _, target := range resolved {
		wc.Clusters = append(wc.Clusters, &tcpproxyv3.TcpProxy_WeightedCluster_ClusterWeight{
			Name:   model.NamedTCPServiceClusterName(target.Name),
			Weight: target.Weight,
		})
	}
	proxy.ClusterSpecifier = &tcpproxyv3.TcpProxy_WeightedClusters{WeightedClusters: wc}
	return proxy, nil
}

func buildTCPServiceLoadAssignment(s model.TCPService) *endpointv3.ClusterLoadAssignment {
	lbEndpoints := make([]*endpointv3.LbEndpoint, 0, len(s.Endpoints))
	for _, ep := range s.Endpoints {
		lbEndpoints = append(lbEndpoints, &endpointv3.LbEndpoint{
			HostIdentifier: &endpointv3.LbEndpoint_Endpoint{
				Endpoint: &endpointv3.Endpoint{
					Address: &corev3.Address{
						Address: &corev3.Address_SocketAddress{
							SocketAddress: &corev3.SocketAddress{
								Address:       ep.Address,
								PortSpecifier: &corev3.SocketAddress_PortValue{PortValue: ep.Port},
							},
						},
					},
				},
			},
		})
	}
	return &endpointv3.ClusterLoadAssignment{
		ClusterName: model.NamedTCPServiceClusterName(s.Name),
		Endpoints:   []*endpointv3.LocalityLbEndpoints{{LbEndpoints: lbEndpoints}},
	}
}
