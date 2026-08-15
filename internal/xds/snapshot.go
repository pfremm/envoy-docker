// Package xds builds Envoy xDS resources (LDS/RDS/CDS/EDS) from a route map
// and serves them over ADS.
package xds

import (
	"fmt"
	"log/slog"
	"sort"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	routerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	cachetypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
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
	names := sortedSubdomains(routes)

	clusters := make([]cachetypes.Resource, 0, len(names))
	endpoints := make([]cachetypes.Resource, 0, len(names))
	for _, name := range names {
		route := routes[name]
		clusters = append(clusters, buildCluster(route.ClusterName()))
		endpoints = append(endpoints, buildClusterLoadAssignment(route))
	}

	httpListener := buildHTTPListener(cfg.HTTPPort)
	httpsListener := buildHTTPSListener(cfg.HTTPSPort, cfg.CertSecretName, cfg.ACMESDSClusterName)
	routeConfig := buildHTTPSRouteConfiguration(routes, names, cfg.BaseDomain)

	resources := map[resourcev3.Type][]cachetypes.Resource{
		resourcev3.ClusterType:  clusters,
		resourcev3.EndpointType: endpoints,
		resourcev3.RouteType:    {routeConfig},
		resourcev3.ListenerType: {httpListener, httpsListener},
	}

	snap, err := cachev3.NewSnapshot(version, resources)
	if err != nil {
		return nil, fmt.Errorf("building snapshot: %w", err)
	}
	return snap, nil
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

func buildHTTPSRouteConfiguration(routes map[string]model.Route, names []string, baseDomain string) *routev3.RouteConfiguration {
	vhosts := make([]*routev3.VirtualHost, 0, len(names))
	for _, name := range names {
		vhosts = append(vhosts, buildVirtualHost(routes[name], baseDomain))
	}
	return &routev3.RouteConfiguration{
		Name:         httpsRouteConfigName,
		VirtualHosts: vhosts,
	}
}

func buildVirtualHost(route model.Route, baseDomain string) *routev3.VirtualHost {
	host := route.Subdomain + "." + baseDomain
	return &routev3.VirtualHost{
		Name:    route.ClusterName(),
		Domains: []string{host},
		Routes: []*routev3.Route{
			{
				Match: &routev3.RouteMatch{
					PathSpecifier: &routev3.RouteMatch_Prefix{Prefix: "/"},
				},
				Action: &routev3.Route_Route{
					Route: &routev3.RouteAction{
						ClusterSpecifier: &routev3.RouteAction_Cluster{Cluster: route.ClusterName()},
					},
				},
			},
		},
	}
}

// buildHTTPListener returns the plain-HTTP listener that unconditionally
// redirects every request to HTTPS on the same host.
func buildHTTPListener(port uint32) *listenerv3.Listener {
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

// buildHTTPSListener returns the TLS listener that serves routed traffic.
// Its routes come from RDS (dynamic, via ADS); its certificate comes from
// SDS served by the separate envoy-acme control plane, referenced here only
// by cluster name + secret name.
func buildHTTPSListener(port uint32, certSecretName, acmeSDSClusterName string) *listenerv3.Listener {
	hcm := &hcmv3.HttpConnectionManager{
		StatPrefix: "https",
		RouteSpecifier: &hcmv3.HttpConnectionManager_Rds{
			Rds: &hcmv3.Rds{
				RouteConfigName: httpsRouteConfigName,
				ConfigSource:    adsConfigSource(),
			},
		},
		HttpFilters: []*hcmv3.HttpFilter{routerHTTPFilter()},
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
		Name:    httpsListenerName,
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
