package xds

import (
	"fmt"
	"sort"
	"strings"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	cachetypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
)

func BuildSnapshotForConfig(version string, httpCfg model.HTTPConfiguration, cfg Config) (cachev3.ResourceSnapshot, error) {
	if httpCfg.Routes == nil {
		httpCfg.Routes = map[string]model.Route{}
	}
	if httpCfg.Services == nil {
		httpCfg.Services = map[string]model.HTTPService{}
	}
	if httpCfg.Middlewares == nil {
		httpCfg.Middlewares = map[string]model.Middleware{}
	}
	for name, middleware := range httpCfg.Middlewares {
		if middleware.Name != name {
			return nil, fmt.Errorf("HTTP middleware map key %q does not match middleware name %q", name, middleware.Name)
		}
		if err := middleware.Validate(); err != nil {
			return nil, fmt.Errorf("invalid HTTP middleware %q: %w", name, err)
		}
	}
	for key, route := range httpCfg.Routes {
		if len(route.MiddlewareNames) == 0 {
			continue
		}
		resolved := make([]model.Middleware, 0, len(route.MiddlewareNames))
		for _, name := range route.MiddlewareNames {
			middleware, ok := httpCfg.Middlewares[name]
			if !ok {
				return nil, fmt.Errorf("router %q references unknown middleware %q", route.RouterName, name)
			}
			resolved = append(resolved, middleware)
		}
		route.Middlewares = resolved
		httpCfg.Routes[key] = route
	}
	for name, service := range httpCfg.Services {
		if service.Name != name {
			return nil, fmt.Errorf("HTTP service map key %q does not match service name %q", name, service.Name)
		}
		if err := service.Validate(); err != nil {
			return nil, fmt.Errorf("invalid HTTP service %q: %w", name, err)
		}
		if _, err := httpCfg.ResolveService(name); err != nil {
			return nil, err
		}
	}
	for _, route := range httpCfg.Routes {
		if err := model.ValidateMiddlewareChain(route.Middlewares); err != nil {
			return nil, fmt.Errorf("router %q has invalid middleware chain: %w", route.RouterName, err)
		}
		if route.Timeout != nil && *route.Timeout < 0 {
			return nil, fmt.Errorf("router %q has a negative timeout", route.RouterName)
		}
		if route.IdleTimeout != nil && *route.IdleTimeout < 0 {
			return nil, fmt.Errorf("router %q has a negative idle timeout", route.RouterName)
		}
		if route.Retry != nil {
			if strings.TrimSpace(route.Retry.RetryOn) == "" {
				return nil, fmt.Errorf("router %q retry policy requires retryon", route.RouterName)
			}
			if route.Retry.PerTryTimeout < 0 {
				return nil, fmt.Errorf("router %q has a negative per-try timeout", route.RouterName)
			}
		}
		if route.ServiceName != "" {
			if _, err := httpCfg.ResolveService(route.ServiceName); err != nil {
				return nil, fmt.Errorf("router %q: %w", route.RouterName, err)
			}
		}
	}

	routeConfig := buildHTTPSRouteConfiguration(httpCfg.Routes, sortedSubdomains(httpCfg.Routes), cfg.BaseDomain, nil)
	published := publishedRoutes(httpCfg.Routes, routeConfig)
	plan, err := planSecurity(published)
	if err != nil {
		return nil, fmt.Errorf("planning security middleware: %w", err)
	}

	clusterResources := []cachetypes.Resource{}
	endpointResources := []cachetypes.Resource{}
	clusterNames := map[string]string{}
	for _, name := range sortedSubdomains(published) {
		route := published[name]
		if route.ServiceName != "" {
			continue
		}
		clusterName := route.ClusterName()
		if prior, exists := clusterNames[clusterName]; exists {
			return nil, fmt.Errorf("xDS cluster name %q collides between %s and legacy route %q", clusterName, prior, route.RouterName)
		}
		clusterNames[clusterName] = fmt.Sprintf("legacy route %q", route.RouterName)
		clusterResources = append(clusterResources, buildCluster(clusterName))
		endpointResources = append(endpointResources, buildClusterLoadAssignment(route))
	}
	serviceNames := make([]string, 0, len(httpCfg.Services))
	for name, s := range httpCfg.Services {
		if len(s.Weighted) == 0 {
			serviceNames = append(serviceNames, name)
		}
	}
	sort.Strings(serviceNames)
	for _, name := range serviceNames {
		s := httpCfg.Services[name]
		clusterName := model.NamedServiceClusterName(s.Name)
		if prior, exists := clusterNames[clusterName]; exists {
			return nil, fmt.Errorf("xDS cluster name %q collides between %s and named service %q", clusterName, prior, s.Name)
		}
		clusterNames[clusterName] = fmt.Sprintf("named service %q", s.Name)
		clusterResources = append(clusterResources, buildServiceCluster(s))
		endpointResources = append(endpointResources, buildServiceLoadAssignment(s))
	}
	for _, c := range plan.authClusters {
		if prior, exists := clusterNames[c.Name]; exists {
			return nil, fmt.Errorf("xDS cluster name %q collides between %s and a forwardauth service", c.Name, prior)
		}
		clusterNames[c.Name] = "forwardauth service"
		clusterResources = append(clusterResources, c)
	}

	byRouteName := map[string]model.Route{}
	for _, r := range published {
		name := routeResourceName(r)
		if prior, exists := byRouteName[name]; exists {
			return nil, fmt.Errorf("xDS route name %q collides between routers %q and %q", name, prior.RouterName, r.RouterName)
		}
		byRouteName[name] = r
	}
	for _, vh := range routeConfig.VirtualHosts {
		for _, er := range vh.Routes {
			old := er.GetRoute()
			if old == nil {
				continue
			}
			r, ok := byRouteName[er.Name]
			if !ok {
				continue
			}
			er.Action = &routev3.Route_Route{Route: configuredRouteAction(r, httpCfg)}
			if err := applyRouteMiddlewares(er, r.Middlewares); err != nil {
				return nil, fmt.Errorf("router %q middleware compilation: %w", r.RouterName, err)
			}
			applyRouteSecurity(er, r.Middlewares)
		}
	}
	applySecurityDefaults(routeConfig, plan)

	resources := map[resourcev3.Type][]cachetypes.Resource{
		resourcev3.ClusterType:  clusterResources,
		resourcev3.EndpointType: endpointResources,
		resourcev3.RouteType:    {routeConfig},
		resourcev3.ListenerType: {buildHTTPListener(cfg.HTTPPort), buildHTTPSListener(cfg.HTTPSPort, cfg.CertSecretName, cfg.ACMESDSClusterName, plan)},
	}
	snap, err := cachev3.NewSnapshot(version, resources)
	if err != nil {
		return nil, fmt.Errorf("building snapshot: %w", err)
	}
	return snap, nil
}

func buildServiceCluster(s model.HTTPService) *clusterv3.Cluster {
	name := model.NamedServiceClusterName(s.Name)
	c := buildCluster(name)
	if s.Sticky != nil {
		c.LbPolicy = clusterv3.Cluster_RING_HASH
	}
	if h := s.HealthCheck; h != nil {
		c.HealthChecks = []*corev3.HealthCheck{{Timeout: durationpb.New(h.Timeout), Interval: durationpb.New(h.Interval), UnhealthyThreshold: wrapperspb.UInt32(h.UnhealthyThreshold), HealthyThreshold: wrapperspb.UInt32(h.HealthyThreshold), HealthChecker: &corev3.HealthCheck_HttpHealthCheck_{HttpHealthCheck: &corev3.HealthCheck_HttpHealthCheck{Path: h.Path}}}}
	}
	if o := s.Outlier; o != nil {
		od := &clusterv3.OutlierDetection{}
		if o.Consecutive5xx > 0 {
			od.Consecutive_5Xx = wrapperspb.UInt32(o.Consecutive5xx)
		}
		if o.Interval > 0 {
			od.Interval = durationpb.New(o.Interval)
		}
		if o.BaseEjectionTime > 0 {
			od.BaseEjectionTime = durationpb.New(o.BaseEjectionTime)
		}
		if o.MaxEjectionPercent != nil {
			od.MaxEjectionPercent = wrapperspb.UInt32(*o.MaxEjectionPercent)
		}
		c.OutlierDetection = od
	}
	switch s.Protocol {
	case model.ProtocolHTTP2, model.ProtocolGRPC:
		c.Http2ProtocolOptions = &corev3.Http2ProtocolOptions{}
	case model.ProtocolHTTPS:
		validation := &tlsv3.CertificateValidationContext{TrustedCa: &corev3.DataSource{Specifier: &corev3.DataSource_Filename{Filename: "/etc/ssl/certs/ca-certificates.crt"}}}
		upstreamTLS := &tlsv3.UpstreamTlsContext{CommonTlsContext: &tlsv3.CommonTlsContext{ValidationContextType: &tlsv3.CommonTlsContext_ValidationContext{ValidationContext: validation}}}
		c.TransportSocket = &corev3.TransportSocket{Name: transportSocketTLS, ConfigType: &corev3.TransportSocket_TypedConfig{TypedConfig: mustAny(upstreamTLS)}}
		c.UpstreamHttpProtocolOptions = &corev3.UpstreamHttpProtocolOptions{AutoSni: true, AutoSanValidation: true}
	}
	return c
}

func buildServiceLoadAssignment(s model.HTTPService) *endpointv3.ClusterLoadAssignment {
	r := model.Route{Subdomain: model.NamedServiceClusterName(s.Name), Endpoints: s.Endpoints}
	return buildClusterLoadAssignment(r)
}

func configuredRouteAction(route model.Route, cfg model.HTTPConfiguration) *routev3.RouteAction {
	a := &routev3.RouteAction{}
	if route.ServiceName == "" {
		a.ClusterSpecifier = &routev3.RouteAction_Cluster{Cluster: route.ClusterName()}
	} else {
		resolved, _ := cfg.ResolveService(route.ServiceName)
		if len(resolved) == 1 {
			a.ClusterSpecifier = &routev3.RouteAction_Cluster{Cluster: model.NamedServiceClusterName(resolved[0].Name)}
		} else {
			wc := &routev3.WeightedCluster{}
			for _, target := range resolved {
				wc.Clusters = append(wc.Clusters, &routev3.WeightedCluster_ClusterWeight{Name: model.NamedServiceClusterName(target.Name), Weight: wrapperspb.UInt32(target.Weight)})
			}
			a.ClusterSpecifier = &routev3.RouteAction_WeightedClusters{WeightedClusters: wc}
		}
		root := cfg.Services[route.ServiceName]
		if len(root.Weighted) == 0 && root.Sticky != nil {
			cookie := root.Sticky
			attrs := []*routev3.RouteAction_HashPolicy_CookieAttribute{}
			if cookie.Secure {
				attrs = append(attrs, &routev3.RouteAction_HashPolicy_CookieAttribute{Name: "Secure"})
			}
			if cookie.HTTPOnly {
				attrs = append(attrs, &routev3.RouteAction_HashPolicy_CookieAttribute{Name: "HttpOnly"})
			}
			if cookie.SameSite != "" {
				attrs = append(attrs, &routev3.RouteAction_HashPolicy_CookieAttribute{Name: "SameSite", Value: canonicalSameSite(cookie.SameSite)})
			}
			cp := &routev3.RouteAction_HashPolicy_Cookie{Name: cookie.Name, Path: "/", Attributes: attrs}
			if cookie.TTL >= 0 {
				cp.Ttl = durationpb.New(cookie.TTL)
			}
			a.HashPolicy = []*routev3.RouteAction_HashPolicy{{PolicySpecifier: &routev3.RouteAction_HashPolicy_Cookie_{Cookie: cp}, Terminal: true}}
		}
	}
	if route.Timeout != nil {
		a.Timeout = durationpb.New(*route.Timeout)
	}
	if route.IdleTimeout != nil {
		a.IdleTimeout = durationpb.New(*route.IdleTimeout)
	}
	if r := route.Retry; r != nil {
		a.RetryPolicy = &routev3.RetryPolicy{RetryOn: r.RetryOn}
		if r.Attempts > 0 {
			a.RetryPolicy.NumRetries = wrapperspb.UInt32(r.Attempts)
		}
		if r.PerTryTimeout > 0 {
			a.RetryPolicy.PerTryTimeout = durationpb.New(r.PerTryTimeout)
		}
	}
	return a
}

func canonicalSameSite(value string) string {
	switch value {
	case "lax":
		return "Lax"
	case "strict":
		return "Strict"
	case "none":
		return "None"
	default:
		return value
	}
}
