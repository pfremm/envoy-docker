package xds

import (
	"strings"
	"testing"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	compressorv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/compressor/v3"
	customresponsev3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/custom_response/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
)

func indexOf(names []string, target string) int {
	for i, n := range names {
		if n == target {
			return i
		}
	}
	return -1
}

// --- Compression: listener-level LDS ---

func TestBuildSnapshot_CompressionListenerFilter(t *testing.T) {
	routes := map[string]model.Route{
		"app": {
			Subdomain: "app", RouterName: "web",
			Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}},
			Middlewares: []model.Middleware{{
				Name: "gz",
				Compress: &model.CompressMiddleware{
					MinResponseBytes: 256,
					ContentTypes:     []string{"text/html", "application/json"},
				},
			}},
		},
	}
	snap, err := BuildSnapshot("1", routes, Config{BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	hcm := httpsHCM(t, snap)
	names := filterNames(hcm)
	if idx := indexOf(names, gzipCompressorFilterName); idx < 0 {
		t.Fatalf("expected gzip compressor filter in listener, got %v", names)
	}
	// Router must always be last.
	if names[len(names)-1] != "envoy.filters.http.router" {
		t.Fatalf("router filter must be last, got %v", names)
	}
	var gz *hcmv3.HttpFilter
	for _, f := range hcm.HttpFilters {
		if f.Name == gzipCompressorFilterName {
			gz = f
		}
	}
	comp := &compressorv3.Compressor{}
	unmarshalAny(t, gz.GetTypedConfig(), comp)
	if comp.GetResponseDirectionConfig().GetCommonConfig().GetMinContentLength().GetValue() != 256 {
		t.Fatalf("min content length not wired: %+v", comp)
	}
	got := comp.GetResponseDirectionConfig().GetCommonConfig().GetContentType()
	if len(got) != 2 || got[0] != "application/json" || got[1] != "text/html" {
		t.Fatalf("content types not wired/sorted: %v", got)
	}
}

func TestBuildSnapshot_CompressionConflictRejected(t *testing.T) {
	routes := map[string]model.Route{
		"a": {Subdomain: "a", RouterName: "a", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 1}},
			Middlewares: []model.Middleware{{Name: "c1", Compress: &model.CompressMiddleware{MinResponseBytes: 100}}}},
		"b": {Subdomain: "b", RouterName: "b", Endpoints: []model.Endpoint{{Address: "10.0.0.2", Port: 2}},
			Middlewares: []model.Middleware{{Name: "c2", Compress: &model.CompressMiddleware{MinResponseBytes: 999}}}},
	}
	_, err := BuildSnapshot("1", routes, Config{BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443})
	if err == nil || !strings.Contains(err.Error(), "conflicting compress") {
		t.Fatalf("expected conflicting compress error, got %v", err)
	}
}

func TestBuildSnapshot_NoCompressionNoFilter(t *testing.T) {
	routes := map[string]model.Route{
		"app": {Subdomain: "app", RouterName: "web", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}}},
	}
	snap, err := BuildSnapshot("1", routes, Config{BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	hcm := httpsHCM(t, snap)
	if idx := indexOf(filterNames(hcm), gzipCompressorFilterName); idx >= 0 {
		t.Fatalf("no route uses compress; compressor filter should be absent, got %v", filterNames(hcm))
	}
}

// --- gRPC-Web: listener-level LDS + CORS ordering + protocol validation ---

func TestBuildSnapshotForConfig_GRPCWebListenerFilterAndOrdering(t *testing.T) {
	cfg := model.HTTPConfiguration{
		Routes: map[string]model.Route{
			"app": {Subdomain: "app", RouterName: "web", ServiceName: "grpcsvc",
				Middlewares: []model.Middleware{{Name: "gw", GRPCWeb: &model.GRPCWebMiddleware{Enabled: true}}}},
		},
		Services: map[string]model.HTTPService{
			"grpcsvc": {Name: "grpcsvc", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 9090}}, Protocol: model.ProtocolGRPC},
		},
	}
	snap, err := BuildSnapshotForConfig("1", cfg, Config{BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	hcm := httpsHCM(t, snap)
	names := filterNames(hcm)
	grpcIdx := indexOf(names, grpcWebFilterName)
	corsIdx := indexOf(names, corsFilterName)
	if grpcIdx < 0 {
		t.Fatalf("expected grpc_web filter in listener, got %v", names)
	}
	if corsIdx < 0 || grpcIdx > corsIdx {
		t.Fatalf("grpc_web must precede cors: names=%v", names)
	}
}

func TestBuildSnapshotForConfig_GRPCWebRejectsNonHTTP2Upstream(t *testing.T) {
	cfg := model.HTTPConfiguration{
		Routes: map[string]model.Route{
			"app": {Subdomain: "app", RouterName: "web", ServiceName: "svc",
				Middlewares: []model.Middleware{{Name: "gw", GRPCWeb: &model.GRPCWebMiddleware{Enabled: true}}}},
		},
		Services: map[string]model.HTTPService{
			"svc": {Name: "svc", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}}, Protocol: model.ProtocolHTTP1},
		},
	}
	_, err := BuildSnapshotForConfig("1", cfg, Config{BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443})
	if err == nil || !strings.Contains(err.Error(), "grpcweb") {
		t.Fatalf("expected grpcweb upstream protocol validation error, got %v", err)
	}
}

func TestBuildSnapshotForConfig_GRPCWebRejectsLegacyRoute(t *testing.T) {
	cfg := model.HTTPConfiguration{
		Routes: map[string]model.Route{
			"app": {Subdomain: "app", RouterName: "web", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}},
				Middlewares: []model.Middleware{{Name: "gw", GRPCWeb: &model.GRPCWebMiddleware{Enabled: true}}}},
		},
		Services: map[string]model.HTTPService{},
	}
	_, err := BuildSnapshotForConfig("1", cfg, Config{BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443})
	if err == nil {
		t.Fatal("expected error for legacy route with grpcweb")
	}
}

// --- Circuit breakers: cluster-scoped CDS, variant derivation + dedup ---

func TestBuildSnapshot_CircuitBreakerAppliedDirectlyWhenSinglePolicy(t *testing.T) {
	routes := map[string]model.Route{
		"app": {
			Subdomain: "app", RouterName: "web",
			Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}},
			Middlewares: []model.Middleware{{
				Name:           "cb",
				CircuitBreaker: &model.CircuitBreakerMiddleware{MaxConnections: 100, MaxPendingRequests: 50, MaxRequests: 200, MaxRetries: 3},
			}},
		},
	}
	snap, err := BuildSnapshot("1", routes, Config{BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	clusters := snap.GetResources(resourcev3.ClusterType)
	if len(clusters) != 1 {
		t.Fatalf("expected 1 cluster (no variant needed), got %d: %v", len(clusters), clusters)
	}
	c := clusters["app"].(*clusterv3.Cluster)
	th := c.CircuitBreakers.GetThresholds()[0]
	if th.MaxConnections.GetValue() != 100 || th.MaxPendingRequests.GetValue() != 50 || th.MaxRequests.GetValue() != 200 || th.MaxRetries.GetValue() != 3 {
		t.Fatalf("thresholds not applied: %+v", th)
	}
}

func TestBuildSnapshotForConfig_CircuitBreakerVariantDerivationAndDedup(t *testing.T) {
	// Two routers share the "api" named service but request different CB
	// policies: expect two variant clusters and the base cluster left
	// untouched (Envoy defaults). A third router requests the SAME policy
	// as the first, which must dedupe onto the same variant (no third
	// cluster).
	cfg := model.HTTPConfiguration{
		Routes: map[string]model.Route{
			"one": {Subdomain: "one", RouterName: "one", ServiceName: "api",
				Middlewares: []model.Middleware{{Name: "cb1", CircuitBreaker: &model.CircuitBreakerMiddleware{MaxConnections: 10}}}},
			"two": {Subdomain: "two", RouterName: "two", ServiceName: "api",
				Middlewares: []model.Middleware{{Name: "cb2", CircuitBreaker: &model.CircuitBreakerMiddleware{MaxConnections: 20}}}},
			"three": {Subdomain: "three", RouterName: "three", ServiceName: "api",
				Middlewares: []model.Middleware{{Name: "cb3", CircuitBreaker: &model.CircuitBreakerMiddleware{MaxConnections: 10}}}},
		},
		Services: map[string]model.HTTPService{
			"api": {Name: "api", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}}},
		},
	}
	snap, err := BuildSnapshotForConfig("1", cfg, Config{BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	clusters := snap.GetResources(resourcev3.ClusterType)
	// base "http-service/api" + 2 distinct variants (10 and 20) = 3 total.
	if len(clusters) != 3 {
		names := make([]string, 0, len(clusters))
		for n := range clusters {
			names = append(names, n)
		}
		t.Fatalf("expected 3 clusters (base + 2 dedup'd variants), got %d: %v", len(clusters), names)
	}
	base := clusters[model.NamedServiceClusterName("api")].(*clusterv3.Cluster)
	if base.CircuitBreakers != nil {
		t.Fatalf("base cluster should be untouched when policies differ, got %+v", base.CircuitBreakers)
	}
	var variant10, variant20 *clusterv3.Cluster
	for name, res := range clusters {
		if name == model.NamedServiceClusterName("api") {
			continue
		}
		c := res.(*clusterv3.Cluster)
		switch c.CircuitBreakers.GetThresholds()[0].MaxConnections.GetValue() {
		case 10:
			variant10 = c
		case 20:
			variant20 = c
		}
	}
	if variant10 == nil || variant20 == nil {
		t.Fatalf("expected variant clusters for policies 10 and 20")
	}

	rc := snap.GetResources(resourcev3.RouteType)[httpsRouteConfigName].(*routev3.RouteConfiguration)
	byName := map[string]string{}
	for _, vh := range rc.VirtualHosts {
		for _, er := range vh.Routes {
			byName[er.Name] = er.GetRoute().GetCluster()
		}
	}
	if byName["one"] != variant10.Name || byName["three"] != variant10.Name {
		t.Fatalf("routers one/three should dedupe onto the same variant cluster: one=%q three=%q variant10=%q", byName["one"], byName["three"], variant10.Name)
	}
	if byName["two"] != variant20.Name {
		t.Fatalf("router two should use its own variant cluster: two=%q variant20=%q", byName["two"], variant20.Name)
	}
	if variant10.Name == variant20.Name {
		t.Fatalf("distinct policies must not collapse onto the same cluster")
	}

	endpoints := snap.GetResources(resourcev3.EndpointType)
	if _, ok := endpoints[variant10.Name]; !ok {
		t.Fatalf("expected endpoint assignment for variant cluster %q", variant10.Name)
	}
}

func TestBuildSnapshotForConfig_CircuitBreakerRejectsWeightedService(t *testing.T) {
	cfg := model.HTTPConfiguration{
		Routes: map[string]model.Route{
			"app": {Subdomain: "app", RouterName: "web", ServiceName: "rollout",
				Middlewares: []model.Middleware{{Name: "cb", CircuitBreaker: &model.CircuitBreakerMiddleware{MaxConnections: 5}}}},
		},
		Services: map[string]model.HTTPService{
			"blue":    {Name: "blue", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}}},
			"green":   {Name: "green", Endpoints: []model.Endpoint{{Address: "10.0.0.2", Port: 8080}}},
			"rollout": {Name: "rollout", Weighted: []model.WeightedService{{Name: "blue", Weight: 1}, {Name: "green", Weight: 1}}},
		},
	}
	_, err := BuildSnapshotForConfig("1", cfg, Config{BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443})
	if err == nil || !strings.Contains(err.Error(), "weighted-service") {
		t.Fatalf("expected weighted-service rejection, got %v", err)
	}
}

// --- Error pages: RDS internal redirect + recursion rejection ---

func TestBuildSnapshotForConfig_ErrorsInternalRedirect(t *testing.T) {
	cfg := model.HTTPConfiguration{
		Routes: map[string]model.Route{
			"app": {Subdomain: "app", RouterName: "web", ServiceName: "api",
				Middlewares: []model.Middleware{{Name: "err", Errors: &model.ErrorsMiddleware{Status: []string{"500-599"}, Service: "errpage"}}}},
		},
		Services: map[string]model.HTTPService{
			"api":     {Name: "api", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}}},
			"errpage": {Name: "errpage", Endpoints: []model.Endpoint{{Address: "10.0.0.9", Port: 9999}}},
		},
	}
	snap, err := BuildSnapshotForConfig("1", cfg, Config{BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	rc := snap.GetResources(resourcev3.RouteType)[httpsRouteConfigName].(*routev3.RouteConfiguration)
	var found bool
	for _, vh := range rc.VirtualHosts {
		for _, er := range vh.Routes {
			if er.Name != "web" {
				continue
			}
			cfgAny, ok := er.TypedPerFilterConfig[customResponseFilterName]
			if !ok {
				t.Fatalf("expected custom_response per-route override on route %q", er.Name)
			}
			cr := &customresponsev3.CustomResponse{}
			unmarshalAny(t, cfgAny, cr)
			if cr.GetCustomResponseMatcher() == nil {
				t.Fatal("expected a matcher for error status codes")
			}
			found = true
		}
	}
	if !found {
		t.Fatal("did not find the app route in RDS output")
	}
	// The listener must carry the custom_response filter.
	hcm := httpsHCM(t, snap)
	if indexOf(filterNames(hcm), customResponseFilterName) < 0 {
		t.Fatalf("expected custom_response filter in listener, got %v", filterNames(hcm))
	}
	// A synthetic error-page virtual host must exist and route to errpage's cluster.
	var errVHFound bool
	for _, vh := range rc.VirtualHosts {
		for _, d := range vh.Domains {
			if d == errorPageHost("errpage") {
				errVHFound = true
				if vh.Routes[0].GetRoute().GetCluster() != model.NamedServiceClusterName("errpage") {
					t.Fatalf("error page vhost routes to wrong cluster: %+v", vh.Routes[0].GetRoute())
				}
			}
		}
	}
	if !errVHFound {
		t.Fatal("expected synthetic error-page virtual host")
	}
}

func TestBuildSnapshotForConfig_ErrorsRecursionRejected(t *testing.T) {
	// errpage's OWN route carries an errors middleware pointing back at
	// itself, which must be rejected (no recursive error handling).
	cfg := model.HTTPConfiguration{
		Routes: map[string]model.Route{
			"app": {Subdomain: "app", RouterName: "web", ServiceName: "api",
				Middlewares: []model.Middleware{{Name: "err", Errors: &model.ErrorsMiddleware{Status: []string{"500"}, Service: "errpage"}}}},
			"errpage-route": {Subdomain: "errpage-route", RouterName: "errpage-route", ServiceName: "errpage",
				Middlewares: []model.Middleware{{Name: "err2", Errors: &model.ErrorsMiddleware{Status: []string{"500"}, Service: "errpage"}}}},
		},
		Services: map[string]model.HTTPService{
			"api":     {Name: "api", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}}},
			"errpage": {Name: "errpage", Endpoints: []model.Endpoint{{Address: "10.0.0.9", Port: 9999}}},
		},
	}
	_, err := BuildSnapshotForConfig("1", cfg, Config{BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443})
	if err == nil || !strings.Contains(err.Error(), "recursive") {
		t.Fatalf("expected recursion rejection, got %v", err)
	}
}

func TestBuildSnapshotForConfig_ErrorsUnresolvableServiceRejected(t *testing.T) {
	cfg := model.HTTPConfiguration{
		Routes: map[string]model.Route{
			"app": {Subdomain: "app", RouterName: "web", ServiceName: "api",
				Middlewares: []model.Middleware{{Name: "err", Errors: &model.ErrorsMiddleware{Status: []string{"500"}, Service: "does-not-exist"}}}},
		},
		Services: map[string]model.HTTPService{
			"api": {Name: "api", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}}},
		},
	}
	_, err := BuildSnapshotForConfig("1", cfg, Config{BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443})
	if err == nil || !strings.Contains(err.Error(), "not a named HTTP service") {
		t.Fatalf("expected unresolvable errors.service rejection, got %v", err)
	}
}

// --- Composed filter ordering across all resilience/protocol filters ---

func TestBuildSnapshotForConfig_ComposedFilterOrdering(t *testing.T) {
	cfg := model.HTTPConfiguration{
		Routes: map[string]model.Route{
			"app": {Subdomain: "app", RouterName: "web", ServiceName: "grpcsvc",
				Middlewares: []model.Middleware{
					{Name: "gw", GRPCWeb: &model.GRPCWebMiddleware{Enabled: true}},
					{Name: "gz", Compress: &model.CompressMiddleware{MinResponseBytes: 100}},
				}},
		},
		Services: map[string]model.HTTPService{
			"grpcsvc": {Name: "grpcsvc", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 9090}}, Protocol: model.ProtocolGRPC},
		},
	}
	snap, err := BuildSnapshotForConfig("1", cfg, Config{BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	hcm := httpsHCM(t, snap)
	names := filterNames(hcm)
	grpcIdx := indexOf(names, grpcWebFilterName)
	gzipIdx := indexOf(names, gzipCompressorFilterName)
	corsIdx := indexOf(names, corsFilterName)
	routerIdx := indexOf(names, "envoy.filters.http.router")
	if grpcIdx < 0 || gzipIdx < 0 || corsIdx < 0 || routerIdx < 0 {
		t.Fatalf("missing expected filter(s): %v", names)
	}
	if !(grpcIdx < gzipIdx && gzipIdx < corsIdx && corsIdx < routerIdx) {
		t.Fatalf("filter ordering wrong, want grpc_web < compressor < cors < router, got %v", names)
	}
}
