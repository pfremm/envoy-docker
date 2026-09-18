package xds

import (
	"testing"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	localrlv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/local_ratelimit/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
)

func durationPtr(d time.Duration) *time.Duration { return &d }
func uint32Ptr(v uint32) *uint32                 { return &v }

func TestBuildSnapshotForConfigNamedServicePolicies(t *testing.T) {
	cfg := model.HTTPConfiguration{Routes: map[string]model.Route{"app": {Subdomain: "app", RouterName: "web", ServiceName: "api", Timeout: durationPtr(30 * time.Second), IdleTimeout: durationPtr(5 * time.Second), Retry: &model.RetryPolicy{Attempts: 3, PerTryTimeout: 2 * time.Second, RetryOn: "5xx,reset"}}}, Services: map[string]model.HTTPService{
		"api": {Name: "api", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}, {Address: "10.0.0.1", Port: 8081}}, Protocol: model.ProtocolHTTPS, HealthCheck: &model.HealthCheck{Path: "/ready", Interval: 7 * time.Second, Timeout: time.Second, UnhealthyThreshold: 4, HealthyThreshold: 2}, Outlier: &model.OutlierDetection{Consecutive5xx: 6, Interval: 11 * time.Second, BaseEjectionTime: 31 * time.Second, MaxEjectionPercent: uint32Ptr(50)}, Sticky: &model.StickyCookie{Name: "affinity", Secure: true, HTTPOnly: true, SameSite: "lax", TTL: time.Hour}},
	}}

	snap, err := BuildSnapshotForConfig("1", cfg, Config{BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	name := model.NamedServiceClusterName("api")
	cluster := snap.GetResources(resourcev3.ClusterType)[name].(*clusterv3.Cluster)
	if cluster.LbPolicy != clusterv3.Cluster_RING_HASH {
		t.Fatalf("lb=%v", cluster.LbPolicy)
	}
	if len(cluster.HealthChecks) != 1 || cluster.HealthChecks[0].GetHttpHealthCheck().Path != "/ready" || cluster.HealthChecks[0].UnhealthyThreshold.Value != 4 {
		t.Fatalf("health=%+v", cluster.HealthChecks)
	}
	if cluster.OutlierDetection.GetConsecutive_5Xx().Value != 6 || cluster.OutlierDetection.GetMaxEjectionPercent().Value != 50 {
		t.Fatalf("outlier=%+v", cluster.OutlierDetection)
	}
	up := &tlsv3.UpstreamTlsContext{}
	if cluster.TransportSocket == nil || cluster.TransportSocket.GetTypedConfig().UnmarshalTo(up) != nil {
		t.Fatal("expected upstream TLS context")
	}
	if up.GetCommonTlsContext().GetValidationContext().GetTrustedCa().GetFilename() != "/etc/ssl/certs/ca-certificates.crt" || !cluster.GetUpstreamHttpProtocolOptions().GetAutoSni() || !cluster.GetUpstreamHttpProtocolOptions().GetAutoSanValidation() {
		t.Fatal("upstream HTTPS must verify system CAs with automatic SNI/SAN validation")
	}
	cla := snap.GetResources(resourcev3.EndpointType)[name].(*endpointv3.ClusterLoadAssignment)
	if len(cla.Endpoints[0].LbEndpoints) != 2 {
		t.Fatalf("endpoints=%+v", cla.Endpoints)
	}
	rc := snap.GetResources(resourcev3.RouteType)[httpsRouteConfigName].(*routev3.RouteConfiguration)
	a := rc.VirtualHosts[0].Routes[0].GetRoute()
	if a.GetCluster() != name || a.Timeout.AsDuration() != 30*time.Second || a.IdleTimeout.AsDuration() != 5*time.Second {
		t.Fatalf("action=%+v", a)
	}
	if a.RetryPolicy.GetNumRetries().Value != 2 || a.RetryPolicy.PerTryTimeout.AsDuration() != 2*time.Second || a.RetryPolicy.RetryOn != "5xx,reset" {
		t.Fatalf("retry=%+v", a.RetryPolicy)
	}
	cookie := a.HashPolicy[0].GetCookie()
	if cookie.Name != "affinity" || cookie.Ttl.AsDuration() != time.Hour || len(cookie.Attributes) != 3 {
		t.Fatalf("cookie=%+v", cookie)
	}
}

func TestBuildSnapshotForConfigWeightedServicesAndHTTP2(t *testing.T) {
	cfg := model.HTTPConfiguration{Routes: map[string]model.Route{"app": {Subdomain: "app", RouterName: "web", ServiceName: "rollout"}}, Services: map[string]model.HTTPService{
		"blue":    {Name: "blue", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}}, Protocol: model.ProtocolHTTP2},
		"green":   {Name: "green", Endpoints: []model.Endpoint{{Address: "10.0.0.2", Port: 8080}}, Protocol: model.ProtocolGRPC},
		"rollout": {Name: "rollout", Weighted: []model.WeightedService{{Name: "green", Weight: 1}, {Name: "blue", Weight: 9}}},
	}}

	snap, err := BuildSnapshotForConfig("1", cfg, Config{BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	clusters := snap.GetResources(resourcev3.ClusterType)
	if len(clusters) != 2 {
		t.Fatalf("clusters=%v", clusters)
	}
	for _, n := range []string{"blue", "green"} {
		if clusters[model.NamedServiceClusterName(n)].(*clusterv3.Cluster).Http2ProtocolOptions == nil {
			t.Fatalf("%s should use HTTP/2", n)
		}
	}
	rc := snap.GetResources(resourcev3.RouteType)[httpsRouteConfigName].(*routev3.RouteConfiguration)
	weights := rc.VirtualHosts[0].Routes[0].GetRoute().GetWeightedClusters().Clusters
	if len(weights) != 2 || weights[0].Name != model.NamedServiceClusterName("blue") || weights[0].Weight.Value != 9 || weights[1].Name != model.NamedServiceClusterName("green") || weights[1].Weight.Value != 1 {
		t.Fatalf("weights=%+v", weights)
	}
}

func TestBuildSnapshotForConfigEmitsExplicitZeroMaxEjectionPercent(t *testing.T) {
	zero := uint32(0)
	cfg := model.HTTPConfiguration{Routes: map[string]model.Route{"app": {Subdomain: "app", ServiceName: "api"}}, Services: map[string]model.HTTPService{
		"api": {Name: "api", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}}, Outlier: &model.OutlierDetection{MaxEjectionPercent: &zero}},
	}}

	snap, err := BuildSnapshotForConfig("1", cfg, Config{BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	cluster := snap.GetResources(resourcev3.ClusterType)[model.NamedServiceClusterName("api")].(*clusterv3.Cluster)
	if cluster.OutlierDetection.MaxEjectionPercent == nil || cluster.OutlierDetection.MaxEjectionPercent.Value != 0 {
		t.Fatalf("explicit zero was not preserved: %+v", cluster.OutlierDetection)
	}
}

func TestBuildSnapshotForConfigLegacyRouteUnchanged(t *testing.T) {
	// A legacy router (no .service) must keep its implicit per-router
	// cluster and endpoint through the config-based builder.
	cfg := model.HTTPConfiguration{Routes: map[string]model.Route{"app": {
		Subdomain: "app", RouterName: "web", Source: model.SourceDocker,
		Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}},
	}}, Services: map[string]model.HTTPService{}}

	snap, err := BuildSnapshotForConfig("1", cfg, Config{BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := snap.GetResources(resourcev3.ClusterType)["app"]; !ok {
		t.Fatalf("legacy cluster missing: %v", snap.GetResources(resourcev3.ClusterType))
	}
	cla := snap.GetResources(resourcev3.EndpointType)["app"].(*endpointv3.ClusterLoadAssignment)
	if len(cla.Endpoints[0].LbEndpoints) != 1 {
		t.Fatalf("endpoints=%+v", cla.Endpoints)
	}
	rc := snap.GetResources(resourcev3.RouteType)[httpsRouteConfigName].(*routev3.RouteConfiguration)
	a := rc.VirtualHosts[0].Routes[0].GetRoute()
	if a.GetCluster() != "app" || a.Timeout != nil || a.RetryPolicy != nil || len(a.HashPolicy) != 0 {
		t.Fatalf("legacy action must stay plain: %+v", a)
	}
}

func TestBuildSnapshotForConfigKeepsPoliciesPerRouterSharingService(t *testing.T) {
	cfg := model.HTTPConfiguration{
		Routes: map[string]model.Route{
			"one": {Subdomain: "one", RouterName: "one", ServiceName: "api", Middlewares: []model.Middleware{{Name: "one-rate", RateLimit: &model.RateLimitMiddleware{Average: 1, Burst: 2, Period: "1s"}}}},
			"two": {Subdomain: "two", RouterName: "two", ServiceName: "api", Middlewares: []model.Middleware{{Name: "two-rate", RateLimit: &model.RateLimitMiddleware{Average: 3, Burst: 7, Period: "1s"}}}},
		},
		Services: map[string]model.HTTPService{"api": {Name: "api", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}}}},
	}
	snap, err := BuildSnapshotForConfig("1", cfg, Config{BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	rc := snap.GetResources(resourcev3.RouteType)[httpsRouteConfigName].(*routev3.RouteConfiguration)
	wantBurst := map[string]uint32{"one": 2, "two": 7}
	seen := map[string]bool{}
	for _, vh := range rc.VirtualHosts {
		for _, er := range vh.Routes {
			want, ok := wantBurst[er.Name]
			if !ok {
				continue
			}
			cfg := &localrlv3.LocalRateLimit{}
			unmarshalAny(t, er.TypedPerFilterConfig[localRLFilterName], cfg)
			if got := cfg.GetTokenBucket().GetMaxTokens(); got != want {
				t.Fatalf("router %q burst = %d, want %d", er.Name, got, want)
			}
			seen[er.Name] = true
		}
	}
	if !seen["one"] || !seen["two"] {
		t.Fatalf("missing named routes, seen %v", seen)
	}
}

func TestBuildSnapshotForConfigRejectsUnknownAndCycle(t *testing.T) {
	base := Config{BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443}
	_, err := BuildSnapshotForConfig("1", model.HTTPConfiguration{Routes: map[string]model.Route{"app": {Subdomain: "app", ServiceName: "missing"}}, Services: map[string]model.HTTPService{}}, base)
	if err == nil {
		t.Fatal("expected unknown service error")
	}
	_, err = BuildSnapshotForConfig("1", model.HTTPConfiguration{Routes: map[string]model.Route{}, Services: map[string]model.HTTPService{"a": {Name: "a", Weighted: []model.WeightedService{{Name: "b", Weight: 1}}}, "b": {Name: "b", Weighted: []model.WeightedService{{Name: "a", Weight: 1}}}}}, base)
	if err == nil {
		t.Fatal("expected cycle error")
	}
}

// The config-path builder (the one main.go actually uses) must also always
// emit the default https_routes RDS resource, including on the initial
// publish with zero routes.
func TestBuildSnapshotForConfigEmptyStillPublishesDefaultRouteConfig(t *testing.T) {
	cfg := Config{BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443, CertSecretName: "c", ACMESDSClusterName: "a"}
	snap, err := BuildSnapshotForConfig("1", model.HTTPConfiguration{}, cfg)
	if err != nil {
		t.Fatalf("BuildSnapshotForConfig() unexpected error: %v", err)
	}
	rcs := snap.GetResources(resourcev3.RouteType)
	if _, ok := rcs[httpsRouteConfigName]; !ok {
		t.Fatalf("default route config %q must exist with zero routes, got %v", httpsRouteConfigName, rcs)
	}
}

// Two containers reusing the same router name on DIFFERENT subdomains must
// not reject the whole snapshot: the build-layer dedupe keeps the first
// claimant (sorted-subdomain order, deterministic) and skips the later one
// with a warning, mirroring the discovery-layer guard (which also covers
// docker paths; this one additionally covers static config).
func TestBuildSnapshotForConfigDuplicateRouterNamesDeduped(t *testing.T) {
	cfg := Config{BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443, CertSecretName: "c", ACMESDSClusterName: "a"}
	httpCfg := model.HTTPConfiguration{
		Routes: map[string]model.Route{
			"app1": {Subdomain: "app1", RouterName: "web", Origin: "c1/web", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 80}}},
			"app2": {Subdomain: "app2", RouterName: "web", Origin: "c2/web", Endpoints: []model.Endpoint{{Address: "10.0.0.2", Port: 80}}},
		},
	}
	snap, err := BuildSnapshotForConfig("1", httpCfg, cfg)
	if err != nil {
		t.Fatalf("duplicate router names must not reject the snapshot: %v", err)
	}
	rc := snap.GetResources(resourcev3.RouteType)[httpsRouteConfigName].(*routev3.RouteConfiguration)
	domains := map[string]bool{}
	for _, vh := range rc.VirtualHosts {
		for _, d := range vh.Domains {
			domains[d] = true
		}
	}
	if !domains["app1.example.com"] {
		t.Errorf("first claimant app1 should publish, got %v", domains)
	}
	if domains["app2.example.com"] {
		t.Errorf("later duplicate app2 must be skipped, got %v", domains)
	}
}
