package xds

import (
	"bytes"
	"io"
	"log/slog"
	"strings"
	"testing"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
	"github.com/bryanpfremm/envoy-control-plane/internal/rule"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestMerge_StaticWinsOnCollision(t *testing.T) {
	dockerRoutes := map[string]model.Route{
		"myapp": {Subdomain: "myapp", Source: model.SourceDocker, Origin: "container-a/web"},
		"other": {Subdomain: "other", Source: model.SourceDocker, Origin: "container-b/web"},
	}
	staticRoutes := map[string]model.Route{
		"myapp": {Subdomain: "myapp", Source: model.SourceStatic, Origin: "static.yaml[0]"},
	}

	merged := Merge(dockerRoutes, staticRoutes, testLogger())

	if len(merged) != 2 {
		t.Fatalf("Merge() returned %d routes, want 2: %+v", len(merged), merged)
	}
	if merged["myapp"].Source != model.SourceStatic {
		t.Errorf("Merge()[myapp].Source = %v, want %v (static should win)", merged["myapp"].Source, model.SourceStatic)
	}
	if merged["other"].Source != model.SourceDocker {
		t.Errorf("Merge()[other].Source = %v, want %v", merged["other"].Source, model.SourceDocker)
	}
}

func TestBuildSnapshot(t *testing.T) {
	routes := map[string]model.Route{
		"myapp": {
			Subdomain: "myapp",
			Endpoints: []model.Endpoint{{Address: "172.20.0.5", Port: 8080}},
			Source:    model.SourceDocker,
		},
		"nas": {
			Subdomain: "nas",
			Endpoints: []model.Endpoint{{Address: "192.168.1.10", Port: 5000}},
			Source:    model.SourceStatic,
		},
	}

	cfg := Config{
		BaseDomain:         "nas.pfrem.me",
		HTTPPort:           80,
		HTTPSPort:          443,
		CertSecretName:     "wildcard-cert",
		ACMESDSClusterName: "acme_sds_cluster",
	}

	snap, err := BuildSnapshot("1", routes, cfg)
	if err != nil {
		t.Fatalf("BuildSnapshot() unexpected error: %v", err)
	}

	clusters := snap.GetResources(resourcev3.ClusterType)
	if len(clusters) != 2 {
		t.Fatalf("expected 2 clusters, got %d", len(clusters))
	}
	if _, ok := clusters["myapp"]; !ok {
		t.Error("expected cluster named \"myapp\"")
	}
	myappCluster := clusters["myapp"].(*clusterv3.Cluster)
	if myappCluster.GetType() != clusterv3.Cluster_EDS {
		t.Errorf("cluster type = %v, want EDS", myappCluster.GetType())
	}

	endpoints := snap.GetResources(resourcev3.EndpointType)
	if len(endpoints) != 2 {
		t.Fatalf("expected 2 endpoint resources, got %d", len(endpoints))
	}

	routeConfigs := snap.GetResources(resourcev3.RouteType)
	rc, ok := routeConfigs[httpsRouteConfigName]
	if !ok {
		t.Fatalf("expected route config %q, got %+v", httpsRouteConfigName, routeConfigs)
	}
	routeConfig := rc.(*routev3.RouteConfiguration)
	if len(routeConfig.VirtualHosts) != 2 {
		t.Fatalf("expected 2 virtual hosts, got %d", len(routeConfig.VirtualHosts))
	}
	gotDomains := map[string]bool{}
	for _, vh := range routeConfig.VirtualHosts {
		for _, d := range vh.Domains {
			gotDomains[d] = true
		}
	}
	for _, want := range []string{"myapp.nas.pfrem.me", "nas.nas.pfrem.me"} {
		if !gotDomains[want] {
			t.Errorf("expected virtual host domain %q, got domains %v", want, gotDomains)
		}
	}

	listeners := snap.GetResources(resourcev3.ListenerType)
	if len(listeners) != 2 {
		t.Fatalf("expected 2 listeners, got %d", len(listeners))
	}

	httpListener := listeners[httpListenerName].(*listenerv3.Listener)
	if httpListener.Address.GetSocketAddress().GetPortValue() != 80 {
		t.Errorf("http listener port = %d, want 80", httpListener.Address.GetSocketAddress().GetPortValue())
	}
	if httpListener.FilterChains[0].TransportSocket != nil {
		t.Error("http listener should not have a transport socket (no TLS)")
	}
	httpHCM := decodeHCM(t, httpListener)
	redirectAction := httpHCM.GetRouteConfig().VirtualHosts[0].Routes[0].GetRedirect()
	if redirectAction == nil || !redirectAction.GetHttpsRedirect() {
		t.Error("http listener's route should be an https_redirect")
	}

	httpsListener := listeners[httpsListenerName].(*listenerv3.Listener)
	if httpsListener.Address.GetSocketAddress().GetPortValue() != 443 {
		t.Errorf("https listener port = %d, want 443", httpsListener.Address.GetSocketAddress().GetPortValue())
	}
	ts := httpsListener.FilterChains[0].TransportSocket
	if ts == nil {
		t.Fatal("https listener should have a TLS transport socket")
	}
	tlsCtx := &tlsv3.DownstreamTlsContext{}
	if err := ts.GetTypedConfig().UnmarshalTo(tlsCtx); err != nil {
		t.Fatalf("unmarshaling downstream tls context: %v", err)
	}
	secretConfigs := tlsCtx.GetCommonTlsContext().GetTlsCertificateSdsSecretConfigs()
	if len(secretConfigs) != 1 || secretConfigs[0].Name != "wildcard-cert" {
		t.Errorf("unexpected SDS secret configs: %+v", secretConfigs)
	}
	acmeCluster := secretConfigs[0].GetSdsConfig().GetApiConfigSource().GetGrpcServices()[0].GetEnvoyGrpc().GetClusterName()
	if acmeCluster != "acme_sds_cluster" {
		t.Errorf("acme SDS cluster name = %q, want %q", acmeCluster, "acme_sds_cluster")
	}

	httpsHCM := decodeHCM(t, httpsListener)
	if httpsHCM.GetRds().GetRouteConfigName() != httpsRouteConfigName {
		t.Errorf("https listener RDS route config name = %q, want %q", httpsHCM.GetRds().GetRouteConfigName(), httpsRouteConfigName)
	}
}

func decodeHCM(t *testing.T, l *listenerv3.Listener) *hcmv3.HttpConnectionManager {
	t.Helper()
	hcm := &hcmv3.HttpConnectionManager{}
	if err := l.FilterChains[0].Filters[0].GetTypedConfig().UnmarshalTo(hcm); err != nil {
		t.Fatalf("unmarshaling HCM for listener %q: %v", l.Name, err)
	}
	return hcm
}

// vhByDomain indexes the virtual hosts of a route configuration by their
// (single) domain.
func vhByDomain(t *testing.T, rc *routev3.RouteConfiguration) map[string]*routev3.VirtualHost {
	t.Helper()
	byDomain := map[string]*routev3.VirtualHost{}
	for _, vh := range rc.VirtualHosts {
		if len(vh.Domains) != 1 {
			t.Fatalf("virtual host %q has %d domains, want 1: %v", vh.Name, len(vh.Domains), vh.Domains)
		}
		byDomain[vh.Domains[0]] = vh
	}
	return byDomain
}

func TestBuildRouteConfig_PriorityOrdering(t *testing.T) {
	// Two rule-based routes on the same host. The shorter rule has an
	// explicit priority and must be emitted first (Envoy first-match-wins).
	routes := map[string]model.Route{
		"api": {
			Subdomain:  "api",
			Endpoints:  []model.Endpoint{{Address: "10.0.0.2", Port: 8080}},
			Source:     model.SourceDocker,
			Origin:     "c1/api",
			Rule:       model.Rule{Node: model.AtomNode(model.NewPathPrefix("/api"))},
			RuleExpr:   `PathPrefix(/api)`,
			RouterName: "api",
		},
		"health": {
			Subdomain:   "health",
			Endpoints:   []model.Endpoint{{Address: "10.0.0.3", Port: 9090}},
			Source:      model.SourceDocker,
			Origin:      "c1/health",
			Rule:        model.Rule{Node: model.AtomNode(model.NewPath("/health"))},
			RuleExpr:    `Path(/health)`,
			RouterName:  "health",
			Priority:    10,
			PrioritySet: true,
		},
	}
	rc := buildHTTPSRouteConfiguration(routes, sortedSubdomains(routes), "example.com", testLogger())
	byDomain := vhByDomain(t, rc)

	// Both routes live on the host of their (absent) Host atom -> they fall
	// back to their subdomain host; here each has its own host, so check the
	// shared-host case separately below.
	if len(byDomain) != 2 {
		t.Fatalf("expected 2 virtual hosts, got %v", byDomain)
	}
}

func TestBuildRouteConfig_SameHostPrecedence(t *testing.T) {
	// Two routers advertising the same host with different rules: they must
	// land in one virtual host, ordered by precedence (explicit priority
	// first, then specificity, then router name).
	mk := func(sub, ruleExpr, router string, prio int, set bool) model.Route {
		r, err := rule.Parse(ruleExpr)
		if err != nil {
			panic(err)
		}
		return model.Route{
			Subdomain:   sub,
			Endpoints:   []model.Endpoint{{Address: "10.0.0.1", Port: 8080}},
			Source:      model.SourceDocker,
			Origin:      "c/" + router,
			Rule:        r,
			RuleExpr:    ruleExpr,
			RouterName:  router,
			Priority:    prio,
			PrioritySet: set,
		}
	}
	routes := map[string]model.Route{
		"broad":  mk("broad", `Host(app.example.com) && PathPrefix(/)`, "broad", 0, false),
		"narrow": mk("narrow", `Host(app.example.com) && PathPrefix(/api) && Method(GET)`, "narrow", 0, false),
		"pinned": mk("pinned", `Host(app.example.com) && Path(/)`, "pinned", 5, true),
	}
	rc := buildHTTPSRouteConfiguration(routes, sortedSubdomains(routes), "example.com", testLogger())
	byDomain := vhByDomain(t, rc)

	vh, ok := byDomain["app.example.com"]
	if !ok {
		t.Fatalf("expected virtual host app.example.com, got %v", byDomain)
	}
	if len(vh.Routes) != 3 {
		t.Fatalf("expected 3 routes in the shared virtual host, got %d", len(vh.Routes))
	}
	// First: the pinned route (explicit priority beats specificity).
	if vh.Routes[0].GetRoute().GetCluster() != "pinned" {
		t.Errorf("route[0] cluster = %q, want pinned (explicit priority first)", vh.Routes[0].GetRoute().GetCluster())
	}
	// Second: the narrow rule (longer rule string than broad).
	if vh.Routes[1].GetRoute().GetCluster() != "narrow" {
		t.Errorf("route[1] cluster = %q, want narrow (more specific)", vh.Routes[1].GetRoute().GetCluster())
	}
	// Last: the broad prefix.
	if vh.Routes[2].GetRoute().GetCluster() != "broad" {
		t.Errorf("route[2] cluster = %q, want broad (least specific last)", vh.Routes[2].GetRoute().GetCluster())
	}
}

func TestBuildRouteConfig_LegacyMovesToCatchAll(t *testing.T) {
	// With a rule-based route present, a legacy subdomain route must move
	// into the catch-all "*" virtual host.
	r, err := rule.Parse(`Host(app.example.com) && PathPrefix(/api)`)
	if err != nil {
		t.Fatal(err)
	}
	routes := map[string]model.Route{
		"api": {
			Subdomain:  "api",
			Endpoints:  []model.Endpoint{{Address: "10.0.0.1", Port: 8080}},
			Source:     model.SourceDocker,
			Origin:     "c/api",
			Rule:       r,
			RuleExpr:   `Host(app.example.com) && PathPrefix(/api)`,
			RouterName: "api",
		},
		"legacy": {
			Subdomain:  "legacy",
			Endpoints:  []model.Endpoint{{Address: "10.0.0.2", Port: 8080}},
			Source:     model.SourceDocker,
			Origin:     "c/legacy",
			RouterName: "legacy",
		},
	}
	rc := buildHTTPSRouteConfiguration(routes, sortedSubdomains(routes), "example.com", testLogger())
	byDomain := vhByDomain(t, rc)

	if _, ok := byDomain["app.example.com"]; !ok {
		t.Errorf("expected virtual host app.example.com, got %v", byDomain)
	}
	catchAll, ok := byDomain["*"]
	if !ok {
		t.Fatalf("expected catch-all virtual host, got %v", byDomain)
	}
	if len(catchAll.Routes) != 1 || catchAll.Routes[0].GetRoute().GetCluster() != "legacy" {
		t.Errorf("catch-all should carry the legacy route, got %+v", catchAll.Routes)
	}
	if catchAll.Routes[0].GetMatch().GetPrefix() != "/" {
		t.Errorf("legacy catch-all route prefix = %q, want /", catchAll.Routes[0].GetMatch().GetPrefix())
	}
}

func TestBuildRouteConfig_LegacyOnlyShapeUnchanged(t *testing.T) {
	// No rule-based routes: the legacy shape is preserved exactly (one
	// virtual host per subdomain, no catch-all).
	routes := map[string]model.Route{
		"one": {
			Subdomain: "one",
			Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}},
			Source:    model.SourceDocker,
		},
		"two": {
			Subdomain: "two",
			Endpoints: []model.Endpoint{{Address: "10.0.0.2", Port: 8080}},
			Source:    model.SourceDocker,
		},
	}
	rc := buildHTTPSRouteConfiguration(routes, sortedSubdomains(routes), "example.com", testLogger())
	byDomain := vhByDomain(t, rc)
	if len(byDomain) != 2 {
		t.Fatalf("expected 2 virtual hosts, got %v", byDomain)
	}
	if _, ok := byDomain["*"]; ok {
		t.Error("no catch-all virtual host should exist in the legacy-only shape")
	}
	for _, sub := range []string{"one", "two"} {
		vh := byDomain[sub+".example.com"]
		if vh == nil {
			t.Fatalf("missing virtual host %s.example.com", sub)
		}
		if len(vh.Routes) != 1 || vh.Routes[0].GetMatch().GetPrefix() != "/" {
			t.Errorf("virtual host %s should have one catch-all route, got %+v", sub, vh.Routes)
		}
	}
}

func TestBuildRouteConfig_DNFEmitsMultipleRoutes(t *testing.T) {
	// Host(a) && (Path(/x) || PathPrefix(/y)) expands to two DNF terms and
	// must emit two generated routes pointing at the same cluster.
	r, err := rule.Parse(`Host(app.example.com) && (Path(/x) || PathPrefix(/y))`)
	if err != nil {
		t.Fatal(err)
	}
	routes := map[string]model.Route{
		"multi": {
			Subdomain:  "multi",
			Endpoints:  []model.Endpoint{{Address: "10.0.0.1", Port: 8080}},
			Source:     model.SourceDocker,
			Origin:     "c/multi",
			Rule:       r,
			RuleExpr:   `Host(app.example.com) && (Path(/x) || PathPrefix(/y))`,
			RouterName: "multi",
		},
	}
	rc := buildHTTPSRouteConfiguration(routes, sortedSubdomains(routes), "example.com", testLogger())
	vh := vhByDomain(t, rc)["app.example.com"]
	if vh == nil {
		t.Fatalf("expected virtual host app.example.com, got %+v", rc.VirtualHosts)
	}
	if len(vh.Routes) != 2 {
		t.Fatalf("expected 2 generated routes (one per DNF term), got %d", len(vh.Routes))
	}
	for i, rt := range vh.Routes {
		if rt.GetRoute().GetCluster() != "multi" {
			t.Errorf("route[%d] cluster = %q, want multi (same action)", i, rt.GetRoute().GetCluster())
		}
	}
	// The exact-path term is more specific and must come first.
	if vh.Routes[0].GetMatch().GetPath() != "/x" {
		t.Errorf("route[0] path = %q, want /x (exact path first)", vh.Routes[0].GetMatch().GetPath())
	}
	if vh.Routes[1].GetMatch().GetPrefix() != "/y" {
		t.Errorf("route[1] prefix = %q, want /y", vh.Routes[1].GetMatch().GetPrefix())
	}
}

func TestBuildRouteConfig_UntranslatableRuleSkippedOnly(t *testing.T) {
	// A rule using ClientIP cannot be translated; only that route is
	// skipped (with a warning), the rest of the host is unaffected.
	r, err := rule.Parse(`Host(app.example.com) && ClientIP(10.0.0.0/8)`)
	if err != nil {
		t.Fatal(err)
	}
	routes := map[string]model.Route{
		"bad": {
			Subdomain:  "bad",
			Endpoints:  []model.Endpoint{{Address: "10.0.0.1", Port: 8080}},
			Source:     model.SourceDocker,
			Origin:     "c/bad",
			Rule:       r,
			RuleExpr:   `Host(app.example.com) && ClientIP(10.0.0.0/8)`,
			RouterName: "bad",
		},
		"good": {
			Subdomain:  "good",
			Endpoints:  []model.Endpoint{{Address: "10.0.0.2", Port: 8080}},
			Source:     model.SourceDocker,
			Origin:     "c/good",
			Rule:       model.Rule{Node: model.And(model.AtomNode(model.NewHost("app.example.com")), model.AtomNode(model.NewPathPrefix("/ok")))},
			RuleExpr:   `Host(app.example.com) && PathPrefix(/ok)`,
			RouterName: "good",
		},
	}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	rc := buildHTTPSRouteConfiguration(routes, sortedSubdomains(routes), "example.com", logger)
	vh := vhByDomain(t, rc)["app.example.com"]
	if vh == nil {
		t.Fatalf("expected virtual host app.example.com, got %+v", rc.VirtualHosts)
	}
	if len(vh.Routes) != 1 || vh.Routes[0].GetRoute().GetCluster() != "good" {
		t.Errorf("expected only the good route, got %+v", vh.Routes)
	}
	if !bytes.Contains(logs.Bytes(), []byte("ClientIP")) {
		t.Errorf("expected an actionable warning mentioning ClientIP, got: %s", logs.String())
	}
}

func TestGroupRoutesByEntrypoint_DefaultAndExplicit(t *testing.T) {
	cfg := Config{
		HTTPEntrypoints: map[string]uint32{"admin": 8443},
	}
	routes := map[string]model.Route{
		// No .entrypoints label -> default entrypoint (legacy pair).
		"legacy": {Subdomain: "legacy", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}}},
		// Explicit admin entrypoint.
		"admin": {Subdomain: "admin", Endpoints: []model.Endpoint{{Address: "10.0.0.2", Port: 8080}}, Entrypoints: []string{"admin"}},
		// Served on both the default and admin entrypoints.
		"both": {Subdomain: "both", Endpoints: []model.Endpoint{{Address: "10.0.0.3", Port: 8080}}, Entrypoints: []string{"default", "admin"}},
	}
	byEp, names, err := groupRoutesByEntrypoint(routes, cfg)
	if err != nil {
		t.Fatalf("groupRoutesByEntrypoint() unexpected error: %v", err)
	}
	wantNames := []string{"admin", "default"}
	if len(names) != 2 || names[0] != wantNames[0] || names[1] != wantNames[1] {
		t.Fatalf("entrypointNames = %v, want %v (sorted, always includes default)", names, wantNames)
	}
	// The default entrypoint carries the legacy route and the "both" route.
	if got := len(byEp["default"]); got != 2 {
		t.Errorf("default entrypoint carries %d routes, want 2 (legacy, both): %+v", got, byEp["default"])
	}
	if _, ok := byEp["default"]["legacy"]; !ok {
		t.Errorf("default entrypoint should carry the legacy route, got %+v", byEp["default"])
	}
	// The admin entrypoint carries the admin route and the "both" route.
	if got := len(byEp["admin"]); got != 2 {
		t.Errorf("admin entrypoint carries %d routes, want 2 (admin, both): %+v", got, byEp["admin"])
	}
	if _, ok := byEp["admin"]["admin"]; !ok {
		t.Errorf("admin entrypoint should carry the admin route, got %+v", byEp["admin"])
	}
}

func TestGroupRoutesByEntrypoint_UnknownEntryptRejected(t *testing.T) {
	cfg := Config{HTTPEntrypoints: map[string]uint32{"admin": 8443}}
	routes := map[string]model.Route{
		"bad": {Subdomain: "bad", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}}, Entrypoints: []string{"ghost"}},
	}
	_, _, err := groupRoutesByEntrypoint(routes, cfg)
	if err == nil {
		t.Fatal("groupRoutesByEntrypoint() expected an error for an unknown entrypoint, got nil")
	}
	if !strings.Contains(err.Error(), "ghost") {
		t.Errorf("error = %q, want it to name the unknown entrypoint %q", err.Error(), "ghost")
	}
}

func TestGroupRoutesByEntrypoint_ConfiguredDefault(t *testing.T) {
	// With a configured default entrypoint, a router with no .entrypoints
	// label is served on that entrypoint (not the implicit default pair).
	cfg := Config{
		HTTPEntrypoints:       map[string]uint32{"admin": 8443},
		DefaultHTTPEntrypoint: "admin",
	}
	routes := map[string]model.Route{
		"legacy": {Subdomain: "legacy", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}}},
	}
	byEp, names, err := groupRoutesByEntrypoint(routes, cfg)
	if err != nil {
		t.Fatalf("groupRoutesByEntrypoint() unexpected error: %v", err)
	}
	if len(names) != 1 || names[0] != "admin" {
		t.Fatalf("entrypointNames = %v, want [admin] (configured default)", names)
	}
	if _, ok := byEp["admin"]["legacy"]; !ok {
		t.Errorf("legacy route should be on the configured default entrypoint, got %+v", byEp)
	}
}

func TestBuildSnapshot_EntrypointListenersAndRouteConfigs(t *testing.T) {
	routes := map[string]model.Route{
		"legacy": {Subdomain: "legacy", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}}, Source: model.SourceDocker},
		"admin":  {Subdomain: "admin", Endpoints: []model.Endpoint{{Address: "10.0.0.2", Port: 8080}}, Source: model.SourceDocker, Entrypoints: []string{"admin"}},
	}
	cfg := Config{
		BaseDomain:         "example.com",
		HTTPPort:           80,
		HTTPSPort:          443,
		CertSecretName:     "wildcard-cert",
		ACMESDSClusterName: "acme_sds_cluster",
		HTTPEntrypoints:    map[string]uint32{"admin": 8443},
	}
	snap, err := BuildSnapshot("1", routes, cfg)
	if err != nil {
		t.Fatalf("BuildSnapshot() unexpected error: %v", err)
	}

	// Two RDS route configs: the legacy https_routes (default) and the
	// namespaced https_routes__admin.
	rcs := snap.GetResources(resourcev3.RouteType)
	if _, ok := rcs[httpsRouteConfigName]; !ok {
		t.Errorf("expected route config %q, got %v", httpsRouteConfigName, rcs)
	}
	if _, ok := rcs[httpsRouteConfigName+"__admin"]; !ok {
		t.Errorf("expected route config %q, got %v", httpsRouteConfigName+"__admin", rcs)
	}
	// The default route config carries only the legacy route's host.
	defRC := rcs[httpsRouteConfigName].(*routev3.RouteConfiguration)
	if len(defRC.VirtualHosts) != 1 || defRC.VirtualHosts[0].Domains[0] != "legacy.example.com" {
		t.Errorf("default route config virtual hosts = %+v, want one for legacy.example.com", defRC.VirtualHosts)
	}
	adminRC := rcs[httpsRouteConfigName+"__admin"].(*routev3.RouteConfiguration)
	if len(adminRC.VirtualHosts) != 1 || adminRC.VirtualHosts[0].Domains[0] != "admin.example.com" {
		t.Errorf("admin route config virtual hosts = %+v, want one for admin.example.com", adminRC.VirtualHosts)
	}

	// Three listeners: the legacy http_listener + https_listener, plus a
	// dedicated TLS listener for the admin entrypoint on its configured port.
	listeners := snap.GetResources(resourcev3.ListenerType)
	if _, ok := listeners[httpsListenerName]; !ok {
		t.Errorf("expected listener %q, got %v", httpsListenerName, listeners)
	}
	adminListener, ok := listeners[httpsListenerName+"__admin"]
	if !ok {
		t.Fatalf("expected admin entrypoint listener %q, got %v", httpsListenerName+"__admin", listeners)
	}
	al := adminListener.(*listenerv3.Listener)
	if al.Address.GetSocketAddress().GetPortValue() != 8443 {
		t.Errorf("admin listener port = %d, want 8443", al.Address.GetSocketAddress().GetPortValue())
	}
	adminHCM := decodeHCM(t, al)
	if adminHCM.GetRds().GetRouteConfigName() != httpsRouteConfigName+"__admin" {
		t.Errorf("admin listener RDS route config name = %q, want %q", adminHCM.GetRds().GetRouteConfigName(), httpsRouteConfigName+"__admin")
	}
	// The admin listener is TLS.
	if al.FilterChains[0].TransportSocket == nil {
		t.Error("admin entrypoint listener should have a TLS transport socket")
	}

	// Both routes are published (each gets a cluster + endpoint) even though
	// they live on different entrypoints.
	clusters := snap.GetResources(resourcev3.ClusterType)
	if _, ok := clusters["legacy"]; !ok {
		t.Errorf("expected cluster %q, got %v", "legacy", clusters)
	}
	if _, ok := clusters["admin"]; !ok {
		t.Errorf("expected cluster %q, got %v", "admin", clusters)
	}
}

func TestApplyRouteObservability_TracingAndAccessLog(t *testing.T) {
	mk := func(sub string, tr *model.TracingConfig, access *bool) model.Route {
		return model.Route{Subdomain: sub, Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}}, RouterName: sub, Tracing: tr, AccessLog: access}
	}

	// Tracing enabled with an operation name -> per-route Tracing with a
	// span name and 100% sampling.
	r := mk("traced", &model.TracingConfig{Enabled: true, OperationName: "my-span"}, nil)
	er := &routev3.Route{}
	applyRouteObservability(er, r)
	if er.Tracing == nil {
		t.Fatal("expected a per-route Tracing message, got nil")
	}
	if er.Tracing.Operation != "my-span" {
		t.Errorf("Tracing.Operation = %q, want my-span", er.Tracing.Operation)
	}
	if er.Tracing.OverallSampling == nil || er.Tracing.OverallSampling.GetNumerator() != 100 {
		t.Errorf("Tracing.OverallSampling = %+v, want 100/100 (enabled)", er.Tracing.OverallSampling)
	}

	// Tracing explicitly disabled -> 0% sampling, no span name.
	r = mk("off", &model.TracingConfig{Enabled: false}, nil)
	er = &routev3.Route{}
	applyRouteObservability(er, r)
	if er.Tracing == nil {
		t.Fatal("expected a per-route Tracing message (explicit false), got nil")
	}
	if er.Tracing.OverallSampling == nil || er.Tracing.OverallSampling.GetNumerator() != 0 {
		t.Errorf("Tracing.OverallSampling = %+v, want 0/100 (disabled)", er.Tracing.OverallSampling)
	}
	if er.Tracing.Operation != "" {
		t.Errorf("Tracing.Operation = %q, want empty (no operationname)", er.Tracing.Operation)
	}

	// Access log enabled -> route metadata in the observability namespace.
	on := true
	r = mk("logged", nil, &on)
	er = &routev3.Route{}
	applyRouteObservability(er, r)
	md := er.Metadata
	if md == nil || md.FilterMetadata[observabilityMetadataNamespace] == nil {
		t.Fatalf("expected route metadata in namespace %q, got %+v", observabilityMetadataNamespace, er.Metadata)
	}
	fields := md.FilterMetadata[observabilityMetadataNamespace].GetFields()
	if got := fields["accesslog"].GetBoolValue(); got != true {
		t.Errorf("metadata accesslog = %v, want true", got)
	}
	if got := fields["subdomain"].GetStringValue(); got != "logged" {
		t.Errorf("metadata subdomain = %q, want logged", got)
	}
	if fields["router"] == nil {
		t.Error("metadata should carry the router name")
	}

	// No hooks -> no Tracing message and no metadata.
	er = &routev3.Route{}
	applyRouteObservability(er, mk("plain", nil, nil))
	if er.Tracing != nil {
		t.Errorf("unexpected Tracing message for a route with no hooks: %+v", er.Tracing)
	}
	if er.Metadata != nil {
		t.Errorf("unexpected metadata for a route with no hooks: %+v", er.Metadata)
	}
}

func TestBuildSnapshot_ObservabilityOnEmittedRoutes(t *testing.T) {
	on := true
	routes := map[string]model.Route{
		"traced": {
			Subdomain:  "traced",
			Endpoints:  []model.Endpoint{{Address: "10.0.0.1", Port: 8080}},
			Source:     model.SourceDocker,
			RouterName: "traced",
			Tracing:    &model.TracingConfig{Enabled: true, OperationName: "traced-span"},
			AccessLog:  &on,
		},
	}
	cfg := Config{
		BaseDomain:         "example.com",
		HTTPPort:           80,
		HTTPSPort:          443,
		CertSecretName:     "cert",
		ACMESDSClusterName: "acme",
	}
	snap, err := BuildSnapshot("1", routes, cfg)
	if err != nil {
		t.Fatalf("BuildSnapshot() unexpected error: %v", err)
	}
	rc := snap.GetResources(resourcev3.RouteType)[httpsRouteConfigName].(*routev3.RouteConfiguration)
	if len(rc.VirtualHosts) != 1 || len(rc.VirtualHosts[0].Routes) != 1 {
		t.Fatalf("expected one virtual host with one route, got %+v", rc.VirtualHosts)
	}
	er := rc.VirtualHosts[0].Routes[0]
	if er.Tracing == nil || er.Tracing.Operation != "traced-span" {
		t.Errorf("emitted route Tracing = %+v, want operation traced-span", er.Tracing)
	}
	if er.Metadata == nil || er.Metadata.FilterMetadata[observabilityMetadataNamespace] == nil {
		t.Errorf("emitted route should carry observability metadata, got %+v", er.Metadata)
	}
}
