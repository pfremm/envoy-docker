package dockerwatch

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/protobuf/proto"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
	"github.com/bryanpfremm/envoy-control-plane/internal/xds"
)

// sharedSubdomainContainer builds a container advertising exactly one router
// on the "app" subdomain, so several containers can contend for it.
func sharedSubdomainContainer(id, router, rule, priority, ip string) container.Summary {
	labels := map[string]string{
		"envoy.enable": "true",
		"envoy.http.routers." + router + ".subdomain": "app",
		"envoy.http.routers." + router + ".port":      "8080",
	}
	if rule != "" {
		labels["envoy.http.routers."+router+".rule"] = rule
	}
	if priority != "" {
		labels["envoy.http.routers."+router+".priority"] = priority
	}
	return container.Summary{
		ID: id, Names: []string{"/" + id}, Labels: labels,
		NetworkSettings: &container.NetworkSettingsSummary{
			Networks: map[string]*network.EndpointSettings{"proxy": {IPAddress: ip}},
		},
	}
}

// sharedSubdomainConfig is the xDS config used by the shared-subdomain tests.
func sharedSubdomainConfig() xds.Config {
	return xds.Config{
		BaseDomain:         "example.com",
		HTTPPort:           80,
		HTTPSPort:          443,
		CertSecretName:     "wildcard-cert",
		ACMESDSClusterName: "acme_sds_cluster",
	}
}

// routersOf returns the RouterName of every discovered route, so a test can
// assert on the SET of surviving routers rather than only on the winner.
func routersOf(cfg model.HTTPConfiguration) map[string]model.Route {
	out := make(map[string]model.Route, len(cfg.Routes))
	for _, route := range cfg.Routes {
		out[route.RouterName] = route
	}
	return out
}

// TestDiscoverSharedSubdomainPreservesDistinctRouters is the regression test
// for the release blocker: discovery keyed routes solely by subdomain, so two
// DISTINCT routers sharing one subdomain collapsed into a single route and the
// lower-precedence router was discarded before it could ever reach the xDS
// precedence/fallback evaluation. Asserting only "the right router won"
// (TestDiscoverConflictingRoutersUsesPriority) cannot catch that, because a
// dropped route also leaves the winner in place. This asserts PRESERVATION.
func TestDiscoverSharedSubdomainPreservesDistinctRouters(t *testing.T) {
	cfg := discover([]container.Summary{
		// Container ids are sorted, so the broad, lower-precedence router
		// is processed FIRST: the bug dropped whichever distinct router
		// arrived second, so ordering matters for the regression.
		sharedSubdomainContainer("c1", "broad", "Host(app.example.com)", "", "10.0.0.1"),
		sharedSubdomainContainer("c2", "narrow", "Host(app.example.com) && PathPrefix(/admin)", "10", "10.0.0.2"),
	}, "proxy", slog.New(slog.DiscardHandler))

	if len(cfg.Routes) != 2 {
		t.Fatalf("both distinct routers must survive discovery, got %d route(s): %+v", len(cfg.Routes), cfg.Routes)
	}
	byRouter := routersOf(cfg)
	broad, okBroad := byRouter["broad"]
	narrow, okNarrow := byRouter["narrow"]
	if !okBroad || !okNarrow {
		t.Fatalf("expected routers broad and narrow to both survive, got %+v", byRouter)
	}

	// Each preserved router keeps its OWN backend; a collapse would have
	// merged or dropped one set of endpoints.
	if len(broad.Endpoints) != 1 || broad.Endpoints[0].Address != "10.0.0.1" {
		t.Errorf("broad router endpoints = %+v, want the c1 backend 10.0.0.1", broad.Endpoints)
	}
	if len(narrow.Endpoints) != 1 || narrow.Endpoints[0].Address != "10.0.0.2" {
		t.Errorf("narrow router endpoints = %+v, want the c2 backend 10.0.0.2", narrow.Endpoints)
	}

	// Distinct routers must get distinct cluster names, otherwise both
	// routes would point at one cluster and the preserved route would be
	// served the wrong backend.
	if broad.ClusterName() == narrow.ClusterName() {
		t.Errorf("preserved routers share cluster name %q; each needs its own cluster", broad.ClusterName())
	}
	// The highest-precedence router keeps the legacy subdomain-named
	// cluster, so existing single-router deployments are unchanged.
	if narrow.ClusterName() != "app" {
		t.Errorf("highest-precedence router cluster = %q, want the legacy subdomain name %q", narrow.ClusterName(), "app")
	}
	// Both still describe the same subdomain.
	if broad.Subdomain != "app" || narrow.Subdomain != "app" {
		t.Errorf("preserved routes must keep subdomain app, got broad=%q narrow=%q", broad.Subdomain, narrow.Subdomain)
	}
}

// TestSharedSubdomainRDSOrdersBothRoutesSemantically proves the preserved
// routers reach RDS and are ordered there by the documented precedence, in ONE
// virtual host (two virtual hosts with the same domain is a duplicate-domain
// error Envoy rejects), each pointing at its own cluster with its own
// endpoints. This is the semantic assertion the contract requires: it inspects
// generated LDS/RDS/CDS/EDS meaning, not snapshot text.
func TestSharedSubdomainRDSOrdersBothRoutesSemantically(t *testing.T) {
	cfg := discover([]container.Summary{
		sharedSubdomainContainer("c1", "broad", "Host(app.example.com)", "", "10.0.0.1"),
		sharedSubdomainContainer("c2", "narrow", "Host(app.example.com) && PathPrefix(/admin)", "10", "10.0.0.2"),
	}, "proxy", slog.New(slog.DiscardHandler))

	snap, err := xds.BuildSnapshotForConfig("1", cfg, sharedSubdomainConfig())
	if err != nil {
		t.Fatalf("BuildSnapshotForConfig() unexpected error: %v", err)
	}

	rc, ok := snap.GetResources(resourcev3.RouteType)["https_routes"].(*routev3.RouteConfiguration)
	if !ok {
		t.Fatalf("expected https_routes route configuration, got %v", snap.GetResources(resourcev3.RouteType))
	}

	// Exactly one virtual host may claim app.example.com.
	var host *routev3.VirtualHost
	claims := 0
	for _, vh := range rc.VirtualHosts {
		for _, d := range vh.Domains {
			if d == "app.example.com" {
				claims++
				host = vh
			}
		}
	}
	if claims != 1 {
		t.Fatalf("app.example.com claimed by %d virtual hosts, want exactly 1 (Envoy rejects duplicate domains)", claims)
	}

	// Both routers must be present, narrow (explicit priority 10) first:
	// Envoy evaluates top-to-bottom and first match wins, so a broad
	// PathPrefix(/) route ahead of the narrow one would shadow it.
	if len(host.Routes) != 2 {
		t.Fatalf("virtual host carries %d route(s), want both preserved routers: %+v", len(host.Routes), host.Routes)
	}
	if host.Routes[0].Name != "narrow" || host.Routes[1].Name != "broad" {
		t.Fatalf("route order = [%q %q], want [narrow broad] (explicit priority sorts first)",
			host.Routes[0].Name, host.Routes[1].Name)
	}
	if got := host.Routes[0].GetMatch().GetPrefix(); got != "/admin" {
		t.Errorf("narrow route prefix = %q, want /admin", got)
	}

	// Each route resolves to its own cluster...
	narrowCluster := host.Routes[0].GetRoute().GetCluster()
	broadCluster := host.Routes[1].GetRoute().GetCluster()
	if narrowCluster == broadCluster {
		t.Fatalf("both routes point at cluster %q; preserved routers need distinct clusters", narrowCluster)
	}

	// ...and each cluster exists in CDS with an EDS assignment carrying
	// that router's own backend address.
	clusters := snap.GetResources(resourcev3.ClusterType)
	for _, name := range []string{narrowCluster, broadCluster} {
		c, ok := clusters[name].(*clusterv3.Cluster)
		if !ok {
			t.Fatalf("cluster %q missing from CDS: %v", name, clusters)
		}
		if c.Name != name {
			t.Errorf("cluster resource name = %q, want %q", c.Name, name)
		}
	}
	wantAddress := map[string]string{narrowCluster: "10.0.0.2", broadCluster: "10.0.0.1"}
	endpoints := snap.GetResources(resourcev3.EndpointType)
	for cluster, want := range wantAddress {
		cla, ok := endpoints[cluster].(*endpointv3.ClusterLoadAssignment)
		if !ok {
			t.Fatalf("cluster %q has no EDS assignment: %v", cluster, endpoints)
		}
		var got []string
		for _, locality := range cla.Endpoints {
			for _, lb := range locality.LbEndpoints {
				got = append(got, lb.GetEndpoint().GetAddress().GetSocketAddress().GetAddress())
			}
		}
		if len(got) != 1 || got[0] != want {
			t.Errorf("cluster %q endpoints = %v, want exactly [%s] (its own router's backend)", cluster, got, want)
		}
	}
}

// TestSharedSubdomainLegacyRoutersShareOneVirtualHost covers the legacy
// (no-rule) form of the same defect. Legacy routes get their own exact-domain
// virtual host; when two of them share a subdomain they must join ONE virtual
// host ordered by precedence rather than emitting two virtual hosts with the
// same domain, which Envoy rejects at the RDS layer.
func TestSharedSubdomainLegacyRoutersShareOneVirtualHost(t *testing.T) {
	cfg := discover([]container.Summary{
		sharedSubdomainContainer("c1", "alpha", "", "", "10.0.0.1"),
		sharedSubdomainContainer("c2", "beta", "", "", "10.0.0.2"),
	}, "proxy", slog.New(slog.DiscardHandler))

	if len(cfg.Routes) != 2 {
		t.Fatalf("both legacy routers must survive discovery, got %d: %+v", len(cfg.Routes), cfg.Routes)
	}

	snap, err := xds.BuildSnapshotForConfig("1", cfg, sharedSubdomainConfig())
	if err != nil {
		t.Fatalf("BuildSnapshotForConfig() unexpected error: %v", err)
	}
	rc := snap.GetResources(resourcev3.RouteType)["https_routes"].(*routev3.RouteConfiguration)

	seen := map[string]int{}
	for _, vh := range rc.VirtualHosts {
		for _, d := range vh.Domains {
			seen[d]++
		}
	}
	if seen["app.example.com"] != 1 {
		t.Fatalf("app.example.com claimed by %d virtual hosts, want 1: %+v", seen["app.example.com"], rc.VirtualHosts)
	}

	var names []string
	for _, vh := range rc.VirtualHosts {
		if vh.Domains[0] != "app.example.com" {
			continue
		}
		for _, r := range vh.Routes {
			names = append(names, r.Name)
		}
	}
	if len(names) != 2 {
		t.Fatalf("legacy virtual host carries routes %v, want both alpha and beta", names)
	}
	// Router name is the stable tie-breaker when neither sets a priority
	// and neither has a rule.
	if names[0] != "alpha" || names[1] != "beta" {
		t.Errorf("legacy route order = %v, want [alpha beta] (router-name tie-break)", names)
	}
}

// TestSharedSubdomainSnapshotIsDeterministic proves the preservation path does
// not reintroduce map-iteration nondeterminism: discovery now materialises
// routes from a map of slices, so a missing sort would produce snapshots that
// differ between rebuilds and churn xDS for no reason.
func TestSharedSubdomainSnapshotIsDeterministic(t *testing.T) {
	containers := []container.Summary{
		sharedSubdomainContainer("c1", "broad", "Host(app.example.com)", "", "10.0.0.1"),
		sharedSubdomainContainer("c2", "narrow", "Host(app.example.com) && PathPrefix(/admin)", "10", "10.0.0.2"),
		sharedSubdomainContainer("c3", "mid", "Host(app.example.com) && PathPrefix(/api)", "", "10.0.0.3"),
	}

	var first string
	for i := 0; i < 25; i++ {
		cfg := discover(containers, "proxy", slog.New(slog.DiscardHandler))
		if len(cfg.Routes) != 3 {
			t.Fatalf("iteration %d: %d routes survived, want 3: %+v", i, len(cfg.Routes), cfg.Routes)
		}
		snap, err := xds.BuildSnapshotForConfig("1", cfg, sharedSubdomainConfig())
		if err != nil {
			t.Fatalf("iteration %d: BuildSnapshotForConfig() error: %v", i, err)
		}
		got := serializeRouteResources(t, snap)
		if i == 0 {
			first = got
			continue
		}
		if got != first {
			t.Fatalf("iteration %d produced a different snapshot than iteration 0:\nfirst=%s\ngot  =%s", i, first, got)
		}
	}
}

// serializeRouteResources renders the RDS resources deterministically so two
// snapshots can be compared byte-for-byte.
func serializeRouteResources(t *testing.T, snap cachev3.ResourceSnapshot) string {
	t.Helper()
	var b strings.Builder
	for _, name := range []string{"https_routes"} {
		rc, ok := snap.GetResources(resourcev3.RouteType)[name].(*routev3.RouteConfiguration)
		if !ok {
			t.Fatalf("route configuration %q missing", name)
		}
		out, err := proto.MarshalOptions{Deterministic: true}.Marshal(rc)
		if err != nil {
			t.Fatalf("marshaling %q: %v", name, err)
		}
		b.WriteString(name)
		b.Write(out)
	}
	return b.String()
}
