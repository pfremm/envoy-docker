package xds

import (
	"strings"
	"testing"

	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	tcpproxyv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
)

func hostSNI(v string) model.Rule { return model.Rule{Node: model.AtomNode(model.NewSNI(v))} }

func baseTCPCfg() Config {
	return Config{
		BaseDomain:           "example.com",
		HTTPPort:             80,
		HTTPSPort:            443,
		TCPEntrypoints:       map[string]uint32{"websecure": 8443, "raw": 8444},
		DefaultTCPEntrypoint: "websecure",
	}
}

func TestBuildTCP_RawServiceListenerNoHTTPFilter(t *testing.T) {
	tcpCfg := model.TCPConfiguration{
		Routers: map[string]model.TCPRouter{
			"raw": {Name: "raw", Rule: hostSNI("*"), RuleExpr: "HostSNI(*)", ServiceName: "db", Entrypoints: []string{"raw"}},
		},
		Services: map[string]model.TCPService{
			"db": {Name: "db", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 5432}}},
		},
	}
	snap, err := BuildSnapshotForConfigWithTCP("1", model.HTTPConfiguration{}, tcpCfg, baseTCPCfg())
	if err != nil {
		t.Fatal(err)
	}
	listeners := snap.GetResources(resourcev3.ListenerType)
	l, ok := listeners[tcpListenerNamePrefix+"raw"].(*listenerv3.Listener)
	if !ok {
		t.Fatalf("expected tcp listener for entrypoint raw, got %v", listeners)
	}
	if l.Address.GetSocketAddress().GetPortValue() != 8444 {
		t.Fatalf("listener port = %d, want 8444", l.Address.GetSocketAddress().GetPortValue())
	}
	if len(l.ListenerFilters) != 0 {
		t.Fatalf("raw-only listener should have no TLS inspector, got %+v", l.ListenerFilters)
	}
	if len(l.FilterChains) != 1 {
		t.Fatalf("expected 1 filter chain, got %d", len(l.FilterChains))
	}
	chain := l.FilterChains[0]
	if chain.FilterChainMatch.GetTransportProtocol() != "raw_buffer" {
		t.Fatalf("raw chain must match transport_protocol=raw_buffer, got %q", chain.FilterChainMatch.GetTransportProtocol())
	}
	if len(chain.Filters) != 1 || chain.Filters[0].Name != wellknown.TCPProxy {
		t.Fatalf("expected single tcp_proxy filter, got %+v", chain.Filters)
	}
	// Never an HTTP connection manager on a raw/passthrough chain.
	for _, f := range chain.Filters {
		if f.Name == wellknown.HTTPConnectionManager {
			t.Fatal("HTTP connection manager must never be attached to a raw TCP chain")
		}
	}
	proxy := &tcpproxyv3.TcpProxy{}
	unmarshalAny(t, chain.Filters[0].GetTypedConfig(), proxy)
	if proxy.GetCluster() != model.NamedTCPServiceClusterName("db") {
		t.Fatalf("tcp_proxy cluster = %q", proxy.GetCluster())
	}

	clusters := snap.GetResources(resourcev3.ClusterType)
	cname := model.NamedTCPServiceClusterName("db")
	if _, ok := clusters[cname]; !ok {
		t.Fatalf("expected tcp service cluster %q, got %v", cname, clusters)
	}
	endpoints := snap.GetResources(resourcev3.EndpointType)
	cla := endpoints[cname].(*endpointv3.ClusterLoadAssignment)
	if len(cla.Endpoints[0].LbEndpoints) != 1 {
		t.Fatalf("endpoints=%+v", cla.Endpoints)
	}
}

func TestBuildTCP_PassthroughListenerHasTLSInspectorAndSNIMatch(t *testing.T) {
	tcpCfg := model.TCPConfiguration{
		Routers: map[string]model.TCPRouter{
			"secure": {Name: "secure", Rule: hostSNI("app.example.com"), RuleExpr: "HostSNI(app.example.com)", ServiceName: "app", TLSPassthrough: true, Entrypoints: []string{"websecure"}},
		},
		Services: map[string]model.TCPService{
			"app": {Name: "app", Endpoints: []model.Endpoint{{Address: "10.0.0.2", Port: 443}}},
		},
	}
	snap, err := BuildSnapshotForConfigWithTCP("1", model.HTTPConfiguration{}, tcpCfg, baseTCPCfg())
	if err != nil {
		t.Fatal(err)
	}
	l := snap.GetResources(resourcev3.ListenerType)[tcpListenerNamePrefix+"websecure"].(*listenerv3.Listener)
	if len(l.ListenerFilters) != 1 || l.ListenerFilters[0].Name != wellknown.TLSInspector {
		t.Fatalf("expected TLS inspector listener filter, got %+v", l.ListenerFilters)
	}
	chain := l.FilterChains[0]
	if chain.FilterChainMatch.GetTransportProtocol() != "tls" {
		t.Fatalf("passthrough chain must match transport_protocol=tls, got %q", chain.FilterChainMatch.GetTransportProtocol())
	}
	if got := chain.FilterChainMatch.GetServerNames(); len(got) != 1 || got[0] != "app.example.com" {
		t.Fatalf("server_names = %v, want [app.example.com]", got)
	}
	// Passthrough forwards encrypted bytes untouched: no downstream
	// TransportSocket (no TLS termination) on the chain.
	if chain.TransportSocket != nil {
		t.Fatalf("passthrough chain must not terminate TLS, got transport socket %+v", chain.TransportSocket)
	}
}

func TestBuildTCP_CatchAllHasNoServerNamesConstraint(t *testing.T) {
	tcpCfg := model.TCPConfiguration{
		Routers: map[string]model.TCPRouter{
			"catchall": {Name: "catchall", Rule: hostSNI("*"), RuleExpr: "HostSNI(*)", ServiceName: "app", TLSPassthrough: true, Entrypoints: []string{"websecure"}},
		},
		Services: map[string]model.TCPService{
			"app": {Name: "app", Endpoints: []model.Endpoint{{Address: "10.0.0.2", Port: 443}}},
		},
	}
	snap, err := BuildSnapshotForConfigWithTCP("1", model.HTTPConfiguration{}, tcpCfg, baseTCPCfg())
	if err != nil {
		t.Fatal(err)
	}
	l := snap.GetResources(resourcev3.ListenerType)[tcpListenerNamePrefix+"websecure"].(*listenerv3.Listener)
	chain := l.FilterChains[0]
	if len(chain.FilterChainMatch.GetServerNames()) != 0 {
		t.Fatalf("catch-all chain must have no server_names constraint, got %v", chain.FilterChainMatch.GetServerNames())
	}
}

func TestBuildTCP_MultipleEntrypointsProduceMultipleListeners(t *testing.T) {
	tcpCfg := model.TCPConfiguration{
		Routers: map[string]model.TCPRouter{
			"r": {Name: "r", Rule: hostSNI("*"), RuleExpr: "HostSNI(*)", ServiceName: "svc", Entrypoints: []string{"raw", "websecure"}, TLSPassthrough: false},
		},
		Services: map[string]model.TCPService{
			"svc": {Name: "svc", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 1}}},
		},
	}
	// A raw router on "websecure" is fine only if it's still catch-all;
	// here it just needs two listeners to exist.
	snap, err := BuildSnapshotForConfigWithTCP("1", model.HTTPConfiguration{}, tcpCfg, baseTCPCfg())
	if err != nil {
		t.Fatal(err)
	}
	listeners := snap.GetResources(resourcev3.ListenerType)
	if _, ok := listeners[tcpListenerNamePrefix+"raw"]; !ok {
		t.Fatalf("missing raw entrypoint listener: %v", listeners)
	}
	if _, ok := listeners[tcpListenerNamePrefix+"websecure"]; !ok {
		t.Fatalf("missing websecure entrypoint listener: %v", listeners)
	}
}

func TestBuildTCP_UnknownEntrypointSkipsRouter(t *testing.T) {
	// A label-derived unknown entrypoint must not wedge the snapshot: the
	// router is skipped with a warning and no TCP listener is emitted.
	tcpCfg := model.TCPConfiguration{
		Routers: map[string]model.TCPRouter{
			"r": {Name: "r", Rule: hostSNI("*"), RuleExpr: "HostSNI(*)", ServiceName: "svc", Entrypoints: []string{"doesnotexist"}},
		},
		Services: map[string]model.TCPService{
			"svc": {Name: "svc", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 1}}},
		},
	}
	snap, err := BuildSnapshotForConfigWithTCP("1", model.HTTPConfiguration{}, tcpCfg, baseTCPCfg())
	if err != nil {
		t.Fatalf("unknown entrypoint must not fail the snapshot: %v", err)
	}
	for name := range snap.GetResources(resourcev3.ListenerType) {
		if strings.HasPrefix(name, tcpListenerNamePrefix) {
			t.Fatalf("no TCP listener should be emitted for a skipped router, got %q", name)
		}
	}
}

func TestBuildTCP_NoEntrypointsNoDefaultSkipsRouter(t *testing.T) {
	// No .entrypoints and no configured default: the router is skipped
	// with a warning instead of wedging the snapshot.
	tcpCfg := model.TCPConfiguration{
		Routers: map[string]model.TCPRouter{
			"r": {Name: "r", Rule: hostSNI("*"), RuleExpr: "HostSNI(*)", ServiceName: "svc"},
		},
		Services: map[string]model.TCPService{
			"svc": {Name: "svc", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 1}}},
		},
	}
	cfg := baseTCPCfg()
	cfg.DefaultTCPEntrypoint = ""
	snap, err := BuildSnapshotForConfigWithTCP("1", model.HTTPConfiguration{}, tcpCfg, cfg)
	if err != nil {
		t.Fatalf("missing default entrypoint must not fail the snapshot: %v", err)
	}
	for name := range snap.GetResources(resourcev3.ListenerType) {
		if strings.HasPrefix(name, tcpListenerNamePrefix) {
			t.Fatalf("no TCP listener should be emitted for a skipped router, got %q", name)
		}
	}
}

func TestBuildTCP_SamePriorityConflictKeepsDeterministicWinner(t *testing.T) {
	// Two same-tier routers with identical SNI would emit duplicate
	// FilterChainMatch entries (Envoy LDS NACK). The build keeps the
	// highest-precedence router (name-sorted tie-break: "a") and skips the
	// other with a warning, so one conflicting label never wedges the
	// snapshot.
	tcpCfg := model.TCPConfiguration{
		Routers: map[string]model.TCPRouter{
			"a": {Name: "a", Rule: hostSNI("dup.com"), RuleExpr: "HostSNI(dup.com)", ServiceName: "svc", TLSPassthrough: true, Entrypoints: []string{"websecure"}},
			"b": {Name: "b", Rule: hostSNI("dup.com"), RuleExpr: "HostSNI(dup.com)", ServiceName: "svc", TLSPassthrough: true, Entrypoints: []string{"websecure"}},
		},
		Services: map[string]model.TCPService{
			"svc": {Name: "svc", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 1}}},
		},
	}
	snap, err := BuildSnapshotForConfigWithTCP("1", model.HTTPConfiguration{}, tcpCfg, baseTCPCfg())
	if err != nil {
		t.Fatalf("overlapping SNI must not fail the snapshot: %v", err)
	}
	l := snap.GetResources(resourcev3.ListenerType)[tcpListenerNamePrefix+"websecure"].(*listenerv3.Listener)
	if len(l.FilterChains) != 1 {
		t.Fatalf("expected exactly 1 surviving filter chain (no duplicate FilterChainMatch), got %d", len(l.FilterChains))
	}
	if l.FilterChains[0].Name != "tcp_router__a" {
		t.Fatalf("expected deterministic winner 'a', got %+v", l.FilterChains)
	}
}

func TestBuildTCP_ExplicitPriorityDoesNotBypassOverlapDedup(t *testing.T) {
	// Distinct priorities cannot make identical SNI matches coexist:
	// FilterChainMatch has no priority concept and Envoy NACKs duplicate
	// matches. The higher-priority router's chain survives; the other is
	// skipped.
	tcpCfg := model.TCPConfiguration{
		Routers: map[string]model.TCPRouter{
			"a": {Name: "a", Rule: hostSNI("dup.com"), RuleExpr: "HostSNI(dup.com)", ServiceName: "svc", TLSPassthrough: true, Entrypoints: []string{"websecure"}, Priority: 10, PrioritySet: true},
			"b": {Name: "b", Rule: hostSNI("dup.com"), RuleExpr: "HostSNI(dup.com)", ServiceName: "svc", TLSPassthrough: true, Entrypoints: []string{"websecure"}, Priority: 5, PrioritySet: true},
		},
		Services: map[string]model.TCPService{
			"svc": {Name: "svc", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 1}}},
		},
	}
	snap, err := BuildSnapshotForConfigWithTCP("1", model.HTTPConfiguration{}, tcpCfg, baseTCPCfg())
	if err != nil {
		t.Fatalf("overlapping SNI with distinct priorities must not fail the snapshot: %v", err)
	}
	l := snap.GetResources(resourcev3.ListenerType)[tcpListenerNamePrefix+"websecure"].(*listenerv3.Listener)
	if len(l.FilterChains) != 1 {
		t.Fatalf("expected 1 surviving filter chain (duplicate FilterChainMatch deduped), got %d", len(l.FilterChains))
	}
	// Higher priority ("a") must be the survivor.
	if l.FilterChains[0].Name != "tcp_router__a" {
		t.Fatalf("expected higher-priority router 'a' to survive, got %+v", l.FilterChains)
	}
}

func TestBuildTCP_WeightedServiceProducesWeightedClusters(t *testing.T) {
	tcpCfg := model.TCPConfiguration{
		Routers: map[string]model.TCPRouter{
			"r": {Name: "r", Rule: hostSNI("*"), RuleExpr: "HostSNI(*)", ServiceName: "rollout", Entrypoints: []string{"raw"}},
		},
		Services: map[string]model.TCPService{
			"blue":    {Name: "blue", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 1}}},
			"green":   {Name: "green", Endpoints: []model.Endpoint{{Address: "10.0.0.2", Port: 1}}},
			"rollout": {Name: "rollout", Weighted: []model.WeightedService{{Name: "blue", Weight: 9}, {Name: "green", Weight: 1}}},
		},
	}
	snap, err := BuildSnapshotForConfigWithTCP("1", model.HTTPConfiguration{}, tcpCfg, baseTCPCfg())
	if err != nil {
		t.Fatal(err)
	}
	l := snap.GetResources(resourcev3.ListenerType)[tcpListenerNamePrefix+"raw"].(*listenerv3.Listener)
	proxy := &tcpproxyv3.TcpProxy{}
	unmarshalAny(t, l.FilterChains[0].Filters[0].GetTypedConfig(), proxy)
	wc := proxy.GetWeightedClusters()
	if wc == nil || len(wc.Clusters) != 2 {
		t.Fatalf("expected weighted clusters, got %+v", proxy)
	}
	clusters := snap.GetResources(resourcev3.ClusterType)
	if _, ok := clusters[model.NamedTCPServiceClusterName("blue")]; !ok {
		t.Fatalf("expected blue cluster, got %v", clusters)
	}
	if _, ok := clusters[model.NamedTCPServiceClusterName("green")]; !ok {
		t.Fatalf("expected green cluster, got %v", clusters)
	}
}

func TestBuildTCP_HTTPCoexistsWithTCP(t *testing.T) {
	httpCfg := model.HTTPConfiguration{
		Routes: map[string]model.Route{
			"app": {Subdomain: "app", RouterName: "web", Endpoints: []model.Endpoint{{Address: "10.0.0.9", Port: 8080}}},
		},
		Services: map[string]model.HTTPService{},
	}
	tcpCfg := model.TCPConfiguration{
		Routers: map[string]model.TCPRouter{
			"raw": {Name: "raw", Rule: hostSNI("*"), RuleExpr: "HostSNI(*)", ServiceName: "db", Entrypoints: []string{"raw"}},
		},
		Services: map[string]model.TCPService{
			"db": {Name: "db", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 5432}}},
		},
	}
	snap, err := BuildSnapshotForConfigWithTCP("1", httpCfg, tcpCfg, baseTCPCfg())
	if err != nil {
		t.Fatal(err)
	}
	listeners := snap.GetResources(resourcev3.ListenerType)
	if _, ok := listeners[httpListenerName]; !ok {
		t.Fatalf("expected http listener to still exist alongside TCP: %v", listeners)
	}
	if _, ok := listeners[httpsListenerName]; !ok {
		t.Fatalf("expected https listener to still exist alongside TCP: %v", listeners)
	}
	if _, ok := listeners[tcpListenerNamePrefix+"raw"]; !ok {
		t.Fatalf("expected tcp listener to coexist: %v", listeners)
	}
	// HTTPS listener must still carry the HTTP connection manager.
	httpsL := listeners[httpsListenerName].(*listenerv3.Listener)
	hasHCM := false
	for _, f := range httpsL.FilterChains[0].Filters {
		if f.Name == wellknown.HTTPConnectionManager {
			hasHCM = true
		}
	}
	if !hasHCM {
		t.Fatal("https listener must retain its http connection manager")
	}
	// Cluster namespaces must not collide: legacy route cluster "app" vs
	// tcp service cluster "tcp-service/db".
	clusters := snap.GetResources(resourcev3.ClusterType)
	if _, ok := clusters["app"]; !ok {
		t.Fatalf("missing http cluster: %v", clusters)
	}
	if _, ok := clusters[model.NamedTCPServiceClusterName("db")]; !ok {
		t.Fatalf("missing tcp cluster: %v", clusters)
	}
}

func TestBuildTCP_ClusterNameCollisionRejected(t *testing.T) {
	// A TCP named service sharing a name with an HTTP named service would
	// collide were it not for the "tcp-service/" vs "http-service/"
	// namespace prefixes; verify no false-positive collision is raised
	// for same-named but differently-prefixed services.
	httpCfg := model.HTTPConfiguration{
		Routes:   map[string]model.Route{"app": {Subdomain: "app", RouterName: "web", ServiceName: "shared"}},
		Services: map[string]model.HTTPService{"shared": {Name: "shared", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 80}}}},
	}
	tcpCfg := model.TCPConfiguration{
		Routers:  map[string]model.TCPRouter{"r": {Name: "r", Rule: hostSNI("*"), RuleExpr: "HostSNI(*)", ServiceName: "shared", Entrypoints: []string{"raw"}}},
		Services: map[string]model.TCPService{"shared": {Name: "shared", Endpoints: []model.Endpoint{{Address: "10.0.0.2", Port: 1234}}}},
	}
	snap, err := BuildSnapshotForConfigWithTCP("1", httpCfg, tcpCfg, baseTCPCfg())
	if err != nil {
		t.Fatalf("same-named HTTP and TCP services in different namespaces must not collide: %v", err)
	}
	clusters := snap.GetResources(resourcev3.ClusterType)
	if _, ok := clusters[model.NamedServiceClusterName("shared")]; !ok {
		t.Fatalf("missing http cluster: %v", clusters)
	}
	if _, ok := clusters[model.NamedTCPServiceClusterName("shared")]; !ok {
		t.Fatalf("missing tcp cluster: %v", clusters)
	}
}

func TestBuildTCP_InvalidRawWithConcreteSNIRejected(t *testing.T) {
	tcpCfg := model.TCPConfiguration{
		Routers: map[string]model.TCPRouter{
			"raw": {Name: "raw", Rule: hostSNI("a.com"), RuleExpr: "HostSNI(a.com)", ServiceName: "svc", TLSPassthrough: false, Entrypoints: []string{"raw"}},
		},
		Services: map[string]model.TCPService{
			"svc": {Name: "svc", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 1}}},
		},
	}
	_, err := BuildSnapshotForConfigWithTCP("1", model.HTTPConfiguration{}, tcpCfg, baseTCPCfg())
	if err == nil || !strings.Contains(err.Error(), "catch-all") {
		t.Fatalf("expected raw+concrete-SNI rejection, got %v", err)
	}
}

// TestBuildTCP_DeterministicAcrossRepeatedBuilds is an integration-style
// check spanning the full HTTP+TCP snapshot: building the identical
// configuration many times must always produce byte-identical serialized
// output, proving the deterministic-conflict-detection and precedence
// ordering requirements hold regardless of Go's randomized map iteration.
func TestBuildTCP_DeterministicAcrossRepeatedBuilds(t *testing.T) {
	httpCfg := model.HTTPConfiguration{
		Routes: map[string]model.Route{
			"web1": {Subdomain: "web1", RouterName: "web1", Endpoints: []model.Endpoint{{Address: "10.0.1.1", Port: 80}}},
			"web2": {Subdomain: "web2", RouterName: "web2", Endpoints: []model.Endpoint{{Address: "10.0.1.2", Port: 80}}},
			"web3": {Subdomain: "web3", RouterName: "web3", Endpoints: []model.Endpoint{{Address: "10.0.1.3", Port: 80}}},
		},
		Services: map[string]model.HTTPService{},
	}
	tcpCfg := model.TCPConfiguration{
		Routers: map[string]model.TCPRouter{
			"a": {Name: "a", Rule: hostSNI("a.com"), RuleExpr: "HostSNI(a.com)", ServiceName: "svcA", TLSPassthrough: true, Entrypoints: []string{"websecure"}},
			"b": {Name: "b", Rule: hostSNI("b.com"), RuleExpr: "HostSNI(b.com)", ServiceName: "svcB", TLSPassthrough: true, Entrypoints: []string{"websecure"}},
			"c": {Name: "c", Rule: hostSNI("*"), RuleExpr: "HostSNI(*)", ServiceName: "svcC", TLSPassthrough: true, Entrypoints: []string{"websecure"}},
			"d": {Name: "d", Rule: hostSNI("*"), RuleExpr: "HostSNI(*)", ServiceName: "svcD", Entrypoints: []string{"raw"}},
		},
		Services: map[string]model.TCPService{
			"svcA": {Name: "svcA", Endpoints: []model.Endpoint{{Address: "10.0.2.1", Port: 1}}},
			"svcB": {Name: "svcB", Endpoints: []model.Endpoint{{Address: "10.0.2.2", Port: 1}}},
			"svcC": {Name: "svcC", Endpoints: []model.Endpoint{{Address: "10.0.2.3", Port: 1}}},
			"svcD": {Name: "svcD", Endpoints: []model.Endpoint{{Address: "10.0.2.4", Port: 1}}},
		},
	}
	cfg := baseTCPCfg()

	var first string
	for i := 0; i < 25; i++ {
		snap, err := BuildSnapshotForConfigWithTCP("1", httpCfg, tcpCfg, cfg)
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		var b strings.Builder
		for _, typ := range []string{resourcev3.ListenerType, resourcev3.ClusterType, resourcev3.EndpointType, resourcev3.RouteType} {
			names := make([]string, 0)
			for name := range snap.GetResources(typ) {
				names = append(names, name)
			}
			sortStrings(names)
			for _, n := range names {
				b.WriteString(typ)
				b.WriteString(":")
				b.WriteString(n)
				b.WriteString(snap.GetResources(typ)[n].(interface{ String() string }).String())
				b.WriteString("\n")
			}
		}
		got := b.String()
		if i == 0 {
			first = got
			continue
		}
		if got != first {
			t.Fatalf("iteration %d produced different snapshot serialization than iteration 0 (nondeterministic build)", i)
		}
	}
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
