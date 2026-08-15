package xds

import (
	"io"
	"log/slog"
	"testing"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
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
