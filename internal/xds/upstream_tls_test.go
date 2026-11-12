package xds

import (
	"testing"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/protobuf/proto"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
)

func upstreamTLSRoutes() map[string]model.Route {
	ep := []model.Endpoint{{Address: "10.10.2.42", Port: 8443}}
	return map[string]model.Route{
		"plain":   {Subdomain: "plain", Source: model.SourceStatic, Endpoints: ep},
		"docker":  {Subdomain: "docker", Source: model.SourceDocker, RouterName: "docker", Endpoints: ep},
		"secure":  {Subdomain: "secure", Source: model.SourceStatic, Endpoints: ep, UpstreamTLS: &model.UpstreamTLS{}},
		"truenas": {Subdomain: "truenas", Source: model.SourceStatic, Endpoints: ep, UpstreamTLS: &model.UpstreamTLS{InsecureSkipVerify: true}},
	}
}

// TestRouteClusters_UpstreamTLS covers both snapshot entry points (the
// legacy route map and the HTTPConfiguration one main uses): an https static
// route's cluster gets an upstream TLS socket with SNI = its public host,
// verifying against the system CA bundle unless insecure_skip_verify; http
// static and docker routes keep the plain cluster unchanged.
func TestRouteClusters_UpstreamTLS(t *testing.T) {
	cfg := Config{BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443, CertSecretName: "cert", ACMESDSClusterName: "acme"}
	builds := map[string]func() (cachev3.ResourceSnapshot, error){
		"BuildSnapshot": func() (cachev3.ResourceSnapshot, error) {
			return BuildSnapshot("1", upstreamTLSRoutes(), cfg)
		},
		"BuildSnapshotForConfig": func() (cachev3.ResourceSnapshot, error) {
			return BuildSnapshotForConfig("1", model.HTTPConfiguration{Routes: upstreamTLSRoutes()}, cfg)
		},
	}
	for name, build := range builds {
		t.Run(name, func(t *testing.T) {
			snap, err := build()
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			clusters := snap.GetResources(resourcev3.ClusterType)
			for _, plain := range []string{"plain", "docker"} {
				c, ok := clusters[plain].(*clusterv3.Cluster)
				if !ok {
					t.Fatalf("cluster %q missing", plain)
				}
				if !proto.Equal(c, buildCluster(plain)) {
					t.Errorf("cluster %q = %v, want the plain buildCluster cluster", plain, c)
				}
			}

			secure := upstreamTLSContext(t, clusters["secure"])
			if secure.GetSni() != "secure.example.com" {
				t.Errorf("secure SNI = %q, want secure.example.com", secure.GetSni())
			}
			v := secure.GetCommonTlsContext().GetValidationContext()
			if v.GetTrustedCa().GetFilename() != systemCABundle || v.GetTrustChainVerification() != tlsv3.CertificateValidationContext_VERIFY_TRUST_CHAIN {
				t.Errorf("secure validation context = %v, want trusted_ca %s with chain verification", v, systemCABundle)
			}

			insecure := upstreamTLSContext(t, clusters["truenas"])
			if insecure.GetSni() != "truenas.example.com" {
				t.Errorf("truenas SNI = %q, want truenas.example.com", insecure.GetSni())
			}
			v = insecure.GetCommonTlsContext().GetValidationContext()
			if v.GetTrustChainVerification() != tlsv3.CertificateValidationContext_ACCEPT_UNTRUSTED || v.GetTrustedCa() != nil {
				t.Errorf("truenas validation context = %v, want ACCEPT_UNTRUSTED without trusted_ca", v)
			}
		})
	}
}

func upstreamTLSContext(t *testing.T, res any) *tlsv3.UpstreamTlsContext {
	t.Helper()
	c, ok := res.(*clusterv3.Cluster)
	if !ok {
		t.Fatalf("cluster missing: %v", res)
	}
	ts := c.GetTransportSocket()
	if ts.GetName() != transportSocketTLS {
		t.Fatalf("cluster %s transport socket = %v, want %s", c.Name, ts, transportSocketTLS)
	}
	ctx := &tlsv3.UpstreamTlsContext{}
	if err := ts.GetTypedConfig().UnmarshalTo(ctx); err != nil {
		t.Fatal(err)
	}
	return ctx
}

// TestBuildRouteCluster checks the per-route cluster directly: only a route
// with UpstreamTLS gets a transport socket, with SNI <subdomain>.<base_domain>
// and a validation context that either trusts the system CA bundle or, with
// insecure_skip_verify, accepts any chain without a trusted_ca.
func TestBuildRouteCluster(t *testing.T) {
	ep := []model.Endpoint{{Address: "10.10.2.42", Port: 8443}}
	verify := &tlsv3.CertificateValidationContext{TrustedCa: &corev3.DataSource{Specifier: &corev3.DataSource_Filename{Filename: systemCABundle}}}
	acceptUntrusted := &tlsv3.CertificateValidationContext{TrustChainVerification: tlsv3.CertificateValidationContext_ACCEPT_UNTRUSTED}
	tests := []struct {
		name  string
		route model.Route
		// wantValidation is nil for a plain cluster (no transport socket).
		wantValidation *tlsv3.CertificateValidationContext
		wantSNI        string
	}{
		{name: "http static", route: model.Route{Subdomain: "plain", Source: model.SourceStatic, Endpoints: ep}},
		{name: "docker", route: model.Route{Subdomain: "docker", Source: model.SourceDocker, RouterName: "docker", Endpoints: ep}},
		{
			name:           "https verifies against system CAs",
			route:          model.Route{Subdomain: "secure", Source: model.SourceStatic, Endpoints: ep, UpstreamTLS: &model.UpstreamTLS{}},
			wantValidation: verify,
			wantSNI:        "secure.example.com",
		},
		{
			name:           "https insecure_skip_verify",
			route:          model.Route{Subdomain: "truenas", Source: model.SourceStatic, Endpoints: ep, UpstreamTLS: &model.UpstreamTLS{InsecureSkipVerify: true}},
			wantValidation: acceptUntrusted,
			wantSNI:        "truenas.example.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := buildRouteCluster(tt.route, "example.com")
			if tt.wantValidation == nil {
				if c.GetTransportSocket() != nil {
					t.Errorf("transport socket = %v, want none", c.GetTransportSocket())
				}
				if !proto.Equal(c, buildCluster(tt.route.ClusterName())) {
					t.Errorf("cluster = %v, want the plain buildCluster cluster", c)
				}
				return
			}
			// Apart from the transport socket, the cluster is the plain one.
			withoutTLS := proto.Clone(c).(*clusterv3.Cluster)
			withoutTLS.TransportSocket = nil
			if !proto.Equal(withoutTLS, buildCluster(tt.route.ClusterName())) {
				t.Errorf("cluster without transport socket = %v, want the plain buildCluster cluster", withoutTLS)
			}
			ctx := upstreamTLSContext(t, c)
			if ctx.GetSni() != tt.wantSNI {
				t.Errorf("SNI = %q, want %q", ctx.GetSni(), tt.wantSNI)
			}
			if v := ctx.GetCommonTlsContext().GetValidationContext(); !proto.Equal(v, tt.wantValidation) {
				t.Errorf("validation context = %v, want %v", v, tt.wantValidation)
			}
		})
	}
}

// TestRouteClusters_DockerUnchangedBesideHTTPS builds snapshots where docker
// routes coexist with static https routes (and a plain http static route):
// the docker clusters must stay exactly buildCluster, and the http static
// cluster must carry no transport socket.
func TestRouteClusters_DockerUnchangedBesideHTTPS(t *testing.T) {
	cfg := Config{BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443, CertSecretName: "cert", ACMESDSClusterName: "acme"}
	ep := []model.Endpoint{{Address: "10.0.0.1", Port: 8080}}
	routes := func() map[string]model.Route {
		return map[string]model.Route{
			"app":     {Subdomain: "app", Source: model.SourceDocker, RouterName: "app", Endpoints: ep},
			"grafana": {Subdomain: "grafana", Source: model.SourceDocker, RouterName: "grafana", Endpoints: ep},
			"plain":   {Subdomain: "plain", Source: model.SourceStatic, Endpoints: ep},
			"secure":  {Subdomain: "secure", Source: model.SourceStatic, Endpoints: ep, UpstreamTLS: &model.UpstreamTLS{}},
			"truenas": {Subdomain: "truenas", Source: model.SourceStatic, Endpoints: ep, UpstreamTLS: &model.UpstreamTLS{InsecureSkipVerify: true}},
		}
	}
	builds := map[string]func() (cachev3.ResourceSnapshot, error){
		"BuildSnapshot": func() (cachev3.ResourceSnapshot, error) {
			return BuildSnapshot("1", routes(), cfg)
		},
		"BuildSnapshotForConfig": func() (cachev3.ResourceSnapshot, error) {
			return BuildSnapshotForConfig("1", model.HTTPConfiguration{Routes: routes()}, cfg)
		},
	}
	for name, build := range builds {
		t.Run(name, func(t *testing.T) {
			snap, err := build()
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			clusters := snap.GetResources(resourcev3.ClusterType)
			for _, docker := range []string{"app", "grafana"} {
				c, ok := clusters[docker].(*clusterv3.Cluster)
				if !ok {
					t.Fatalf("docker cluster %q missing", docker)
				}
				if !proto.Equal(c, buildCluster(docker)) {
					t.Errorf("docker cluster %q = %v, want the plain buildCluster cluster", docker, c)
				}
			}
			plain, ok := clusters["plain"].(*clusterv3.Cluster)
			if !ok {
				t.Fatal("cluster \"plain\" missing")
			}
			if plain.GetTransportSocket() != nil {
				t.Errorf("http static cluster transport socket = %v, want none", plain.GetTransportSocket())
			}
			for _, https := range []string{"secure", "truenas"} {
				upstreamTLSContext(t, clusters[https])
			}
		})
	}
}
