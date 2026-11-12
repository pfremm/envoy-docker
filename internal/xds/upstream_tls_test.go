package xds

import (
	"testing"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
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
