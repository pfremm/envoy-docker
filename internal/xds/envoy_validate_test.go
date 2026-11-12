package xds_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	bootstrapv3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
	"github.com/bryanpfremm/envoy-control-plane/internal/sso"
	"github.com/bryanpfremm/envoy-control-plane/internal/xds"
)

// TestEnvoyValidatesSSOSnapshot renders a snapshot with two SSO profiles on
// one listener, an opted-in router per profile, a public router, a buffered
// router (listener buffer filter and Lua size guard disabled, enabled per
// route via FilterConfig and LuaPerRoute) and the synthesized callback virtual host into a static bootstrap (RDS inlined,
// EDS made static, the ACME SDS certificate and the SSO secrets read from
// local files) and runs `envoy --mode validate` on it.
//
// It needs a real Envoy binary and is skipped unless ENVOY_BIN is set. Set
// ENVOY_VALIDATE_DIR to keep the generated files (bootstrap.json, secrets,
// certificate) for running Envoy by hand; a tls.crt/tls.key already present
// there is used instead of a generated one. ENVOY_VALIDATE_HTTPS_PORT and
// ENVOY_VALIDATE_HTTP_PORT override the listener ports (18443/18080);
// ENVOY_VALIDATE_UPSTREAM_PORT points every router at 127.0.0.1:<port>
// (default 1, where nothing listens).
func TestEnvoyValidatesSSOSnapshot(t *testing.T) {
	envoyBin := os.Getenv("ENVOY_BIN")
	if envoyBin == "" {
		t.Skip("ENVOY_BIN not set")
	}
	dir := os.Getenv("ENVOY_VALIDATE_DIR")
	if dir == "" {
		dir = t.TempDir()
	} else if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	httpsPort := envPort(t, "ENVOY_VALIDATE_HTTPS_PORT", 18443)
	httpPort := envPort(t, "ENVOY_VALIDATE_HTTP_PORT", 18080)

	ssoDoc := "sso_profiles:\n"
	// nas is a public client (dummy token_secret); media is a confidential
	// client whose credentials.client_secret becomes OAuth2 token_secret.
	for _, p := range []struct {
		name, paths  string
		confidential bool
	}{
		{"nas", "", false},
		{"media", "    redirect_path: /oauth2/media/callback\n    signout_path: /oauth2/media/signout\n", true},
	} {
		creds := fmt.Sprintf("    credentials: {client_id: envoy-%[1]s}\n    token_secret: {name: sso-%[1]s-token, sds_path: %[2]s/sso-%[1]s-token.yaml}\n", p.name, dir)
		secretName, secretValue := "sso-"+p.name+"-token", "dummy-"+p.name
		if p.confidential {
			creds = fmt.Sprintf("    credentials:\n      client_id: envoy-%[1]s\n      client_secret: {name: sso-%[1]s-client, sds_path: %[2]s/sso-%[1]s-client.yaml}\n", p.name, dir)
			secretName, secretValue = "sso-"+p.name+"-client", "client-secret-"+p.name
		}
		ssoDoc += fmt.Sprintf(`  %[1]s:
    redirect_uri_host: sso.example.com
%[2]s    cookie_domain: example.com
    issuer: https://auth.example.com/application/o/%[1]s/
    authorization_endpoint: https://auth.example.com/application/o/authorize/
    token_endpoint: {cluster: sso_idp, uri: https://auth.example.com/application/o/token/}
    jwks: {cluster: sso_idp, uri: https://auth.example.com/application/o/%[1]s/jwks/}
%[4]s    hmac_secret:  {name: sso-%[1]s-hmac,  sds_path: %[3]s/sso-%[1]s-hmac.yaml}
`, p.name, p.paths, dir, creds)
		writeGenericSecret(t, filepath.Join(dir, "sso-"+p.name+"-hmac.yaml"), "sso-"+p.name+"-hmac", "0123456789abcdef0123456789abcdef")
		writeGenericSecret(t, filepath.Join(dir, secretName+".yaml"), secretName, secretValue)
	}
	ssoCfg := sso.Parse("sso.yaml", []byte(ssoDoc))
	if ssoCfg.LoadErr != nil || len(ssoCfg.Invalid) != 0 {
		t.Fatalf("SSO config invalid: %v %v", ssoCfg.LoadErr, ssoCfg.Invalid)
	}
	if p := ssoCfg.Profiles["media"]; !p.HasClientSecret() || p.ClientSecretRef().Name != "sso-media-client" {
		t.Fatalf("media profile is not confidential: %+v", p)
	}

	upstreamPort := envPort(t, "ENVOY_VALIDATE_UPSTREAM_PORT", 1)
	route := func(name, profile string) model.Route {
		return model.Route{
			Subdomain: name, RouterName: name, Source: model.SourceDocker, SSOProfile: profile,
			Endpoints: []model.Endpoint{{Address: "127.0.0.1", Port: upstreamPort}},
		}
	}
	wsoff := route("wsoff", "")
	wsoff.WebSocketDisabled = true
	bufMW := model.Middleware{Name: "buf", Buffering: &model.BufferingMiddleware{MaxRequestBytes: 1024}}
	buf := route("buf", "")
	buf.MiddlewareNames, buf.Middlewares = []string{"buf"}, []model.Middleware{bufMW}
	snap, err := xds.BuildSnapshotForConfig("1", model.HTTPConfiguration{Routes: map[string]model.Route{
		"app":   route("app", "nas"),
		"media": route("media", "media"),
		"www":   route("www", ""),
		"wsoff": wsoff,
		"buf":   buf,
	}, Middlewares: map[string]model.Middleware{"buf": bufMW}}, xds.Config{
		BaseDomain: "example.com", HTTPPort: httpPort, HTTPSPort: httpsPort,
		CertSecretName: "cert", ACMESDSClusterName: "acme", SSO: ssoCfg,
	})
	if err != nil {
		t.Fatalf("BuildSnapshotForConfig: %v", err)
	}

	certPath, keyPath := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if _, err := os.Stat(certPath); err != nil {
		writeSelfSignedCert(t, certPath, keyPath)
	}
	certSDS := filepath.Join(dir, "cert.yaml")
	writeSecretFile(t, certSDS, &tlsv3.Secret{Name: "cert", Type: &tlsv3.Secret_TlsCertificate{TlsCertificate: &tlsv3.TlsCertificate{
		CertificateChain: &corev3.DataSource{Specifier: &corev3.DataSource_Filename{Filename: certPath}},
		PrivateKey:       &corev3.DataSource{Specifier: &corev3.DataSource_Filename{Filename: keyPath}},
	}}})

	bootstrap := staticBootstrap(t, snap, certSDS)
	out, err := protojson.MarshalOptions{Indent: "  "}.Marshal(bootstrap)
	if err != nil {
		t.Fatalf("marshal bootstrap: %v", err)
	}
	bootstrapPath := filepath.Join(dir, "bootstrap.json")
	if err := os.WriteFile(bootstrapPath, out, 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(envoyBin, "--mode", "validate", "-c", bootstrapPath, "--log-level", "warn")
	res, err := cmd.CombinedOutput()
	t.Logf("envoy --mode validate -c %s:\n%s", bootstrapPath, res)
	if err != nil {
		t.Fatalf("envoy rejected the generated config: %v", err)
	}
}

func envPort(t *testing.T, name string, def uint32) uint32 {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.ParseUint(v, 10, 16)
	if err != nil || n == 0 {
		t.Fatalf("%s=%q is not a port", name, v)
	}
	return uint32(n)
}

// staticBootstrap turns an xDS snapshot into a static bootstrap: RDS
// references are replaced by the route configuration inline, EDS clusters
// become STATIC with their load assignment, and the listener certificate is
// read from certSDS instead of the ACME SDS cluster.
func staticBootstrap(t *testing.T, snap cachev3.ResourceSnapshot, certSDS string) *bootstrapv3.Bootstrap {
	t.Helper()
	routes := snap.GetResources(resourcev3.RouteType)
	endpoints := snap.GetResources(resourcev3.EndpointType)
	static := &bootstrapv3.Bootstrap_StaticResources{}

	for name, res := range snap.GetResources(resourcev3.ListenerType) {
		l := proto.Clone(res).(*listenerv3.Listener)
		for _, fc := range l.FilterChains {
			for _, f := range fc.Filters {
				hcm := &hcmv3.HttpConnectionManager{}
				mustUnmarshal(t, f.GetTypedConfig(), hcm)
				if rds := hcm.GetRds(); rds != nil {
					rc, ok := routes[rds.RouteConfigName].(*routev3.RouteConfiguration)
					if !ok {
						t.Fatalf("listener %s references missing route config %q", name, rds.RouteConfigName)
					}
					hcm.RouteSpecifier = &hcmv3.HttpConnectionManager_RouteConfig{RouteConfig: rc}
				}
				f.ConfigType = &listenerv3.Filter_TypedConfig{TypedConfig: mustMarshal(t, hcm)}
			}
			if ts := fc.TransportSocket; ts != nil {
				tlsCtx := &tlsv3.DownstreamTlsContext{}
				mustUnmarshal(t, ts.GetTypedConfig(), tlsCtx)
				for _, sds := range tlsCtx.GetCommonTlsContext().GetTlsCertificateSdsSecretConfigs() {
					sds.SdsConfig = fileConfigSource(certSDS)
				}
				ts.ConfigType = &corev3.TransportSocket_TypedConfig{TypedConfig: mustMarshal(t, tlsCtx)}
			}
		}
		static.Listeners = append(static.Listeners, l)
	}

	for name, res := range snap.GetResources(resourcev3.ClusterType) {
		c := proto.Clone(res).(*clusterv3.Cluster)
		if c.GetType() == clusterv3.Cluster_EDS {
			cla, ok := endpoints[name].(*endpointv3.ClusterLoadAssignment)
			if !ok {
				t.Fatalf("EDS cluster %s has no endpoints", name)
			}
			c.ClusterDiscoveryType = &clusterv3.Cluster_Type{Type: clusterv3.Cluster_STATIC}
			c.EdsClusterConfig = nil
			c.LoadAssignment = cla
		}
		static.Clusters = append(static.Clusters, c)
	}

	return &bootstrapv3.Bootstrap{
		Node: &corev3.Node{Id: "envoy-validate", Cluster: "envoy-validate"},
		Admin: &bootstrapv3.Admin{Address: &corev3.Address{Address: &corev3.Address_SocketAddress{SocketAddress: &corev3.SocketAddress{
			Address: "127.0.0.1", PortSpecifier: &corev3.SocketAddress_PortValue{PortValue: 0},
		}}}},
		StaticResources: static,
	}
}

func fileConfigSource(path string) *corev3.ConfigSource {
	return &corev3.ConfigSource{
		ResourceApiVersion:    corev3.ApiVersion_V3,
		ConfigSourceSpecifier: &corev3.ConfigSource_PathConfigSource{PathConfigSource: &corev3.PathConfigSource{Path: path}},
	}
}

func writeGenericSecret(t *testing.T, path, name, value string) {
	t.Helper()
	writeSecretFile(t, path, &tlsv3.Secret{Name: name, Type: &tlsv3.Secret_GenericSecret{GenericSecret: &tlsv3.GenericSecret{
		Secret: &corev3.DataSource{Specifier: &corev3.DataSource_InlineString{InlineString: value}},
	}}})
}

// writeSecretFile writes a file-based SDS resource (the {resources: [...]}
// discovery-response shape Envoy's path config source reads; JSON is YAML).
func writeSecretFile(t *testing.T, path string, s *tlsv3.Secret) {
	t.Helper()
	b, err := protojson.Marshal(mustMarshal(t, s))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"resources":[`+string(b)+`]}`), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeSelfSignedCert(t *testing.T, certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "*.example.com"},
		DNSNames:     []string{"*.example.com", "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustMarshal(t *testing.T, m proto.Message) *anypb.Any {
	t.Helper()
	a, err := anypb.New(m)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func mustUnmarshal(t *testing.T, a *anypb.Any, m proto.Message) {
	t.Helper()
	if err := a.UnmarshalTo(m); err != nil {
		t.Fatal(err)
	}
}
