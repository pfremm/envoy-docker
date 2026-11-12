package dockerwatch

import (
	"strings"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"

	"github.com/bryanpfremm/envoy-control-plane/internal/sso"
	"github.com/bryanpfremm/envoy-control-plane/internal/xds"
)

func TestParseRouters_SSOLabel(t *testing.T) {
	got, bad, err := parseRouters(map[string]string{
		"envoy.http.routers.app.subdomain":    "app",
		"envoy.http.routers.app.port":         "8080",
		"envoy.http.routers.app.sso":          "nas",
		"envoy.http.routers.public.subdomain": "www",
		"envoy.http.routers.public.port":      "8080",
		"envoy.http.routers.empty.subdomain":  "e",
		"envoy.http.routers.empty.port":       "8080",
		"envoy.http.routers.empty.sso":        " ",
	})
	if err != nil {
		t.Fatalf("parseRouters() unexpected error: %v", err)
	}
	if got["app"].ssoProfile != "nas" {
		t.Errorf("app ssoProfile = %q, want nas", got["app"].ssoProfile)
	}
	if got["public"].ssoProfile != "" {
		t.Errorf("public ssoProfile = %q, want empty", got["public"].ssoProfile)
	}
	if e := bad["empty"]; e == nil || !strings.Contains(e.Error(), "sso cannot be empty") {
		t.Errorf("empty sso label: bad = %v, want rejection of only that router", bad)
	}
	if len(bad) != 1 {
		t.Errorf("badRouters = %v, want only the empty-sso router", bad)
	}
}

func TestDiscoverCarriesSSOProfile(t *testing.T) {
	c := container.Summary{ID: "c1", Names: []string{"/c1"}, Labels: map[string]string{
		"envoy.enable":                     "true",
		"envoy.http.routers.app.subdomain": "app",
		"envoy.http.routers.app.port":      "8080",
		"envoy.http.routers.app.sso":       "nas",
	}, NetworkSettings: &container.NetworkSettingsSummary{Networks: map[string]*network.EndpointSettings{"proxy": {IPAddress: "10.0.0.1"}}}}
	cfg := discover([]container.Summary{c}, "proxy", nil)
	if got := cfg.Routes["app"].SSOProfile; got != "nas" {
		t.Fatalf("SSOProfile = %q, want nas", got)
	}
}

func TestParseRouters_SSOLabelValues(t *testing.T) {
	cases := []struct {
		name, value, want, wantErr string
	}{
		{"plain", "nas", "nas", ""},
		{"surrounding whitespace trimmed", "  nas\t", "nas", ""},
		{"case preserved", "NAS", "NAS", ""},
		{"mixed case trimmed", " Nas-Prod_1 ", "Nas-Prod_1", ""},
		{"empty", "", "", "sso cannot be empty"},
		{"whitespace only", " \t\n", "", "sso cannot be empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, bad, err := parseRouters(map[string]string{
				"envoy.http.routers.app.subdomain": "app",
				"envoy.http.routers.app.port":      "8080",
				"envoy.http.routers.app.sso":       tc.value,
				"envoy.http.routers.www.subdomain": "www",
				"envoy.http.routers.www.port":      "8080",
			})
			if err != nil {
				t.Fatalf("parseRouters() unexpected error: %v", err)
			}
			if got["www"].ssoProfile != "" || bad["www"] != nil {
				t.Errorf("sibling router affected: %+v / %v", got["www"], bad["www"])
			}
			if tc.wantErr != "" {
				if e := bad["app"]; e == nil || !strings.Contains(e.Error(), tc.wantErr) || !strings.Contains(e.Error(), `router "app"`) {
					t.Fatalf("bad[app] = %v, want error naming the router and containing %q", e, tc.wantErr)
				}
				return
			}
			if bad["app"] != nil {
				t.Fatalf("router rejected: %v", bad["app"])
			}
			if got["app"].ssoProfile != tc.want {
				t.Errorf("ssoProfile = %q, want %q", got["app"].ssoProfile, tc.want)
			}
		})
	}
}

// TestEndToEnd_UnknownSSOProfileRejectsOnlyThatRouter runs labels through
// discovery and the xDS builder: a router naming an undefined (or
// differently-cased) profile is dropped, while its siblings on the same
// container and listener, SSO and public, are still served.
func TestEndToEnd_UnknownSSOProfileRejectsOnlyThatRouter(t *testing.T) {
	ssoCfg := sso.Parse("sso.yaml", []byte(`sso_profiles:
  nas:
    redirect_uri_host: sso.example.com
    cookie_domain: example.com
    issuer: https://auth.example.com/o/nas/
    authorization_endpoint: https://auth.example.com/o/authorize/
    token_endpoint: {cluster: sso_idp, uri: https://auth.example.com/o/token/}
    jwks: {cluster: sso_idp, uri: https://auth.example.com/o/nas/jwks/}
    credentials: {client_id: envoy-nas}
    hmac_secret:  {name: sso-nas-hmac,  sds_path: /etc/envoy/secrets/hmac.yaml}
    token_secret: {name: sso-nas-token, sds_path: /etc/envoy/secrets/token.yaml}
`))
	if ssoCfg.LoadErr != nil || len(ssoCfg.Invalid) != 0 {
		t.Fatalf("fixture invalid: %v %v", ssoCfg.LoadErr, ssoCfg.Invalid)
	}
	c := e2eContainer("c1", "10.0.0.1", map[string]string{
		"envoy.enable":                         "true",
		"envoy.http.routers.typo.subdomain":    "typo",
		"envoy.http.routers.typo.port":         "8080",
		"envoy.http.routers.typo.sso":          "nass",
		"envoy.http.routers.upper.subdomain":   "upper",
		"envoy.http.routers.upper.port":        "8080",
		"envoy.http.routers.upper.sso":         "NAS",
		"envoy.http.routers.private.subdomain": "private",
		"envoy.http.routers.private.port":      "8080",
		"envoy.http.routers.private.sso":       "nas",
		"envoy.http.routers.public.subdomain":  "public",
		"envoy.http.routers.public.port":       "8080",
	})
	cfg := xds.Config{BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443, CertSecretName: "cert", ACMESDSClusterName: "acme", SSO: ssoCfg}
	snap := buildE2ESnapshot(t, []container.Summary{c}, cfg)

	rc := snap.GetResources(resourcev3.RouteType)["https_routes"].(*routev3.RouteConfiguration)
	domains := map[string]bool{}
	for _, vh := range rc.VirtualHosts {
		for _, d := range vh.Domains {
			domains[d] = true
		}
	}
	for _, d := range []string{"typo.example.com", "upper.example.com"} {
		if domains[d] {
			t.Errorf("router with unknown sso profile served at %s", d)
		}
	}
	for _, d := range []string{"private.example.com", "public.example.com"} {
		if !domains[d] {
			t.Errorf("sibling router %s missing (domains %v)", d, domains)
		}
	}
	hcm := e2eDecodeHCM(t, snap.GetResources(resourcev3.ListenerType)["https_listener"].(*listenerv3.Listener))
	var hasOAuth bool
	for _, f := range hcm.HttpFilters {
		if f.Name == "envoy.filters.http.oauth2.nas" {
			hasOAuth = true
		}
	}
	if !hasOAuth {
		t.Errorf("valid sibling SSO router lost its oauth2 filter")
	}
}
