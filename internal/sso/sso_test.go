package sso

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// validProfileYAML is a complete profile body, indented for nesting under
// sso_profiles.<name>.
const validProfileYAML = `
    redirect_uri_host: sso.nas2.pfrem.me
    cookie_domain: nas2.pfrem.me
    issuer: https://auth.example.com/application/o/nas/
    authorization_endpoint: https://auth.example.com/application/o/authorize/
    token_endpoint: {cluster: sso_idp, uri: https://auth.example.com/application/o/token/, timeout: 5s}
    jwks: {cluster: sso_idp, uri: https://auth.example.com/application/o/nas/jwks/}
    credentials:
      client_id: envoy-nas
    hmac_secret:  {name: sso-nas-hmac,  sds_path: /etc/envoy/secrets/sso-nas-hmac.yaml}
    token_secret: {name: sso-nas-token, sds_path: /etc/envoy/secrets/sso-nas-token.yaml}
`

func profileDoc(name, body string) string {
	return "sso_profiles:\n  " + name + ":" + body
}

func TestParseValidProfileDefaults(t *testing.T) {
	cfg := Parse("sso.yaml", []byte(profileDoc("nas", validProfileYAML)))
	if cfg.LoadErr != nil || len(cfg.Invalid) != 0 {
		t.Fatalf("unexpected errors: load=%v invalid=%v", cfg.LoadErr, cfg.Invalid)
	}
	p, err := cfg.Lookup("nas")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if p.RedirectPath != DefaultRedirectPath || p.SignoutPath != DefaultSignoutPath {
		t.Errorf("paths = %q %q, want defaults", p.RedirectPath, p.SignoutPath)
	}
	if p.RedirectURI() != "https://sso.nas2.pfrem.me/oauth2/callback" {
		t.Errorf("RedirectURI = %q", p.RedirectURI())
	}
	if !reflect.DeepEqual(p.AuthScopes, []string{"openid", "email"}) {
		t.Errorf("AuthScopes = %v", p.AuthScopes)
	}
	if p.PassThrough != (PassThroughMatcher{Header: "authorization", Prefix: "Bearer "}) {
		t.Errorf("PassThrough = %+v", p.PassThrough)
	}
	if p.JWKSCacheDuration != 300*time.Second || p.JWKS.Timeout != DefaultTimeout {
		t.Errorf("jwks cache=%v timeout=%v", p.JWKSCacheDuration, p.JWKS.Timeout)
	}
	if p.TokenEndpoint.Host != "auth.example.com" || p.TokenEndpoint.Port != 443 {
		t.Errorf("token endpoint authority = %s:%d", p.TokenEndpoint.Host, p.TokenEndpoint.Port)
	}
}

func TestParseProfileValidation(t *testing.T) {
	replace := func(old, new string) string {
		if !strings.Contains(validProfileYAML, old) {
			t.Fatalf("fixture does not contain %q", old)
		}
		return strings.Replace(validProfileYAML, old, new, 1)
	}
	cases := []struct {
		name    string
		profile string
		body    string
		wantErr string
	}{
		{"bad profile name", "bad.name", validProfileYAML, "profile name"},
		{"missing redirect host", "p", replace("redirect_uri_host: sso.nas2.pfrem.me", ""), "redirect_uri_host is required"},
		{"redirect host with scheme", "p", replace("redirect_uri_host: sso.nas2.pfrem.me", "redirect_uri_host: https://sso.nas2.pfrem.me"), "bare host name"},
		{"redirect host outside cookie domain", "p", replace("redirect_uri_host: sso.nas2.pfrem.me", "redirect_uri_host: sso.other.me"), "not within cookie_domain"},
		{"missing cookie domain", "p", replace("cookie_domain: nas2.pfrem.me", ""), "cookie_domain is required"},
		{"missing issuer", "p", replace("issuer: https://auth.example.com/application/o/nas/", ""), "issuer is required"},
		{"http authorization endpoint", "p", replace("authorization_endpoint: https://", "authorization_endpoint: http://"), "https://"},
		{"relative token uri", "p", replace("uri: https://auth.example.com/application/o/token/", "uri: /token"), "token_endpoint: uri"},
		{"bad timeout", "p", replace("timeout: 5s", "timeout: soon"), "invalid duration"},
		{"bad cache duration", "p", replace("nas/jwks/}", "nas/jwks/, cache_duration: -1s}"), "jwks.cache_duration"},
		{"missing jwks", "p", replace("jwks: {cluster: sso_idp, uri: https://auth.example.com/application/o/nas/jwks/}", ""), "jwks is required"},
		{"bad cluster name", "p", replace("{cluster: sso_idp, uri: https://auth.example.com/application/o/token/", "{cluster: 'bad name', uri: https://auth.example.com/application/o/token/"), "cluster"},
		{"shared cluster different host", "p", replace("jwks: {cluster: sso_idp, uri: https://auth.example.com/", "jwks: {cluster: sso_idp, uri: https://other.example.com/"), "share cluster"},
		{"missing client id", "p", replace("client_id: envoy-nas", "client_id: ''"), "client_id is required"},
		{"inline client secret rejected", "p", replace("client_id: envoy-nas", "client_id: envoy-nas\n      client_secret: hunter2"), "client_secret"},
		{"relative sds path", "p", replace("sds_path: /etc/envoy/secrets/sso-nas-hmac.yaml", "sds_path: secrets/hmac.yaml"), "must be an absolute path"},
		{"missing token secret", "p", replace("token_secret: {name: sso-nas-token, sds_path: /etc/envoy/secrets/sso-nas-token.yaml}", ""), "token_secret is required"},
		{"same secret names", "p", replace("name: sso-nas-token", "name: sso-nas-hmac"), "different secret names"},
		{"same redirect and signout", "p", validProfileYAML + "    signout_path: /oauth2/callback\n", "must differ"},
		{"relative redirect path", "p", validProfileYAML + "    redirect_path: oauth2/callback\n", "redirect_path"},
		{"empty scopes", "p", validProfileYAML + "    auth_scopes: []\n", "auth_scopes must not be empty"},
		{"bad pass-through header", "p", validProfileYAML + "    pass_through_matcher: {header: 'bad header', prefix: x}\n", "pass_through_matcher.header"},
		{"unknown field", "p", validProfileYAML + "    redirect_url: x\n", "redirect_url"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Parse("sso.yaml", []byte(profileDoc(tc.profile, tc.body)))
			if cfg.LoadErr != nil {
				t.Fatalf("unexpected file-level error: %v", cfg.LoadErr)
			}
			err := cfg.Invalid[tc.profile]
			if err == nil {
				t.Fatalf("profile accepted, want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want it to contain %q", err, tc.wantErr)
			}
			if _, lookupErr := cfg.Lookup(tc.profile); lookupErr == nil || !strings.Contains(lookupErr.Error(), "is invalid") {
				t.Fatalf("Lookup error = %v, want invalid-profile error", lookupErr)
			}
		})
	}
}

func TestParseInvalidProfileIsIsolated(t *testing.T) {
	doc := profileDoc("good", validProfileYAML) + "  broken:\n    redirect_uri_host: x.nas2.pfrem.me\n"
	cfg := Parse("sso.yaml", []byte(doc))
	if _, err := cfg.Lookup("good"); err != nil {
		t.Fatalf("good profile rejected: %v", err)
	}
	if _, bad := cfg.Invalid["broken"]; !bad {
		t.Fatalf("broken profile accepted")
	}
}

func TestParseCrossProfileClusterConflict(t *testing.T) {
	other := strings.ReplaceAll(validProfileYAML, "https://auth.example.com/application/o/token/", "https://idp2.example.com/token")
	other = strings.ReplaceAll(other, "jwks: {cluster: sso_idp", "jwks: {cluster: sso_idp2")
	other = strings.ReplaceAll(other, "redirect_uri_host: sso.", "redirect_uri_host: sso2.")
	other = strings.ReplaceAll(other, "sso-nas-", "sso-b-")
	doc := profileDoc("a", validProfileYAML) + "  b:" + other
	cfg := Parse("sso.yaml", []byte(doc))
	if _, err := cfg.Lookup("a"); err != nil {
		t.Fatalf("first profile (sorted) must win: %v", err)
	}
	if err := cfg.Invalid["b"]; err == nil || !strings.Contains(err.Error(), `cluster "sso_idp"`) {
		t.Fatalf("Invalid[b] = %v, want cluster conflict", err)
	}

	// Sharing a cluster that points at the same upstream is fine.
	same := strings.ReplaceAll(validProfileYAML, "redirect_uri_host: sso.", "redirect_uri_host: sso2.")
	same = strings.ReplaceAll(same, "sso-nas-", "sso-b-")
	cfg = Parse("sso.yaml", []byte(profileDoc("a", validProfileYAML)+"  b:"+same))
	if len(cfg.Invalid) != 0 {
		t.Fatalf("shared same-upstream cluster rejected: %v", cfg.Invalid)
	}
}

func TestParseFileLevelError(t *testing.T) {
	cfg := Parse("sso.yaml", []byte("sso_profiles: [not, a, map]\n"))
	if cfg.LoadErr == nil {
		t.Fatalf("want LoadErr")
	}
	if _, err := cfg.Lookup("nas"); err == nil || !strings.Contains(err.Error(), "failed to load") {
		t.Fatalf("Lookup = %v, want load error", err)
	}
}

func TestLookupWithoutConfig(t *testing.T) {
	var cfg *Config
	if _, err := cfg.Lookup("nas"); err == nil || !strings.Contains(err.Error(), "SSO_CONFIG_PATH is not set") {
		t.Fatalf("Lookup = %v", err)
	}
	cfg = Parse("sso.yaml", []byte(profileDoc("nas", validProfileYAML)))
	if _, err := cfg.Lookup("other"); err == nil || !strings.Contains(err.Error(), "not defined") {
		t.Fatalf("Lookup unknown = %v", err)
	}
}

func TestLoaderReloadsOnChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sso.yaml")
	if err := os.WriteFile(path, []byte(profileDoc("nas", validProfileYAML)), 0o600); err != nil {
		t.Fatal(err)
	}
	l := NewLoader(path, nil)
	if got := l.Current().SortedProfileNames(); !reflect.DeepEqual(got, []string{"nas"}) {
		t.Fatalf("profiles = %v", got)
	}
	first := l.Current()
	if second := l.Current(); second != first {
		t.Fatalf("unchanged file was re-parsed")
	}
	if err := os.WriteFile(path, []byte("sso_profiles: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := l.Current().SortedProfileNames(); len(got) != 0 {
		t.Fatalf("profiles after edit = %v", got)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if c := l.Current(); c == nil || c.LoadErr == nil {
		t.Fatalf("missing file must yield LoadErr, got %+v", c)
	}
	if NewLoader("", nil).Current() != nil {
		t.Fatalf("empty path must disable SSO")
	}
}
