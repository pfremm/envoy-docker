package sso

import (
	"strings"
	"testing"
)

// replaceIn returns validProfileYAML with old replaced by new, failing the
// test if the fixture does not contain old (so a fixture edit cannot turn a
// case into a silent no-op).
func replaceIn(t *testing.T, old, new string) string {
	t.Helper()
	if !strings.Contains(validProfileYAML, old) {
		t.Fatalf("fixture does not contain %q", old)
	}
	return strings.Replace(validProfileYAML, old, new, 1)
}

// assertProfileRejected checks that profile is rejected with an error that
// mentions every wantSubstr, and that the router-facing Lookup error names
// the profile as well as the field.
func assertProfileRejected(t *testing.T, profile, body string, wantSubstr ...string) {
	t.Helper()
	cfg := Parse("sso.yaml", []byte(profileDoc(profile, body)))
	if cfg.LoadErr != nil {
		t.Fatalf("unexpected file-level error: %v", cfg.LoadErr)
	}
	if _, ok := cfg.Profiles[profile]; ok {
		t.Fatalf("profile %q accepted, want rejection mentioning %q", profile, wantSubstr)
	}
	err := cfg.Invalid[profile]
	if err == nil {
		t.Fatalf("profile %q not recorded in Invalid", profile)
	}
	_, lookupErr := cfg.Lookup(profile)
	if lookupErr == nil {
		t.Fatalf("Lookup(%q) succeeded for an invalid profile", profile)
	}
	if want := `sso profile "` + profile + `" is invalid`; !strings.Contains(lookupErr.Error(), want) {
		t.Errorf("Lookup error = %q, want it to name the profile (%q)", lookupErr, want)
	}
	for _, s := range wantSubstr {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("error = %q, want it to contain %q", err, s)
		}
		if !strings.Contains(lookupErr.Error(), s) {
			t.Errorf("Lookup error = %q, want it to contain %q", lookupErr, s)
		}
	}
}

func TestParseProfile_MissingRequiredFields(t *testing.T) {
	cases := []struct {
		name  string
		body  string
		field string
	}{
		{"redirect_uri_host", replaceIn(t, "redirect_uri_host: sso.nas2.pfrem.me", ""), "redirect_uri_host is required"},
		{"redirect_uri_host blank", replaceIn(t, "redirect_uri_host: sso.nas2.pfrem.me", "redirect_uri_host: '   '"), "redirect_uri_host is required"},
		{"cookie_domain", replaceIn(t, "cookie_domain: nas2.pfrem.me", ""), "cookie_domain is required"},
		{"issuer", replaceIn(t, "issuer: https://auth.example.com/application/o/nas/", ""), "issuer is required"},
		{"authorization_endpoint", replaceIn(t, "authorization_endpoint: https://auth.example.com/application/o/authorize/", ""), "authorization_endpoint is required"},
		{"token_endpoint", replaceIn(t, "token_endpoint: {cluster: sso_idp, uri: https://auth.example.com/application/o/token/, timeout: 5s}", ""), "token_endpoint is required"},
		{"token_endpoint.cluster", replaceIn(t, "token_endpoint: {cluster: sso_idp, ", "token_endpoint: {"), "token_endpoint: cluster"},
		{"token_endpoint.uri", replaceIn(t, "uri: https://auth.example.com/application/o/token/, ", ""), "token_endpoint: uri"},
		{"jwks", replaceIn(t, "jwks: {cluster: sso_idp, uri: https://auth.example.com/application/o/nas/jwks/}", ""), "jwks is required"},
		{"jwks.cluster", replaceIn(t, "jwks: {cluster: sso_idp, ", "jwks: {"), "jwks: cluster"},
		{"jwks.uri", replaceIn(t, "jwks: {cluster: sso_idp, uri: https://auth.example.com/application/o/nas/jwks/}", "jwks: {cluster: sso_idp}"), "jwks: uri"},
		{"credentials", replaceIn(t, "credentials:\n      client_id: envoy-nas", ""), "credentials.client_id is required"},
		{"credentials.client_id blank", replaceIn(t, "client_id: envoy-nas", "client_id: '  '"), "credentials.client_id is required"},
		{"hmac_secret", replaceIn(t, "hmac_secret:  {name: sso-nas-hmac,  sds_path: /etc/envoy/secrets/sso-nas-hmac.yaml}", ""), "hmac_secret is required"},
		{"hmac_secret.name", replaceIn(t, "{name: sso-nas-hmac,  ", "{"), "hmac_secret.name is required"},
		{"token_secret", replaceIn(t, "token_secret: {name: sso-nas-token, sds_path: /etc/envoy/secrets/sso-nas-token.yaml}", ""), "token_secret is required"},
		{"token_secret.name", replaceIn(t, "{name: sso-nas-token, ", "{"), "token_secret.name is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertProfileRejected(t, "myprof", tc.body, tc.field)
		})
	}
}

func TestParseProfile_BadEndpointURLs(t *testing.T) {
	// Each IdP endpoint must be an absolute https URL with a host. The
	// error names the field and quotes the offending value.
	bad := []struct {
		name, uri, want string
	}{
		{"plain http", "http://auth.example.com/x", "must be an absolute https:// URL"},
		{"no scheme", "auth.example.com/x", "must be an absolute https:// URL"},
		{"relative path", "/application/o/token/", "must be an absolute https:// URL"},
		{"garbage", "::not a url::", "is not a valid URL"},
		{"no host", "https:///token", "has no host"},
		{"userinfo", "https://user:pw@auth.example.com/x", "must not contain credentials"},
		{"port zero", "https://auth.example.com:0/x", "invalid port"},
	}
	fields := []struct {
		name, old, prefix, field string
	}{
		{"authorization_endpoint", "authorization_endpoint: https://auth.example.com/application/o/authorize/", "authorization_endpoint: ", "authorization_endpoint: "},
		{"token_endpoint.uri", "uri: https://auth.example.com/application/o/token/,", "uri: ", "token_endpoint: uri: "},
		{"jwks.uri", "uri: https://auth.example.com/application/o/nas/jwks/}", "uri: ", "jwks: uri: "},
	}
	for _, f := range fields {
		for _, b := range bad {
			t.Run(f.name+"/"+b.name, func(t *testing.T) {
				repl := f.prefix + "'" + b.uri + "'"
				if strings.HasSuffix(f.old, ",") {
					repl += ","
				} else if strings.HasSuffix(f.old, "}") {
					repl += "}"
				}
				body := replaceIn(t, f.old, repl)
				assertProfileRejected(t, "myprof", body, f.field, `"`+b.uri+`"`, b.want)
			})
		}
	}
}

func TestParseProfile_IssuerIsOpaque(t *testing.T) {
	// The issuer is compared verbatim against the token's iss claim
	// (RFC 7519 §4.1.1 makes it a case-sensitive StringOrURI), so it is only
	// required to be non-empty; it is never fetched, and is deliberately not
	// URL-validated.
	for _, iss := range []string{"https://auth.example.com/o/nas/", "urn:example:issuer", "http://legacy-idp"} {
		body := replaceIn(t, "issuer: https://auth.example.com/application/o/nas/", "issuer: '"+iss+"'")
		cfg := Parse("sso.yaml", []byte(profileDoc("p", body)))
		p, err := cfg.Lookup("p")
		if err != nil {
			t.Fatalf("issuer %q rejected: %v", iss, err)
		}
		if p.Issuer != iss {
			t.Errorf("Issuer = %q, want %q verbatim", p.Issuer, iss)
		}
	}
}

func TestParseProfile_BadRedirect(t *testing.T) {
	const old = "redirect_uri_host: sso.nas2.pfrem.me"
	cases := []struct {
		name, body string
		want       []string
	}{
		{"scheme", replaceIn(t, old, "redirect_uri_host: https://sso.nas2.pfrem.me"), []string{"redirect_uri_host", "bare host name"}},
		{"path", replaceIn(t, old, "redirect_uri_host: sso.nas2.pfrem.me/cb"), []string{"redirect_uri_host", "bare host name"}},
		{"garbage", replaceIn(t, old, "redirect_uri_host: 'not_a!host.nas2.pfrem.me'"), []string{"redirect_uri_host", "bare host name"}},
		{"port zero", replaceIn(t, old, "redirect_uri_host: 'sso.nas2.pfrem.me:0'"), []string{"redirect_uri_host", "invalid port"}},
		{"port out of range", replaceIn(t, old, "redirect_uri_host: 'sso.nas2.pfrem.me:70000'"), []string{"redirect_uri_host", "invalid port"}},
		{"outside cookie domain", replaceIn(t, old, "redirect_uri_host: sso.elsewhere.me"), []string{"redirect_uri_host", "not within cookie_domain"}},
		{"relative redirect_path", validProfileYAML + "    redirect_path: oauth2/callback\n", []string{"redirect_path", "absolute path"}},
		{"redirect_path with query", validProfileYAML + "    redirect_path: '/cb?x=1'\n", []string{"redirect_path", "absolute path"}},
		{"relative signout_path", validProfileYAML + "    signout_path: signout\n", []string{"signout_path", "absolute path"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertProfileRejected(t, "myprof", tc.body, tc.want...)
		})
	}

	// A non-standard HTTPS port is allowed and carried into the callback URI.
	cfg := Parse("sso.yaml", []byte(profileDoc("p", replaceIn(t, old, "redirect_uri_host: 'sso.nas2.pfrem.me:8443'"))))
	p, err := cfg.Lookup("p")
	if err != nil {
		t.Fatalf("host:port rejected: %v", err)
	}
	if p.RedirectURI() != "https://sso.nas2.pfrem.me:8443/oauth2/callback" || p.RedirectHostname() != "sso.nas2.pfrem.me" {
		t.Errorf("RedirectURI = %q, RedirectHostname = %q", p.RedirectURI(), p.RedirectHostname())
	}
}

func TestParseProfile_BadSecretPaths(t *testing.T) {
	secrets := []struct {
		field, old string
	}{
		{"hmac_secret", "sds_path: /etc/envoy/secrets/sso-nas-hmac.yaml"},
		{"token_secret", "sds_path: /etc/envoy/secrets/sso-nas-token.yaml"},
	}
	paths := []struct {
		name, yaml, quoted string
	}{
		{"relative", "sds_path: secrets/x.yaml", `"secrets/x.yaml"`},
		{"dot relative", "sds_path: ./x.yaml", `"./x.yaml"`},
		{"home relative", "sds_path: '~/x.yaml'", `"~/x.yaml"`},
		{"empty", "sds_path: ''", `""`},
		{"omitted", "", `""`},
	}
	for _, s := range secrets {
		for _, p := range paths {
			t.Run(s.field+"/"+p.name, func(t *testing.T) {
				old := s.old
				repl := p.yaml
				if p.yaml == "" {
					// Drop the key together with its separating comma.
					old = ", " + s.old
					if !strings.Contains(validProfileYAML, old) {
						old = ",  " + s.old
					}
				}
				body := replaceIn(t, old, repl)
				assertProfileRejected(t, "myprof", body, s.field+".sds_path", p.quoted, "must be an absolute path")
			})
		}
	}
}

func TestParseProfile_SecretPathNotReadByControlPlane(t *testing.T) {
	// sds_path names a file inside the Envoy container; the control plane
	// only emits the reference and never opens it, so a path that does not
	// exist here is accepted (and cleaned).
	const missing = "/definitely/not/present/on/the/control/plane//hmac.yaml"
	body := replaceIn(t, "sds_path: /etc/envoy/secrets/sso-nas-hmac.yaml", "sds_path: "+missing)
	cfg := Parse("sso.yaml", []byte(profileDoc("p", body)))
	p, err := cfg.Lookup("p")
	if err != nil {
		t.Fatalf("nonexistent absolute sds_path rejected: %v", err)
	}
	if p.HMACSecret.SDSPath != "/definitely/not/present/on/the/control/plane/hmac.yaml" {
		t.Errorf("SDSPath = %q, want cleaned path", p.HMACSecret.SDSPath)
	}
}

func TestLookup_ProfileNamesAreCaseSensitive(t *testing.T) {
	cfg := Parse("sso.yaml", []byte(profileDoc("nas", validProfileYAML)))
	if _, err := cfg.Lookup("nas"); err != nil {
		t.Fatalf("Lookup(nas): %v", err)
	}
	_, err := cfg.Lookup("NAS")
	if err == nil {
		t.Fatalf("Lookup(NAS) matched profile nas; profile names are case-sensitive")
	}
	if !strings.Contains(err.Error(), `"NAS" is not defined`) || !strings.Contains(err.Error(), "defined profiles: nas") {
		t.Errorf("Lookup(NAS) error = %q, want not-defined error listing the defined profiles", err)
	}
}
