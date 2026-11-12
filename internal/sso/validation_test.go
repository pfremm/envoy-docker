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

// withClientSecret returns validProfileYAML with credentials.client_secret
// set to cs (raw YAML after "client_secret:"), optionally dropping
// token_secret.
func withClientSecret(t *testing.T, cs string, dropToken bool) string {
	t.Helper()
	body := replaceIn(t, "client_id: envoy-nas", "client_id: envoy-nas\n      client_secret: "+cs)
	if dropToken {
		const tok = "    token_secret: {name: sso-nas-token, sds_path: /etc/envoy/secrets/sso-nas-token.yaml}\n"
		if !strings.Contains(body, tok) {
			t.Fatalf("fixture does not contain %q", tok)
		}
		body = strings.Replace(body, tok, "", 1)
	}
	return body
}

func TestParseProfile_ClientSecretRejected(t *testing.T) {
	const okRef = "{name: sso-nas-client, sds_path: /etc/envoy/secrets/sso-nas-client.yaml}"
	cases := []struct {
		name      string
		cs        string
		dropToken bool
		want      []string
	}{
		{"missing name", "{sds_path: /etc/envoy/secrets/sso-nas-client.yaml}", false, []string{"credentials.client_secret.name is required"}},
		{"blank name", "{name: '  ', sds_path: /etc/envoy/secrets/sso-nas-client.yaml}", false, []string{"credentials.client_secret.name is required"}},
		{"missing sds_path", "{name: sso-nas-client}", false, []string{"credentials.client_secret.sds_path", "must be an absolute path"}},
		{"relative sds_path", "{name: sso-nas-client, sds_path: secrets/c.yaml}", false, []string{"credentials.client_secret.sds_path", `"secrets/c.yaml"`, "must be an absolute path", "inside the Envoy container"}},
		{"inline string", `"abc"`, false, []string{"credentials.client_secret", "inline secrets are not supported", "SDS file"}},
		{"inline string without token_secret", "s3cr3t", true, []string{"credentials.client_secret", "inline secrets are not supported"}},
		{"null", "", false, []string{"credentials.client_secret", "inline secrets are not supported"}},
		{"sequence", "[a, b]", false, []string{"credentials.client_secret", "inline secrets are not supported"}},
		{"extra secret key", "{name: sso-nas-client, sds_path: /etc/envoy/secrets/sso-nas-client.yaml, secret: abc}", false, []string{`unknown key "secret"`, "inline secrets are not supported"}},
		{"extra value key", "{name: sso-nas-client, value: abc}", false, []string{`unknown key "value"`, "inline secrets are not supported"}},
		{"name equals hmac", "{name: sso-nas-hmac, sds_path: /etc/envoy/secrets/sso-nas-client.yaml}", false, []string{"credentials.client_secret and hmac_secret must use different secret names"}},
		{"name equals token", "{name: sso-nas-token, sds_path: /etc/envoy/secrets/sso-nas-client.yaml}", false, []string{"credentials.client_secret and token_secret must use different secret names"}},
		{"path equals hmac", "{name: sso-nas-client, sds_path: /etc/envoy/secrets/sso-nas-hmac.yaml}", false, []string{"credentials.client_secret and hmac_secret must use different sds_path files"}},
		{"path equals hmac uncleaned", "{name: sso-nas-client, sds_path: /etc/envoy//secrets/sso-nas-hmac.yaml}", true, []string{"credentials.client_secret and hmac_secret must use different sds_path files"}},
		{"path equals token", "{name: sso-nas-client, sds_path: /etc/envoy/secrets/sso-nas-token.yaml}", false, []string{"credentials.client_secret and token_secret must use different sds_path files"}},
		{"valid ref but bad token_secret", okRef, false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := withClientSecret(t, tc.cs, tc.dropToken)
			if tc.want == nil {
				// token_secret is still validated when present.
				body = strings.Replace(body, "sds_path: /etc/envoy/secrets/sso-nas-token.yaml", "sds_path: rel.yaml", 1)
				tc.want = []string{"token_secret.sds_path", "must be an absolute path"}
			}
			assertProfileRejected(t, "myprof", body, tc.want...)
		})
	}
}

func TestParseProfile_ClientSecretAccepted(t *testing.T) {
	client := Secret{Name: "sso-nas-client", SDSPath: "/etc/envoy/secrets/sso-nas-client.yaml"}
	token := Secret{Name: "sso-nas-token", SDSPath: "/etc/envoy/secrets/sso-nas-token.yaml"}
	const ref = "{name: sso-nas-client, sds_path: /etc/envoy/secrets/sso-nas-client.yaml}"
	cases := []struct {
		name          string
		body          string
		confidential  bool
		wantToken     Secret
		wantClientRef Secret
	}{
		{"public client (token_secret only)", validProfileYAML, false, token, token},
		{"client_secret without token_secret", withClientSecret(t, ref, true), true, Secret{}, client},
		{"client_secret takes precedence over token_secret", withClientSecret(t, ref, false), true, token, client},
		{"block style", replaceIn(t, "client_id: envoy-nas", "client_id: envoy-nas\n      client_secret:\n        name: sso-nas-client\n        sds_path: /etc/envoy/secrets//sso-nas-client.yaml"), true, token, client},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Parse("sso.yaml", []byte(profileDoc("p", tc.body)))
			p, err := cfg.Lookup("p")
			if err != nil {
				t.Fatalf("profile rejected: %v", err)
			}
			if p.HasClientSecret() != tc.confidential || p.TokenSecret != tc.wantToken || p.ClientSecretRef() != tc.wantClientRef {
				t.Errorf("HasClientSecret=%v TokenSecret=%+v ClientSecretRef=%+v, want %v %+v %+v",
					p.HasClientSecret(), p.TokenSecret, p.ClientSecretRef(), tc.confidential, tc.wantToken, tc.wantClientRef)
			}
		})
	}
}

func TestParseProfile_NeitherClientNorTokenSecret(t *testing.T) {
	body := replaceIn(t, "token_secret: {name: sso-nas-token, sds_path: /etc/envoy/secrets/sso-nas-token.yaml}", "")
	assertProfileRejected(t, "myprof", body, "token_secret is required", "unless credentials.client_secret is set")
}

func TestParseCrossProfileClientSecretConflict(t *testing.T) {
	a := withClientSecret(t, "{name: shared-client, sds_path: /etc/envoy/secrets/a-client.yaml}", true)
	b := strings.ReplaceAll(validProfileYAML, "redirect_uri_host: sso.", "redirect_uri_host: sso2.")
	b = strings.ReplaceAll(b, "sso-nas-", "sso-b-")
	cases := []struct {
		name, bBody string
		wantErr     bool
	}{
		// b's client_secret reuses a's client secret name with another file.
		{"client vs client", strings.Replace(b, "client_id: envoy-nas", "client_id: envoy-nas\n      client_secret: {name: shared-client, sds_path: /etc/envoy/secrets/b-client.yaml}", 1), true},
		// b's token_secret reuses a's client secret name with another file.
		{"token vs client", strings.Replace(b, "{name: sso-b-token,", "{name: shared-client,", 1), true},
		// Same name and same file is a shared secret, which is fine.
		{"same file", strings.Replace(b, "client_id: envoy-nas", "client_id: envoy-nas\n      client_secret: {name: shared-client, sds_path: /etc/envoy/secrets/a-client.yaml}", 1), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Parse("sso.yaml", []byte(profileDoc("a", a)+"  b:"+tc.bBody))
			if _, err := cfg.Lookup("a"); err != nil {
				t.Fatalf("first profile (sorted) must win: %v", err)
			}
			_, err := cfg.Lookup("b")
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("b rejected: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), `secret "shared-client"`) || !strings.Contains(err.Error(), `profile "a" already maps it to /etc/envoy/secrets/a-client.yaml`) {
				t.Fatalf("Lookup(b) = %v, want secret name conflict with profile a", err)
			}
		})
	}
}
