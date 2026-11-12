package xds

import (
	"bytes"
	"log/slog"
	"reflect"
	"sort"
	"strings"
	"testing"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	headermutationv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_mutation/v3"
	jwtauthnv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	oauth2v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/oauth2/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/protobuf/proto"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
	"github.com/bryanpfremm/envoy-control-plane/internal/rule"
	"github.com/bryanpfremm/envoy-control-plane/internal/sso"
)

func ssoProfileYAML(name, host string) string {
	return `
  ` + name + `:
    redirect_uri_host: ` + host + `
    cookie_domain: example.com
    issuer: https://auth.example.com/application/o/` + name + `/
    authorization_endpoint: https://auth.example.com/application/o/authorize/
    token_endpoint: {cluster: sso_idp, uri: https://auth.example.com/application/o/token/, timeout: 5s}
    jwks: {cluster: sso_idp, uri: https://auth.example.com/application/o/` + name + `/jwks/}
    credentials:
      client_id: envoy-` + name + `
    hmac_secret:  {name: sso-` + name + `-hmac,  sds_path: /etc/envoy/secrets/sso-` + name + `-hmac.yaml}
    token_secret: {name: sso-` + name + `-token, sds_path: /etc/envoy/secrets/sso-` + name + `-token.yaml}
`
}

func testSSOConfig(t *testing.T, profiles ...string) *sso.Config {
	t.Helper()
	doc := "sso_profiles:"
	for _, p := range profiles {
		doc += ssoProfileYAML(p, "sso-"+p+".example.com")
	}
	cfg := sso.Parse("sso.yaml", []byte(doc))
	if cfg.LoadErr != nil || len(cfg.Invalid) != 0 {
		t.Fatalf("test SSO config invalid: %v %v", cfg.LoadErr, cfg.Invalid)
	}
	return cfg
}

func ssoRoute(name, profile string) model.Route {
	return model.Route{
		Subdomain:  name,
		RouterName: name,
		Endpoints:  []model.Endpoint{{Address: "10.0.0.1", Port: 8080}},
		Source:     model.SourceDocker,
		SSOProfile: profile,
	}
}

func ssoTestConfig(ssoCfg *sso.Config) Config {
	return Config{BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443, CertSecretName: "cert", ACMESDSClusterName: "acme", SSO: ssoCfg}
}

func httpsRouteConfig(t *testing.T, snap cachev3.ResourceSnapshot) *routev3.RouteConfiguration {
	t.Helper()
	rc, ok := snap.GetResources(resourcev3.RouteType)[httpsRouteConfigName].(*routev3.RouteConfiguration)
	if !ok {
		t.Fatalf("no %s route config", httpsRouteConfigName)
	}
	return rc
}

// routesByName indexes generated routes by route name; unnamed routes
// (SSO callback routes) are keyed by "<vhost><path>".
func routesByName(rc *routev3.RouteConfiguration) map[string]*routev3.Route {
	out := map[string]*routev3.Route{}
	for _, vh := range rc.VirtualHosts {
		for _, er := range vh.Routes {
			key := er.Name
			if key == "" {
				key = vh.Name + er.Match.GetPath() + er.Match.GetPrefix()
			}
			out[key] = er
		}
	}
	return out
}

func sortedKeys(m map[string]*routev3.Route) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func jwtPerRoute(t *testing.T, er *routev3.Route) *jwtauthnv3.PerRouteConfig {
	t.Helper()
	anyCfg, ok := er.TypedPerFilterConfig[jwtAuthnFilterName]
	if !ok {
		t.Fatalf("route %q has no jwt_authn per-route config (keys %v)", er.Name, keys(er.TypedPerFilterConfig))
	}
	var pr jwtauthnv3.PerRouteConfig
	unmarshalAny(t, anyCfg, &pr)
	return &pr
}

func oauth2Disabled(t *testing.T, er *routev3.Route, profile string) bool {
	t.Helper()
	anyCfg, ok := er.TypedPerFilterConfig[oauth2FilterName(profile)]
	if !ok {
		return false
	}
	var fc routev3.FilterConfig
	unmarshalAny(t, anyCfg, &fc)
	if !fc.Disabled {
		t.Fatalf("route %q oauth2 override for %q is present but not disabled", er.Name, profile)
	}
	return true
}

func TestSSOSnapshot_OptedAndPublicRouters(t *testing.T) {
	httpCfg := model.HTTPConfiguration{Routes: map[string]model.Route{
		"app": ssoRoute("app", "nas"),
		"www": ssoRoute("www", ""),
	}}
	snap, err := BuildSnapshotForConfig("1", httpCfg, ssoTestConfig(testSSOConfig(t, "nas")))
	if err != nil {
		t.Fatalf("BuildSnapshotForConfig: %v", err)
	}

	hcm := httpsHCM(t, snap)
	names := filterNames(hcm)
	t.Logf("https_listener http_filters: %v", names)
	if len(names) < 4 || names[0] != ssoHSTSFilterName || names[1] != oauth2FilterName("nas") || names[2] != jwtAuthnFilterName || names[len(names)-1] != "envoy.filters.http.router" {
		t.Fatalf("filter order = %v, want sso_hsts, oauth2.nas, jwt_authn first and router last", names)
	}

	// The oauth2 filter's own redirects bypass the route config's
	// response_headers_to_add; the leading header_mutation filter adds HSTS.
	var hsts headermutationv3.HeaderMutation
	unmarshalAny(t, hcm.HttpFilters[0].GetTypedConfig(), &hsts)
	if err := hsts.ValidateAll(); err != nil {
		t.Fatalf("header_mutation config fails proto validation: %v", err)
	}
	if rm := hsts.GetMutations().GetResponseMutations(); len(rm) != 1 || rm[0].GetAppend().GetHeader().GetKey() != "Strict-Transport-Security" ||
		rm[0].GetAppend().GetAppendAction().String() != "ADD_IF_ABSENT" {
		t.Errorf("unexpected sso_hsts config: %v", &hsts)
	}

	var oauth oauth2v3.OAuth2
	unmarshalAny(t, hcm.HttpFilters[1].GetTypedConfig(), &oauth)
	if err := oauth.ValidateAll(); err != nil {
		t.Fatalf("oauth2 config fails proto validation: %v", err)
	}
	oc := oauth.Config
	if oc.RedirectUri != "https://sso-nas.example.com/oauth2/callback" || !oc.ForwardBearerToken ||
		oc.Credentials.CookieDomain != "example.com" || oc.Credentials.GetHmacSecret().GetSdsConfig().GetPathConfigSource().GetPath() != "/etc/envoy/secrets/sso-nas-hmac.yaml" ||
		oc.Credentials.TokenSecret.GetName() != "sso-nas-token" || !reflect.DeepEqual(oc.AuthScopes, []string{"openid", "email"}) ||
		oc.PassThroughMatcher[0].GetName() != "authorization" || oc.PassThroughMatcher[0].GetStringMatch().GetPrefix() != "Bearer " ||
		oc.TokenEndpoint.GetCluster() != "sso_idp" {
		t.Errorf("unexpected oauth2 config: %v", oc)
	}
	var jwt jwtauthnv3.JwtAuthentication
	unmarshalAny(t, hcm.HttpFilters[2].GetTypedConfig(), &jwt)
	if err := jwt.ValidateAll(); err != nil {
		t.Fatalf("jwt_authn config fails proto validation: %v", err)
	}
	prov := jwt.Providers["nas"]
	if prov == nil || !prov.Forward || prov.GetRemoteJwks().GetHttpUri().GetCluster() != "sso_idp" ||
		prov.GetRemoteJwks().GetCacheDuration().AsDuration().Seconds() != 300 || jwt.RequirementMap["nas"].GetProviderName() != "nas" {
		t.Errorf("unexpected jwt_authn config: %v", &jwt)
	}

	rc := httpsRouteConfig(t, snap)
	if err := rc.ValidateAll(); err != nil {
		t.Fatalf("route config fails proto validation: %v", err)
	}
	routes := routesByName(rc)
	for _, name := range sortedKeys(routes) {
		t.Logf("route %-40s typed_per_filter_config keys: %v", name, sortedAnyKeys(routes[name].TypedPerFilterConfig))
	}

	app := routes["app"]
	if oauth2Disabled(t, app, "nas") {
		t.Errorf("opted route must not disable its oauth2 filter")
	}
	if got := jwtPerRoute(t, app).GetRequirementName(); got != "nas" {
		t.Errorf("app jwt requirement = %q, want nas", got)
	}
	www := routes["www"]
	if !oauth2Disabled(t, www, "nas") || !jwtPerRoute(t, www).GetDisabled() {
		t.Errorf("public route must disable oauth2.nas and jwt_authn, got keys %v", keys(www.TypedPerFilterConfig))
	}

	// Callback host synthesized: callback/signout enable oauth2.nas only,
	// jwt disabled; the catch-all 404 disables everything.
	cbVH := ssoCallbackVHPrefix + "sso-nas.example.com"
	for _, path := range []string{"/oauth2/callback", "/oauth2/signout"} {
		er := routes[cbVH+path]
		if er == nil {
			t.Fatalf("missing callback route %s%s (routes %v)", cbVH, path, sortedKeys(routes))
		}
		if oauth2Disabled(t, er, "nas") || !jwtPerRoute(t, er).GetDisabled() {
			t.Errorf("callback route %s: want oauth2.nas enabled and jwt disabled", path)
		}
	}
	if fallback := routes[cbVH+"/"]; fallback == nil || !oauth2Disabled(t, fallback, "nas") {
		t.Errorf("callback vhost catch-all must exist with oauth2 disabled")
	}

	// IdP cluster generated with upstream TLS + SNI.
	c, ok := snap.GetResources(resourcev3.ClusterType)["sso_idp"].(*clusterv3.Cluster)
	if !ok {
		t.Fatalf("sso_idp cluster missing")
	}
	var utls tlsv3.UpstreamTlsContext
	unmarshalAny(t, c.TransportSocket.GetTypedConfig(), &utls)
	if utls.Sni != "auth.example.com" || c.GetType() != clusterv3.Cluster_STRICT_DNS {
		t.Errorf("sso_idp cluster: sni=%q type=%v", utls.Sni, c.GetType())
	}
	// SNI/SAN are pinned in the TLS context; the deprecated
	// upstream_http_protocol_options would only be a no-op here.
	if c.UpstreamHttpProtocolOptions != nil {
		t.Errorf("sso_idp cluster sets deprecated upstream_http_protocol_options: %v", c.UpstreamHttpProtocolOptions)
	}
	if port := c.LoadAssignment.Endpoints[0].LbEndpoints[0].GetEndpoint().Address.GetSocketAddress().GetPortValue(); port != 443 {
		t.Errorf("sso_idp port = %d, want 443", port)
	}
}

func sortedAnyKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestSSOSnapshot_NoOptedRoutersLeavesListenerUnchanged(t *testing.T) {
	httpCfg := model.HTTPConfiguration{Routes: map[string]model.Route{"www": ssoRoute("www", "")}}
	with, err := BuildSnapshotForConfig("1", httpCfg, ssoTestConfig(testSSOConfig(t, "nas")))
	if err != nil {
		t.Fatal(err)
	}
	without, err := BuildSnapshotForConfig("1", httpCfg, ssoTestConfig(nil))
	if err != nil {
		t.Fatal(err)
	}
	if a, b := filterNames(httpsHCM(t, with)), filterNames(httpsHCM(t, without)); !reflect.DeepEqual(a, b) {
		t.Fatalf("filters differ with unused SSO config: %v vs %v", a, b)
	}
	for _, n := range filterNames(httpsHCM(t, with)) {
		if strings.HasPrefix(n, oauth2FilterPrefix) || n == jwtAuthnFilterName || n == ssoHSTSFilterName {
			t.Fatalf("unexpected SSO filter %q", n)
		}
	}
	for _, er := range routesByName(httpsRouteConfig(t, with)) {
		if _, ok := er.TypedPerFilterConfig[jwtAuthnFilterName]; ok {
			t.Fatalf("route %q has jwt override without SSO", er.Name)
		}
	}
	if _, ok := with.GetResources(resourcev3.ClusterType)["sso_idp"]; ok {
		t.Fatalf("unused profile must not emit its IdP cluster")
	}
}

func TestSSOSnapshot_RejectsOnlyUnusableSSORouters(t *testing.T) {
	cases := map[string]*sso.Config{
		"no SSO_CONFIG_PATH": nil,
		"unknown profile":    testSSOConfig(t, "other"),
		"file failed":        sso.Parse("sso.yaml", []byte("sso_profiles: [x]")),
		"invalid profile":    sso.Parse("sso.yaml", []byte("sso_profiles:\n  nas:\n    issuer: x\n")),
	}
	for name, ssoCfg := range cases {
		t.Run(name, func(t *testing.T) {
			httpCfg := model.HTTPConfiguration{Routes: map[string]model.Route{
				"app": ssoRoute("app", "nas"),
				"www": ssoRoute("www", ""),
			}}
			snap, err := BuildSnapshotForConfig("1", httpCfg, ssoTestConfig(ssoCfg))
			if err != nil {
				t.Fatalf("snapshot must still build: %v", err)
			}
			routes := routesByName(httpsRouteConfig(t, snap))
			if _, ok := routes["app"]; ok {
				t.Errorf("router with unusable sso profile must be rejected, not served public")
			}
			if _, ok := routes["www"]; !ok {
				t.Errorf("public router must be unaffected")
			}
			if _, ok := snap.GetResources(resourcev3.ClusterType)["app"]; ok {
				t.Errorf("rejected router must not get a cluster")
			}
		})
	}
}

func TestSSOSnapshot_MultipleProfilesOnOneListener(t *testing.T) {
	httpCfg := model.HTTPConfiguration{Routes: map[string]model.Route{
		"a":   ssoRoute("a", "beta"),
		"b":   ssoRoute("b", "alpha"),
		"pub": ssoRoute("pub", ""),
	}}
	snap, err := BuildSnapshotForConfig("1", httpCfg, ssoTestConfig(testSSOConfig(t, "alpha", "beta")))
	if err != nil {
		t.Fatal(err)
	}
	names := filterNames(httpsHCM(t, snap))
	want := []string{ssoHSTSFilterName, oauth2FilterName("alpha"), oauth2FilterName("beta"), jwtAuthnFilterName}
	if !reflect.DeepEqual(names[:4], want) {
		t.Fatalf("filters = %v, want prefix %v", names, want)
	}
	routes := routesByName(httpsRouteConfig(t, snap))
	if !oauth2Disabled(t, routes["a"], "alpha") || oauth2Disabled(t, routes["a"], "beta") || jwtPerRoute(t, routes["a"]).GetRequirementName() != "beta" {
		t.Errorf("route a (beta): wrong overrides %v", keys(routes["a"].TypedPerFilterConfig))
	}
	if oauth2Disabled(t, routes["b"], "alpha") || !oauth2Disabled(t, routes["b"], "beta") || jwtPerRoute(t, routes["b"]).GetRequirementName() != "alpha" {
		t.Errorf("route b (alpha): wrong overrides %v", keys(routes["b"].TypedPerFilterConfig))
	}
	if !oauth2Disabled(t, routes["pub"], "alpha") || !oauth2Disabled(t, routes["pub"], "beta") || !jwtPerRoute(t, routes["pub"]).GetDisabled() {
		t.Errorf("public route must disable every SSO filter")
	}
}

func TestSSOSnapshot_WholeVirtualHostIsProtected(t *testing.T) {
	// Two routers on one host; only one opts in. The other must not expose
	// part of the SSO subdomain.
	sso1 := ssoRoute("app", "nas")
	sso1.Rule = mustRule(t, "Host(app.example.com) && PathPrefix(/admin)")
	sso1.RuleExpr = "Host(app.example.com) && PathPrefix(/admin)"
	pub := ssoRoute("app-public", "")
	pub.Subdomain = "app2"
	pub.Rule = mustRule(t, "Host(app.example.com)")
	pub.RuleExpr = "Host(app.example.com)"
	httpCfg := model.HTTPConfiguration{Routes: map[string]model.Route{"app": sso1, "app2": pub}}
	snap, err := BuildSnapshotForConfig("1", httpCfg, ssoTestConfig(testSSOConfig(t, "nas")))
	if err != nil {
		t.Fatal(err)
	}
	er := routesByName(httpsRouteConfig(t, snap))["app-public"]
	if er == nil || oauth2Disabled(t, er, "nas") || jwtPerRoute(t, er).GetRequirementName() != "nas" {
		t.Fatalf("unlabeled router sharing an SSO host must be protected")
	}
}

func TestSSOSnapshot_LegacyBuildPath(t *testing.T) {
	routes := map[string]model.Route{"app": ssoRoute("app", "nas"), "www": ssoRoute("www", "")}
	snap, err := BuildSnapshot("1", routes, ssoTestConfig(testSSOConfig(t, "nas")))
	if err != nil {
		t.Fatal(err)
	}
	names := filterNames(httpsHCM(t, snap))
	if names[0] != ssoHSTSFilterName || names[1] != oauth2FilterName("nas") || names[2] != jwtAuthnFilterName {
		t.Fatalf("filters = %v", names)
	}
	if _, ok := snap.GetResources(resourcev3.ClusterType)["sso_idp"]; !ok {
		t.Fatalf("sso_idp cluster missing")
	}
}

func TestSSOSnapshot_IdPClusterCollisionRejected(t *testing.T) {
	httpCfg := model.HTTPConfiguration{Routes: map[string]model.Route{
		"app":     ssoRoute("app", "nas"),
		"sso_idp": ssoRoute("sso_idp", ""),
	}}
	_, err := BuildSnapshotForConfig("1", httpCfg, ssoTestConfig(testSSOConfig(t, "nas")))
	if err == nil || !strings.Contains(err.Error(), "SSO profile IdP cluster") {
		t.Fatalf("err = %v, want cluster collision", err)
	}
}

func TestHSTSOnHTTPSOnly(t *testing.T) {
	httpCfg := model.HTTPConfiguration{Routes: map[string]model.Route{"www": ssoRoute("www", "")}}
	for name, build := range map[string]func() (cachev3.ResourceSnapshot, error){
		"config": func() (cachev3.ResourceSnapshot, error) {
			return BuildSnapshotForConfig("1", httpCfg, ssoTestConfig(nil))
		},
		"legacy": func() (cachev3.ResourceSnapshot, error) {
			return BuildSnapshot("1", httpCfg.Routes, ssoTestConfig(nil))
		},
	} {
		t.Run(name, func(t *testing.T) {
			snap, err := build()
			if err != nil {
				t.Fatal(err)
			}
			rc := httpsRouteConfig(t, snap)
			if len(rc.ResponseHeadersToAdd) != 1 {
				t.Fatalf("https response_headers_to_add = %v", rc.ResponseHeadersToAdd)
			}
			h := rc.ResponseHeadersToAdd[0]
			if h.Header.Key != "Strict-Transport-Security" || h.Header.Value != "max-age=31536000; includeSubDomains" || h.AppendAction.String() != "ADD_IF_ABSENT" {
				t.Errorf("HSTS header = %v", h)
			}
			l := snap.GetResources(resourcev3.ListenerType)[httpListenerName].(*listenerv3.Listener)
			httpRC := decodeHCM(t, l).GetRouteConfig()
			if len(httpRC.ResponseHeadersToAdd) != 0 {
				t.Errorf("plain-HTTP redirect listener must not send HSTS")
			}
			for _, vh := range httpRC.VirtualHosts {
				if len(vh.ResponseHeadersToAdd) != 0 {
					t.Errorf("plain-HTTP vhost %q must not send HSTS", vh.Name)
				}
			}
		})
	}
}

func mustRule(t *testing.T, expr string) model.Rule {
	t.Helper()
	r, err := rule.Parse(expr)
	if err != nil {
		t.Fatalf("rule.Parse(%q): %v", expr, err)
	}
	return r
}

// expectedFileSDS is the SdsSecretConfig shape every SSO secret reference
// must have: a name plus a v3 path_config_source pointing at the file.
func expectedFileSDS(name, path string) *tlsv3.SdsSecretConfig {
	return &tlsv3.SdsSecretConfig{
		Name: name,
		SdsConfig: &corev3.ConfigSource{
			ResourceApiVersion:    corev3.ApiVersion_V3,
			ConfigSourceSpecifier: &corev3.ConfigSource_PathConfigSource{PathConfigSource: &corev3.PathConfigSource{Path: path}},
		},
	}
}

func TestSSOSnapshot_ClientSecretEmittedAsTokenSecret(t *testing.T) {
	const clientLine = "      client_id: envoy-nas\n      client_secret: {name: sso-nas-client, sds_path: /etc/envoy/secrets/sso-nas-client.yaml}\n"
	const tokenLine = "    token_secret: {name: sso-nas-token, sds_path: /etc/envoy/secrets/sso-nas-token.yaml}\n"
	public := ssoProfileYAML("nas", "sso-nas.example.com")
	both := strings.Replace(public, "      client_id: envoy-nas\n", clientLine, 1)
	clientOnly := strings.Replace(both, tokenLine, "", 1)
	if both == public || clientOnly == both {
		t.Fatalf("fixture edits did not apply")
	}
	token := expectedFileSDS("sso-nas-token", "/etc/envoy/secrets/sso-nas-token.yaml")
	client := expectedFileSDS("sso-nas-client", "/etc/envoy/secrets/sso-nas-client.yaml")
	cases := []struct {
		name, profile string
		want          *tlsv3.SdsSecretConfig
	}{
		{"public client unchanged", public, token},
		{"client_secret takes precedence", both, client},
		{"client_secret only", clientOnly, client},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ssoCfg := sso.Parse("sso.yaml", []byte("sso_profiles:"+tc.profile))
			if ssoCfg.LoadErr != nil || len(ssoCfg.Invalid) != 0 {
				t.Fatalf("SSO config invalid: %v %v", ssoCfg.LoadErr, ssoCfg.Invalid)
			}
			snap, err := BuildSnapshotForConfig("1", model.HTTPConfiguration{Routes: map[string]model.Route{"app": ssoRoute("app", "nas")}}, ssoTestConfig(ssoCfg))
			if err != nil {
				t.Fatalf("BuildSnapshotForConfig: %v", err)
			}
			hcm := httpsHCM(t, snap)
			var oauth oauth2v3.OAuth2
			unmarshalAny(t, hcm.HttpFilters[1].GetTypedConfig(), &oauth)
			if err := oauth.ValidateAll(); err != nil {
				t.Fatalf("oauth2 config fails proto validation: %v", err)
			}
			creds := oauth.Config.GetCredentials()
			if !proto.Equal(creds.GetTokenSecret(), tc.want) {
				t.Errorf("token_secret = %v, want %v", creds.GetTokenSecret(), tc.want)
			}
			if hmac := expectedFileSDS("sso-nas-hmac", "/etc/envoy/secrets/sso-nas-hmac.yaml"); !proto.Equal(creds.GetHmacSecret(), hmac) {
				t.Errorf("hmac_secret = %v, want %v", creds.GetHmacSecret(), hmac)
			}
		})
	}
}

func TestSSOSnapshot_BadClientSecretDropsOnlyThatProfile(t *testing.T) {
	bad := strings.Replace(ssoProfileYAML("bad", "sso-bad.example.com"), "      client_id: envoy-bad\n",
		"      client_id: envoy-bad\n      client_secret: \"inline-value\"\n", 1)
	ssoCfg := sso.Parse("sso.yaml", []byte("sso_profiles:"+ssoProfileYAML("nas", "sso-nas.example.com")+bad))
	if _, ok := ssoCfg.Invalid["bad"]; !ok || len(ssoCfg.Profiles) != 1 {
		t.Fatalf("want only profile bad invalid, got profiles=%v invalid=%v", ssoCfg.SortedProfileNames(), ssoCfg.Invalid)
	}
	var logs bytes.Buffer
	cfg := ssoTestConfig(ssoCfg)
	cfg.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	snap, err := BuildSnapshotForConfig("1", model.HTTPConfiguration{Routes: map[string]model.Route{
		"app":  ssoRoute("app", "nas"),
		"evil": ssoRoute("evil", "bad"),
		"www":  ssoRoute("www", ""),
	}}, cfg)
	if err != nil {
		t.Fatalf("snapshot must still build: %v", err)
	}
	routes := routesByName(httpsRouteConfig(t, snap))
	if _, ok := routes["evil"]; ok {
		t.Errorf("router referencing the invalid profile must be rejected, not served public")
	}
	for _, r := range []string{"app", "www"} {
		if _, ok := routes[r]; !ok {
			t.Errorf("router %s must be unaffected", r)
		}
	}
	for _, want := range []string{"skipping router: sso profile cannot be applied", "router=evil", `sso profile \"bad\" is invalid`, "inline secrets are not supported"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("warning log missing %q:\n%s", want, logs.String())
		}
	}
}
