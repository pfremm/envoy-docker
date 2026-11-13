package xds

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/protobuf/proto"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
	"github.com/bryanpfremm/envoy-control-plane/internal/sso"
)

// staticSSORoute is a static config router (no RouterName) opted into an SSO
// profile through the static file's sso field.
func staticSSORoute(subdomain, profile string, tls *model.UpstreamTLS) model.Route {
	return model.Route{
		Subdomain: subdomain, Source: model.SourceStatic, Origin: "static.yaml[" + subdomain + "]",
		Endpoints:  []model.Endpoint{{Address: "10.0.0.1", Port: 8080}},
		SSOProfile: profile, UpstreamTLS: tls,
	}
}

func buildStaticSSOSnapshot(t *testing.T, routes map[string]model.Route, ssoCfg *sso.Config) cachev3.ResourceSnapshot {
	t.Helper()
	snap, err := BuildSnapshotForConfig("1", model.HTTPConfiguration{Routes: routes}, ssoTestConfig(ssoCfg))
	if err != nil {
		t.Fatalf("BuildSnapshotForConfig: %v", err)
	}
	return snap
}

// TestStaticSSO_IdenticalToDockerLabel: a static router with sso: nas
// produces exactly the xDS a docker router labeled .sso=nas on the same
// subdomain does: the HTTPS listener's filter chain (sso_hsts, oauth2.nas,
// jwt_authn), the route configuration (per-route oauth2/jwt_authn overrides,
// callback vhost, HSTS response header) and the clusters (route + IdP), with
// an unlabeled router alongside staying public in both.
func TestStaticSSO_IdenticalToDockerLabel(t *testing.T) {
	ssoCfg := testSSOConfig(t, "nas")
	docker := buildStaticSSOSnapshot(t, map[string]model.Route{
		"dns": ssoRoute("dns", "nas"),
		"www": ssoRoute("www", ""),
	}, ssoCfg)
	static := buildStaticSSOSnapshot(t, map[string]model.Route{
		"dns": staticSSORoute("dns", "nas", nil),
		"www": ssoRoute("www", ""),
	}, ssoCfg)

	if d, s := httpsHCM(t, docker), httpsHCM(t, static); !proto.Equal(d, s) {
		t.Errorf("https listener HCM differs:\ndocker: %v\nstatic: %v", filterNames(d), filterNames(s))
	}
	if names := filterNames(httpsHCM(t, static)); len(names) < 3 || names[0] != ssoHSTSFilterName || names[1] != oauth2FilterName("nas") || names[2] != jwtAuthnFilterName {
		t.Errorf("static sso filter order = %v, want sso_hsts, oauth2.nas, jwt_authn first", names)
	}

	drc, src := httpsRouteConfig(t, docker), httpsRouteConfig(t, static)
	if !proto.Equal(drc, src) {
		t.Errorf("https route config differs:\ndocker: %v\nstatic: %v", drc, src)
	}
	dns := routesByName(src)["dns"]
	if dns == nil {
		t.Fatalf("static sso route missing (routes %v)", sortedKeys(routesByName(src)))
	}
	if oauth2Disabled(t, dns, "nas") {
		t.Error("static sso route disables its oauth2.nas")
	}
	if pr := jwtPerRoute(t, dns); pr.GetRequirementName() != "nas" {
		t.Errorf("static sso route jwt override = %v, want requirement_name nas", pr)
	}
	if www := routesByName(src)["www"]; !oauth2Disabled(t, www, "nas") || !jwtPerRoute(t, www).GetDisabled() {
		t.Error("unlabeled router next to a static sso router must stay public")
	}
	var hsts bool
	for _, h := range src.ResponseHeadersToAdd {
		hsts = hsts || h.GetHeader().GetKey() == "Strict-Transport-Security"
	}
	if !hsts {
		t.Error("https route config lacks the HSTS response header")
	}

	dClusters, sClusters := docker.GetResources(resourcev3.ClusterType), static.GetResources(resourcev3.ClusterType)
	if strings.Join(sortedAnyKeys(dClusters), ",") != strings.Join(sortedAnyKeys(sClusters), ",") {
		t.Fatalf("cluster names differ: docker %v, static %v", sortedAnyKeys(dClusters), sortedAnyKeys(sClusters))
	}
	for name := range dClusters {
		if !proto.Equal(dClusters[name], sClusters[name]) {
			t.Errorf("cluster %q differs between docker and static sso routers", name)
		}
	}
	if _, ok := sClusters["sso_idp"]; !ok {
		t.Error("static sso router did not emit the IdP cluster")
	}
}

// TestStaticSSO_UnknownProfileRejectsOnlyThatRouter: through the real merge
// flow (Merge of docker + static routes, then the snapshot build main runs),
// a static router whose sso profile is unknown, invalid or configured
// without SSO_CONFIG_PATH is dropped (not served public) with a warning that
// identifies it by origin/subdomain, while every other router stays.
func TestStaticSSO_UnknownProfileRejectsOnlyThatRouter(t *testing.T) {
	cases := map[string]*sso.Config{
		"no SSO_CONFIG_PATH": nil,
		"unknown profile":    testSSOConfig(t, "nas"),
		"invalid profile":    sso.Parse("sso.yaml", []byte("sso_profiles:\n  missing:\n    issuer: x\n")),
	}
	for name, ssoCfg := range cases {
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logs, nil))
			merged := Merge(
				map[string]model.Route{"app": ssoRoute("app", "")},
				map[string]model.Route{
					"bad":  staticSSORoute("bad", "missing", nil),
					"good": staticRoute("good"),
				}, logger)
			cfg := ssoTestConfig(ssoCfg)
			cfg.Logger = logger
			snap, err := BuildSnapshotForConfig("1", model.HTTPConfiguration{Routes: merged}, cfg)
			if err != nil {
				t.Fatalf("snapshot must still build: %v", err)
			}
			routes := routesByName(httpsRouteConfig(t, snap))
			if _, ok := routes["bad"]; ok {
				t.Error("static router with unusable sso profile must be rejected, not served public")
			}
			for _, keep := range []string{"app", "good"} {
				if _, ok := routes[keep]; !ok {
					t.Errorf("router %q must be unaffected (routes %v)", keep, sortedKeys(routes))
				}
			}
			if _, ok := snap.GetResources(resourcev3.ClusterType)["bad"]; ok {
				t.Error("rejected static router must not get a cluster")
			}
			out := logs.String()
			for _, want := range []string{"sso profile cannot be applied", "source=static", "subdomain=bad", "origin=static.yaml[bad]", "sso=missing"} {
				if !strings.Contains(out, want) {
					t.Errorf("rejection log lacks %q:\n%s", want, out)
				}
			}
		})
	}
}

// TestStaticSSO_PublicStaticNextToOptedStatic: an unlabeled static router
// keeps disabled oauth2/jwt_authn overrides beside an opted-in static one.
func TestStaticSSO_PublicStaticNextToOptedStatic(t *testing.T) {
	snap := buildStaticSSOSnapshot(t, map[string]model.Route{
		"dns":     staticSSORoute("dns", "nas", nil),
		"truenas": staticRoute("truenas"),
	}, testSSOConfig(t, "nas"))
	routes := routesByName(httpsRouteConfig(t, snap))
	if dns := routes["dns"]; oauth2Disabled(t, dns, "nas") || jwtPerRoute(t, dns).GetRequirementName() != "nas" {
		t.Error("opted-in static router must require oauth2.nas and jwt nas")
	}
	if pub := routes["truenas"]; !oauth2Disabled(t, pub, "nas") || !jwtPerRoute(t, pub).GetDisabled() {
		t.Errorf("unlabeled static router must stay public, got keys %v", keys(pub.TypedPerFilterConfig))
	}
}

// TestStaticSSO_ApexWithCallbackHost: an apex "@" static router with sso is
// protected on its BASE_DOMAIN vhost; a profile whose redirect_uri_host is
// BASE_DOMAIN gets its callback/signout routes prepended to that vhost
// rather than a synthesized one.
func TestStaticSSO_ApexWithCallbackHost(t *testing.T) {
	ssoCfg := sso.Parse("sso.yaml", []byte("sso_profiles:"+ssoProfileYAML("nas", "example.com")))
	if ssoCfg.LoadErr != nil || len(ssoCfg.Invalid) != 0 {
		t.Fatalf("test SSO config invalid: %v %v", ssoCfg.LoadErr, ssoCfg.Invalid)
	}
	apex := apexStaticRoute(&model.UpstreamTLS{InsecureSkipVerify: true})
	apex.SSOProfile = "nas"
	snap := buildStaticSSOSnapshot(t, map[string]model.Route{
		model.ApexSubdomain: apex,
		"truenas":           staticRoute("truenas"),
	}, ssoCfg)
	rc := httpsRouteConfig(t, snap)
	if err := rc.ValidateAll(); err != nil {
		t.Fatalf("route config fails proto validation: %v", err)
	}
	for _, vh := range rc.VirtualHosts {
		if strings.HasPrefix(vh.Name, ssoCallbackVHPrefix) {
			t.Errorf("callback vhost %q synthesized although the apex vhost serves example.com", vh.Name)
		}
	}
	vh := vhostByDomain(rc, "example.com")
	if vh == nil || len(vh.Routes) != 3 {
		t.Fatalf("apex vhost = %v, want callback + signout + apex route", vh)
	}
	for i, path := range []string{"/oauth2/callback", "/oauth2/signout"} {
		er := vh.Routes[i]
		if er.Match.GetPath() != path || oauth2Disabled(t, er, "nas") || !jwtPerRoute(t, er).GetDisabled() {
			t.Errorf("apex vhost route %d = %v, want %s with oauth2.nas enabled and jwt disabled", i, er.Match, path)
		}
	}
	app := vh.Routes[2]
	if app.GetRoute().GetCluster() != model.ApexSubdomain || oauth2Disabled(t, app, "nas") || jwtPerRoute(t, app).GetRequirementName() != "nas" {
		t.Errorf("apex route %v: want apex cluster with oauth2.nas and jwt requirement nas", app)
	}
	if pub := vhostByDomain(rc, "truenas.example.com"); pub == nil || !jwtPerRoute(t, pub.Routes[0]).GetDisabled() {
		t.Error("unlabeled static router must stay public next to the apex sso router")
	}
	if names := filterNames(httpsHCM(t, snap)); len(names) < 2 || names[1] != oauth2FilterName("nas") {
		t.Errorf("https filters = %v, want oauth2.nas", names)
	}
}

// TestStaticSSO_HTTPSUpstreamClusterUnchanged: sso does not alter an https
// static router's upstream cluster: with insecure_skip_verify (crafty/dns
// style) or verification on, the cluster is identical with and without sso.
func TestStaticSSO_HTTPSUpstreamClusterUnchanged(t *testing.T) {
	for name, tls := range map[string]*model.UpstreamTLS{
		"insecure_skip_verify": {InsecureSkipVerify: true},
		"verify":               {},
	} {
		t.Run(name, func(t *testing.T) {
			routes := map[string]model.Route{
				"dns":    staticSSORoute("dns", "nas", tls),
				"crafty": staticSSORoute("crafty", "", tls),
			}
			snap := buildStaticSSOSnapshot(t, routes, testSSOConfig(t, "nas"))
			clusters := snap.GetResources(resourcev3.ClusterType)
			for sub, route := range routes {
				c, ok := clusters[sub].(*clusterv3.Cluster)
				if !ok {
					t.Fatalf("cluster %q missing", sub)
				}
				route.SSOProfile = ""
				if want := buildRouteCluster(route, "example.com"); !proto.Equal(c, want) {
					t.Errorf("cluster %q = %v, want the sso-free https cluster %v", sub, c, want)
				}
				utls := upstreamTLSContext(t, c)
				if utls.GetSni() != sub+".example.com" {
					t.Errorf("cluster %q SNI = %q, want %s.example.com", sub, utls.GetSni(), sub)
				}
			}
			rcRoutes := routesByName(httpsRouteConfig(t, snap))
			if jwtPerRoute(t, rcRoutes["dns"]).GetRequirementName() != "nas" || !jwtPerRoute(t, rcRoutes["crafty"]).GetDisabled() {
				t.Error("https static routers: dns must require nas, crafty must stay public")
			}
		})
	}
}
