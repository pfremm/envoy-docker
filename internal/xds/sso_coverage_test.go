package xds

import (
	"reflect"
	"strings"
	"testing"

	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
)

// TestSSOSnapshot_ExactFilterOrderWithSecurityMiddleware pins the complete
// HTTPS filter chain when SSO and the existing security middlewares are both
// in use: HSTS header_mutation, one oauth2 filter per profile (sorted),
// jwt_authn, then the security chain unchanged, router last.
func TestSSOSnapshot_ExactFilterOrderWithSecurityMiddleware(t *testing.T) {
	// Envoy basic_auth cannot be disabled per route, so every router on the
	// listener carries the same security middleware stack.
	withSecurity := func(r model.Route) model.Route {
		r.Middlewares = []model.Middleware{
			{Name: "rl", RateLimit: &model.RateLimitMiddleware{Average: 10, Burst: 20, Period: "1s"}},
			{Name: "ba", BasicAuth: &model.BasicAuthMiddleware{Users: []string{"alice:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="}}},
			{Name: "allow", IPAllowList: &model.IPAllowListMiddleware{SourceRange: []string{"10.0.0.0/8"}}},
			{Name: "fa", ForwardAuth: &model.ForwardAuthMiddleware{Address: "auth.example.com:8443"}},
		}
		return r
	}
	secured := withSecurity(ssoRoute("secured", ""))
	httpCfg := model.HTTPConfiguration{Routes: map[string]model.Route{
		"zeta":    withSecurity(ssoRoute("zeta", "zeta")),
		"alpha":   withSecurity(ssoRoute("alpha", "alpha")),
		"secured": secured,
	}}
	snap, err := BuildSnapshotForConfig("1", httpCfg, ssoTestConfig(testSSOConfig(t, "zeta", "alpha")))
	if err != nil {
		t.Fatalf("BuildSnapshotForConfig: %v", err)
	}
	got := filterNames(httpsHCM(t, snap))
	want := []string{
		ssoHSTSFilterName,
		oauth2FilterName("alpha"),
		oauth2FilterName("zeta"),
		jwtAuthnFilterName,
		localRLFilterName,
		basicAuthFilterName,
		rbacFilterName,
		mutationFilterName,
		extAuthzFilterName,
		corsFilterName,
		wellknown.Router,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("HTTPS filter order:\n got %v\nwant %v", got, want)
	}

	// The same chain without SSO is exactly the tail after the SSO prefix.
	noSSO, err := BuildSnapshotForConfig("1", model.HTTPConfiguration{Routes: map[string]model.Route{"secured": secured}}, ssoTestConfig(nil))
	if err != nil {
		t.Fatal(err)
	}
	if got := filterNames(httpsHCM(t, noSSO)); !reflect.DeepEqual(got, want[4:]) {
		t.Fatalf("filter order without SSO = %v, want %v", got, want[4:])
	}
}

// TestSSOSnapshot_EveryRouteHasCompleteOverrides checks the override
// invariant across the whole SSO route configuration (including the
// error/catch-all and synthesized callback virtual hosts): every route
// carries a jwt_authn per-route config, disables every oauth2 filter except
// at most the one it uses, and an opted-in route enables its own oauth2
// filter and selects its jwt requirement by name.
func TestSSOSnapshot_EveryRouteHasCompleteOverrides(t *testing.T) {
	httpCfg := model.HTTPConfiguration{Routes: map[string]model.Route{
		"a":    ssoRoute("a", "alpha"),
		"b":    ssoRoute("b", "beta"),
		"pub1": ssoRoute("pub1", ""),
		"pub2": ssoRoute("pub2", ""),
	}}
	snap, err := BuildSnapshotForConfig("1", httpCfg, ssoTestConfig(testSSOConfig(t, "alpha", "beta")))
	if err != nil {
		t.Fatal(err)
	}
	profiles := []string{"alpha", "beta"}
	routes := routesByName(httpsRouteConfig(t, snap))
	for _, key := range sortedKeys(routes) {
		er := routes[key]
		var enabled []string
		for _, p := range profiles {
			if !oauth2Disabled(t, er, p) {
				enabled = append(enabled, p)
			}
		}
		if len(enabled) > 1 {
			t.Errorf("route %s enables several oauth2 filters: %v", key, enabled)
		}
		pr := jwtPerRoute(t, er)
		if len(enabled) == 0 && !pr.GetDisabled() {
			t.Errorf("route %s has every oauth2 filter disabled but jwt_authn enabled (%v)", key, pr)
		}
		if pr.GetDisabled() && pr.GetRequirementName() != "" {
			t.Errorf("route %s: jwt override both disabled and named", key)
		}
	}

	for route, profile := range map[string]string{"a": "alpha", "b": "beta"} {
		er := routes[route]
		if er == nil {
			t.Fatalf("route %q missing (routes %v)", route, sortedKeys(routes))
		}
		if oauth2Disabled(t, er, profile) {
			t.Errorf("opted route %s disables its own oauth2.%s", route, profile)
		}
		if pr := jwtPerRoute(t, er); pr.GetDisabled() || pr.GetRequirementName() != profile {
			t.Errorf("opted route %s jwt override = %v, want requirement_name %q", route, pr, profile)
		}
	}
	for _, route := range []string{"pub1", "pub2"} {
		er := routes[route]
		for _, p := range profiles {
			if !oauth2Disabled(t, er, p) {
				t.Errorf("unlabeled route %s does not disable oauth2.%s", route, p)
			}
		}
		if !jwtPerRoute(t, er).GetDisabled() {
			t.Errorf("unlabeled route %s does not disable jwt_authn", route)
		}
	}
}

// TestSSOSnapshot_FiltersScopedToListenerWithOptedRoutes: SSO filters are
// added per listener, only where an opted-in router is served.
func TestSSOSnapshot_FiltersScopedToListenerWithOptedRoutes(t *testing.T) {
	admin := ssoRoute("admin", "nas")
	admin.Entrypoints = []string{"admin"}
	httpCfg := model.HTTPConfiguration{Routes: map[string]model.Route{
		"admin": admin,
		"www":   ssoRoute("www", ""),
	}}
	cfg := ssoTestConfig(testSSOConfig(t, "nas"))
	cfg.HTTPEntrypoints = map[string]uint32{"admin": 8443}
	snap, err := BuildSnapshotForConfig("1", httpCfg, cfg)
	if err != nil {
		t.Fatal(err)
	}
	listeners := snap.GetResources(resourcev3.ListenerType)

	for _, n := range filterNames(httpsHCM(t, snap)) {
		if strings.HasPrefix(n, oauth2FilterPrefix) || n == jwtAuthnFilterName || n == ssoHSTSFilterName {
			t.Errorf("default HTTPS listener has SSO filter %q but serves no opted-in router", n)
		}
	}
	for _, er := range routesByName(httpsRouteConfig(t, snap)) {
		for k := range er.TypedPerFilterConfig {
			if strings.HasPrefix(k, oauth2FilterPrefix) || k == jwtAuthnFilterName {
				t.Errorf("route %q on the non-SSO listener carries SSO override %q", er.Name, k)
			}
		}
	}

	l, ok := listeners[httpsListenerName+"__admin"].(*listenerv3.Listener)
	if !ok {
		t.Fatalf("admin listener missing")
	}
	got := filterNames(decodeHCM(t, l))
	if len(got) < 4 || !reflect.DeepEqual(got[:3], []string{ssoHSTSFilterName, oauth2FilterName("nas"), jwtAuthnFilterName}) || got[len(got)-1] != wellknown.Router {
		t.Fatalf("admin listener filters = %v, want SSO prefix and router last", got)
	}
}

// TestHSTSWithSSOEnabled: HSTS is on every HTTPS route config exactly once
// (default and extra entrypoints) and never on the plain-HTTP redirect
// listener, also when SSO filters are active.
func TestHSTSWithSSOEnabled(t *testing.T) {
	admin := ssoRoute("admin", "nas")
	admin.Entrypoints = []string{"admin"}
	httpCfg := model.HTTPConfiguration{Routes: map[string]model.Route{
		"app":   ssoRoute("app", "nas"),
		"www":   ssoRoute("www", ""),
		"admin": admin,
	}}
	cfg := ssoTestConfig(testSSOConfig(t, "nas"))
	cfg.HTTPEntrypoints = map[string]uint32{"admin": 8443}
	snap, err := BuildSnapshotForConfig("1", httpCfg, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if names := filterNames(httpsHCM(t, snap)); names[0] != ssoHSTSFilterName {
		t.Fatalf("SSO not active on default listener: %v", names)
	}

	rcs := snap.GetResources(resourcev3.RouteType)
	for _, name := range []string{httpsRouteConfigName, httpsRouteConfigName + "__admin"} {
		rc, ok := rcs[name].(*routev3.RouteConfiguration)
		if !ok {
			t.Fatalf("route config %q missing", name)
		}
		var hsts int
		for _, h := range rc.ResponseHeadersToAdd {
			if h.GetHeader().GetKey() != "Strict-Transport-Security" {
				continue
			}
			hsts++
			if h.GetHeader().GetValue() != "max-age=31536000; includeSubDomains" || h.GetAppendAction().String() != "ADD_IF_ABSENT" {
				t.Errorf("%s HSTS header = %v", name, h)
			}
		}
		if hsts != 1 {
			t.Errorf("%s has %d HSTS headers, want exactly 1 (%v)", name, hsts, rc.ResponseHeadersToAdd)
		}
	}

	l := snap.GetResources(resourcev3.ListenerType)[httpListenerName].(*listenerv3.Listener)
	hcm := decodeHCM(t, l)
	if got := filterNames(hcm); !reflect.DeepEqual(got, []string{wellknown.Router}) {
		t.Errorf("plain-HTTP listener filters = %v, want router only (no SSO/HSTS filters)", got)
	}
	httpRC := hcm.GetRouteConfig()
	if len(httpRC.ResponseHeadersToAdd) != 0 {
		t.Errorf("plain-HTTP redirect route config sends headers: %v", httpRC.ResponseHeadersToAdd)
	}
	for _, vh := range httpRC.VirtualHosts {
		if len(vh.ResponseHeadersToAdd) != 0 {
			t.Errorf("plain-HTTP vhost %q sends headers: %v", vh.Name, vh.ResponseHeadersToAdd)
		}
		for _, er := range vh.Routes {
			if len(er.ResponseHeadersToAdd) != 0 || len(er.TypedPerFilterConfig) != 0 {
				t.Errorf("plain-HTTP route in %q carries headers/overrides", vh.Name)
			}
		}
	}
}
