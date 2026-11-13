package xds

import (
	"reflect"
	"strings"
	"testing"

	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
	"github.com/bryanpfremm/envoy-control-plane/internal/rule"
)

// apexStaticRoute is a static route for the apex BASE_DOMAIN (subdomain "@").
func apexStaticRoute(tls *model.UpstreamTLS) model.Route {
	return model.Route{
		Subdomain: model.ApexSubdomain, Source: model.SourceStatic, Origin: "static.yaml[0]", UpstreamTLS: tls,
		Endpoints: []model.Endpoint{{Address: "10.10.2.42", Port: 443}},
	}
}

func staticRoute(subdomain string) model.Route {
	return model.Route{
		Subdomain: subdomain, Source: model.SourceStatic, Origin: "static.yaml[1]",
		Endpoints: []model.Endpoint{{Address: "10.10.2.43", Port: 80}},
	}
}

// ruleDockerRoute is a rule-based docker router: its presence switches the
// route configuration to the shape with the legacy "*" catch-all vhost.
func ruleDockerRoute(t *testing.T, name, profile string) model.Route {
	t.Helper()
	expr := "Host(" + name + ".example.com) && PathPrefix(/)"
	r, err := rule.Parse(expr)
	if err != nil {
		t.Fatal(err)
	}
	route := ssoRoute(name, profile)
	route.Rule, route.RuleExpr = r, expr
	return route
}

func vhostByDomain(rc *routev3.RouteConfiguration, domain string) *routev3.VirtualHost {
	for _, vh := range rc.VirtualHosts {
		for _, d := range vh.Domains {
			if d == domain {
				return vh
			}
		}
	}
	return nil
}

// TestApexStaticRoute_VirtualHost: a static "@" route is served by a virtual
// host whose domains are exactly BASE_DOMAIN (port tolerance comes from the
// route configuration's ignore_port_in_host_matching, as for every vhost),
// never "@.<base>", both in the legacy-only shape and next to rule-based
// docker routes, where its catch-all copy is constrained to :authority
// BASE_DOMAIN.
func TestApexStaticRoute_VirtualHost(t *testing.T) {
	for _, withRules := range []bool{false, true} {
		name := "legacy only"
		if withRules {
			name = "with rule-based docker routes"
		}
		t.Run(name, func(t *testing.T) {
			routes := map[string]model.Route{
				model.ApexSubdomain: apexStaticRoute(&model.UpstreamTLS{InsecureSkipVerify: true}),
				"nas":               staticRoute("nas"),
			}
			if withRules {
				routes["app"] = ruleDockerRoute(t, "app", "")
			}
			snap, err := BuildSnapshotForConfig("1", model.HTTPConfiguration{Routes: routes}, ssoTestConfig(nil))
			if err != nil {
				t.Fatalf("BuildSnapshotForConfig: %v", err)
			}
			rc := httpsRouteConfig(t, snap)
			if !rc.IgnorePortInHostMatching {
				t.Error("ignore_port_in_host_matching off: apex would not match with a :port")
			}

			vh := vhostByDomain(rc, "example.com")
			if vh == nil {
				t.Fatalf("no virtual host for the apex example.com")
			}
			if !reflect.DeepEqual(vh.Domains, []string{"example.com"}) {
				t.Errorf("apex vhost domains = %v, want exactly [example.com]", vh.Domains)
			}
			if len(vh.Routes) != 1 || vh.Routes[0].GetRoute().GetCluster() != model.ApexSubdomain {
				t.Errorf("apex vhost routes = %v, want one route to the apex cluster", vh.Routes)
			}
			if nas := vhostByDomain(rc, "nas.example.com"); nas == nil {
				t.Error("regular static route lost its nas.example.com vhost")
			}
			for _, v := range rc.VirtualHosts {
				for _, d := range v.Domains {
					if strings.Contains(d, "@") {
						t.Errorf("vhost %q has domain %q containing \"@\"", v.Name, d)
					}
				}
			}

			catchAll := vhostByDomain(rc, catchAllDomain)
			if !withRules {
				if catchAll != nil {
					t.Fatalf("legacy-only config has a catch-all vhost: %v", catchAll)
				}
				return
			}
			if catchAll == nil {
				t.Fatal("no catch-all vhost next to rule-based routes")
			}
			var found bool
			for _, er := range catchAll.Routes {
				if er.GetRoute().GetCluster() != model.ApexSubdomain {
					continue
				}
				found = true
				var authority []string
				for _, h := range er.Match.Headers {
					if h.Name == ":authority" {
						authority = append(authority, h.GetStringMatch().GetExact())
					}
				}
				if !reflect.DeepEqual(authority, []string{"example.com"}) {
					t.Errorf("apex catch-all copy :authority = %v, want [example.com]", authority)
				}
			}
			if !found {
				t.Error("apex route missing from the catch-all vhost")
			}
		})
	}
}

// TestApexStaticRoute_UpstreamSNI: an https static "@" route's upstream TLS
// SNI is BASE_DOMAIN itself.
func TestApexStaticRoute_UpstreamSNI(t *testing.T) {
	c := buildRouteCluster(apexStaticRoute(&model.UpstreamTLS{InsecureSkipVerify: true}), "example.com")
	if c.Name != model.ApexSubdomain {
		t.Errorf("apex cluster name = %q, want %q", c.Name, model.ApexSubdomain)
	}
	if sni := upstreamTLSContext(t, c).GetSni(); sni != "example.com" {
		t.Errorf("apex SNI = %q, want example.com", sni)
	}
}

// TestSSOSnapshot_StaticRoutesNeverInheritSSO: with an SSO profile active on
// the listener, every route serving a static router (a regular subdomain and
// the apex "@", in their own vhosts and in the legacy catch-all copies)
// carries BOTH a disabled oauth2 and a disabled jwt_authn override, so none
// can inherit the listener-wide requirement, while the sso-labeled docker
// router keeps its requirement.
func TestSSOSnapshot_StaticRoutesNeverInheritSSO(t *testing.T) {
	for _, withRules := range []bool{false, true} {
		name := "legacy only"
		if withRules {
			name = "sso router rule-based"
		}
		t.Run(name, func(t *testing.T) {
			secured := ssoRoute("secured", "nas")
			if withRules {
				secured = ruleDockerRoute(t, "secured", "nas")
			}
			snap, err := BuildSnapshotForConfig("1", model.HTTPConfiguration{Routes: map[string]model.Route{
				"secured":           secured,
				"public":            ssoRoute("public", ""),
				"truenas":           staticRoute("truenas"),
				model.ApexSubdomain: apexStaticRoute(&model.UpstreamTLS{InsecureSkipVerify: true}),
			}}, ssoTestConfig(testSSOConfig(t, "nas")))
			if err != nil {
				t.Fatalf("BuildSnapshotForConfig: %v", err)
			}
			rc := httpsRouteConfig(t, snap)

			assertPublic := func(where string, er *routev3.Route) {
				t.Helper()
				if !oauth2Disabled(t, er, "nas") {
					t.Errorf("%s route %q lacks a disabled oauth2.nas override (would inherit SSO)", where, er.Name)
				}
				if _, ok := er.TypedPerFilterConfig[jwtAuthnFilterName]; !ok {
					t.Errorf("%s route %q lacks a jwt_authn override", where, er.Name)
				} else if !jwtPerRoute(t, er).GetDisabled() {
					t.Errorf("%s route %q jwt_authn override not disabled", where, er.Name)
				}
			}
			for _, domain := range []string{"example.com", "truenas.example.com", "public.example.com"} {
				vh := vhostByDomain(rc, domain)
				if vh == nil || len(vh.Routes) == 0 {
					t.Fatalf("no routes for %s", domain)
				}
				for _, er := range vh.Routes {
					assertPublic(domain, er)
				}
			}
			// Static copies in the catch-all vhost are public too.
			staticClusters := map[string]bool{"truenas": true, model.ApexSubdomain: true}
			var copies int
			if catchAll := vhostByDomain(rc, catchAllDomain); catchAll != nil {
				for _, er := range catchAll.Routes {
					if staticClusters[er.GetRoute().GetCluster()] {
						copies++
						assertPublic("catch-all", er)
					}
				}
			}
			if withRules && copies != 2 {
				t.Errorf("catch-all carries %d static route copies, want 2", copies)
			}

			sec := vhostByDomain(rc, "secured.example.com")
			if sec == nil || len(sec.Routes) == 0 {
				t.Fatal("no routes for secured.example.com")
			}
			for _, er := range sec.Routes {
				if oauth2Disabled(t, er, "nas") {
					t.Errorf("sso route %q disables its oauth2.nas", er.Name)
				}
				if pr := jwtPerRoute(t, er); pr.GetDisabled() || pr.GetRequirementName() != "nas" {
					t.Errorf("sso route %q jwt override = %v, want requirement_name nas", er.Name, pr)
				}
			}
		})
	}
}
