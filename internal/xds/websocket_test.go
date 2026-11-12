package xds

import (
	"testing"

	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
)

func TestWebSocket_HCMUpgradeConfigsOnRoutedListeners(t *testing.T) {
	routes := map[string]model.Route{
		"app":   {Subdomain: "app", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}}, Source: model.SourceDocker},
		"admin": {Subdomain: "admin", Endpoints: []model.Endpoint{{Address: "10.0.0.2", Port: 8080}}, Source: model.SourceDocker, Entrypoints: []string{"admin"}},
	}
	cfg := Config{
		BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443,
		CertSecretName: "cert", ACMESDSClusterName: "acme",
		HTTPEntrypoints: map[string]uint32{"admin": 8443},
	}
	snap, err := BuildSnapshot("1", routes, cfg)
	if err != nil {
		t.Fatalf("BuildSnapshot() unexpected error: %v", err)
	}
	listeners := snap.GetResources(resourcev3.ListenerType)
	for _, name := range []string{httpsListenerName, httpsListenerName + "__admin"} {
		l, ok := listeners[name].(*listenerv3.Listener)
		if !ok {
			t.Fatalf("no listener %q in snapshot", name)
		}
		ucs := decodeHCM(t, l).UpgradeConfigs
		if len(ucs) != 1 || ucs[0].UpgradeType != "websocket" || ucs[0].Enabled != nil {
			t.Errorf("listener %q upgrade_configs = %v, want [{upgrade_type: websocket}]", name, ucs)
		}
	}
	// The plain-HTTP listener only redirects to HTTPS; it never proxies.
	if ucs := decodeHCM(t, listeners[httpListenerName].(*listenerv3.Listener)).UpgradeConfigs; len(ucs) != 0 {
		t.Errorf("redirect listener upgrade_configs = %v, want none", ucs)
	}
}

// wsDisabled reports whether a route carries the route-level websocket
// opt-out; it fails the test on any other route-level upgrade config.
func wsDisabled(t *testing.T, er *routev3.Route) bool {
	t.Helper()
	ucs := er.GetRoute().GetUpgradeConfigs()
	if len(ucs) == 0 {
		return false
	}
	if len(ucs) != 1 || ucs[0].UpgradeType != "websocket" || ucs[0].Enabled == nil || ucs[0].Enabled.Value {
		t.Fatalf("route %q upgrade_configs = %v, want [{websocket enabled:false}]", er.Name, ucs)
	}
	return true
}

func TestWebSocket_RouterOptOut(t *testing.T) {
	ep := []model.Endpoint{{Address: "10.0.0.1", Port: 8080}}
	routes := map[string]model.Route{
		"on":  {Subdomain: "on", RouterName: "on", Endpoints: ep, Source: model.SourceDocker},
		"off": {Subdomain: "off", RouterName: "off", Endpoints: ep, Source: model.SourceDocker, WebSocketDisabled: true},
		// A rule with an OR expands to several Envoy routes; each one
		// carries the opt-out.
		"multi": {Subdomain: "multi", RouterName: "multi", Endpoints: ep, Source: model.SourceDocker, WebSocketDisabled: true,
			Rule: mustRule(t, "Host(multi.example.com) && (PathPrefix(/a) || PathPrefix(/b))"), RuleExpr: "x"},
		"ssooff": func() model.Route {
			r := ssoRoute("ssooff", "nas")
			r.WebSocketDisabled = true
			return r
		}(),
	}
	cfg := ssoTestConfig(testSSOConfig(t, "nas"))
	build := map[string]func() (*routev3.RouteConfiguration, error){
		"legacy": func() (*routev3.RouteConfiguration, error) {
			snap, err := BuildSnapshot("1", routes, cfg)
			if err != nil {
				return nil, err
			}
			return httpsRouteConfig(t, snap), nil
		},
		"config": func() (*routev3.RouteConfiguration, error) {
			snap, err := BuildSnapshotForConfig("1", model.HTTPConfiguration{Routes: routes}, cfg)
			if err != nil {
				return nil, err
			}
			return httpsRouteConfig(t, snap), nil
		},
	}
	for path, fn := range build {
		t.Run(path, func(t *testing.T) {
			rc, err := fn()
			if err != nil {
				t.Fatal(err)
			}
			got := routesByName(rc)
			if wsDisabled(t, got["on"]) {
				t.Errorf("router without .websocket label must inherit the HCM default, got a route-level config")
			}
			if !wsDisabled(t, got["off"]) {
				t.Errorf("router with .websocket=false must disable the upgrade at route level")
			}
			if !wsDisabled(t, got["ssooff"]) {
				t.Errorf("SSO router with .websocket=false must disable the upgrade at route level")
			}
			multi := 0
			for _, vh := range rc.VirtualHosts {
				for _, er := range vh.Routes {
					if er.Name != "multi" {
						continue
					}
					multi++
					if !wsDisabled(t, er) {
						t.Errorf("every route of router multi must disable the upgrade, got %v", er.GetRoute().GetUpgradeConfigs())
					}
				}
			}
			if multi < 2 {
				t.Errorf("router multi emitted %d routes, want 2 (one per DNF term)", multi)
			}
		})
	}
}
