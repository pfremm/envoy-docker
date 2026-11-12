package dockerwatch

import (
	"strings"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
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
