package dockerwatch

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
)

func TestParseServices_AllPoliciesAndIndexedValues(t *testing.T) {
	labels := map[string]string{
		"envoy.http.services.api.loadbalancer.servers.10.port":                "9090",
		"envoy.http.services.api.loadbalancer.servers.2.port":                 "8080",
		"envoy.http.services.api.loadbalancer.protocol":                       "https",
		"envoy.http.services.api.loadbalancer.healthcheck.path":               "/ready",
		"envoy.http.services.api.loadbalancer.healthcheck.interval":           "7s",
		"envoy.http.services.api.loadbalancer.healthcheck.timeout":            "1s",
		"envoy.http.services.api.loadbalancer.healthcheck.unhealthythreshold": "4",
		"envoy.http.services.api.loadbalancer.healthcheck.healthythreshold":   "2",
		"envoy.http.services.api.loadbalancer.outlier.consecutive5xx":         "6",
		"envoy.http.services.api.loadbalancer.outlier.interval":               "11s",
		"envoy.http.services.api.loadbalancer.outlier.baseejectiontime":       "31s",
		"envoy.http.services.api.loadbalancer.outlier.maxejectionpercent":     "50",
		"envoy.http.services.api.loadbalancer.sticky.cookie.name":             "affinity",
		"envoy.http.services.api.loadbalancer.sticky.cookie.secure":           "true",
		"envoy.http.services.api.loadbalancer.sticky.cookie.httponly":         "true",
		"envoy.http.services.api.loadbalancer.sticky.cookie.samesite":         "lax",
		"envoy.http.services.api.loadbalancer.sticky.cookie.ttl":              "1h",
	}
	got, bad, err := parseServices(labels)
	if err != nil || len(bad) != 0 {
		t.Fatalf("parseServices: bad=%v err=%v", bad, err)
	}
	s := got["api"]
	if s.ports[2] != 8080 || s.ports[10] != 9090 || s.protocol != "https" {
		t.Fatalf("service=%+v", s)
	}
	if s.health.Path != "/ready" || s.health.Interval != 7*time.Second || s.health.HealthyThreshold != 2 {
		t.Fatalf("health=%+v", s.health)
	}
	if s.outlier.Consecutive5xx != 6 || s.outlier.MaxEjectionPercent == nil || *s.outlier.MaxEjectionPercent != 50 {
		t.Fatalf("outlier=%+v", s.outlier)
	}
	if s.sticky.Name != "affinity" || !s.sticky.Secure || !s.sticky.HTTPOnly || s.sticky.TTL != time.Hour {
		t.Fatalf("sticky=%+v", s.sticky)
	}
}

func TestParseServices_WeightedAndMalformedIsolation(t *testing.T) {
	labels := map[string]string{
		"envoy.http.services.rollout.weighted.services.0.name":   "blue",
		"envoy.http.services.rollout.weighted.services.0.weight": "9",
		"envoy.http.services.rollout.weighted.services.1.name":   "green",
		"envoy.http.services.rollout.weighted.services.1.weight": "1",
		"envoy.http.services.bad.loadbalancer.servers.0.port":    "nope",
	}
	got, bad, err := parseServices(labels)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := bad["bad"]; !ok {
		t.Fatalf("bad=%v", bad)
	}
	if len(got["rollout"].weighted) != 2 {
		t.Fatalf("got=%+v", got)
	}
}

func TestParseRouters_NamedServiceAndActionPolicy(t *testing.T) {
	got, bad, err := parseRouters(map[string]string{
		"envoy.http.routers.web.subdomain":             "app",
		"envoy.http.routers.web.service":               "rollout",
		"envoy.http.routers.web.timeout":               "30s",
		"envoy.http.routers.web.idletimeout":           "5s",
		"envoy.http.routers.web.retries.attempts":      "3",
		"envoy.http.routers.web.retries.pertrytimeout": "2s",
		"envoy.http.routers.web.retries.retryon":       "5xx,reset",
	})
	if err != nil || len(bad) != 0 {
		t.Fatalf("bad=%v err=%v", bad, err)
	}
	r := got["web"]
	if r.port != 0 || r.service != "rollout" || r.timeout == nil || *r.timeout != 30*time.Second || r.idleTimeout == nil || *r.idleTimeout != 5*time.Second || r.retry.Attempts != 3 || r.retry.RetryOn != "5xx,reset" {
		t.Fatalf("router=%+v", r)
	}
}

func TestParseServicesRejectsUnknownField(t *testing.T) {
	_, bad, err := parseServices(map[string]string{"envoy.http.services.api.loadbalancer.typo": "x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := bad["api"]; !ok {
		t.Fatalf("expected unknown field to invalidate only api, got %v", bad)
	}
}

func TestParseRoutersRejectsIncompleteRetryPolicy(t *testing.T) {
	_, bad, err := parseRouters(map[string]string{
		"envoy.http.routers.web.subdomain":        "app",
		"envoy.http.routers.web.port":             "8080",
		"envoy.http.routers.web.retries.attempts": "3",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := bad["web"]; !ok {
		t.Fatalf("expected retry policy without retryon to be rejected: %v", bad)
	}
}

func TestDiscoverNetworkConflictIsDeterministic(t *testing.T) {
	labels := map[string]string{
		"envoy.enable":                              "true",
		"envoy.http.routers.a.subdomain":            "a",
		"envoy.http.routers.a.service":              "api",
		"envoy.http.routers.a.network":              "proxy",
		"envoy.http.routers.b.subdomain":            "b",
		"envoy.http.routers.b.service":              "api",
		"envoy.http.routers.b.network":              "other",
		"envoy.http.services.api.loadbalancer.port": "8080",
	}
	c := container.Summary{ID: "one", Labels: labels, NetworkSettings: &container.NetworkSettingsSummary{Networks: map[string]*network.EndpointSettings{"proxy": {IPAddress: "10.0.0.1"}, "other": {IPAddress: "10.0.0.2"}}}}
	for i := 0; i < 50; i++ {
		cfg := discover([]container.Summary{c}, "proxy", slog.New(slog.NewTextHandler(io.Discard, nil)))
		if _, ok := cfg.Services["api"]; ok || len(cfg.Routes) != 0 {
			t.Fatalf("iteration %d retained conflicting network configuration: %+v", i, cfg)
		}
	}
}

func TestDiscoverNormalizesOmittedProtocolAndHTTP1Replicas(t *testing.T) {
	mk := func(id, ip, protocol string) container.Summary {
		labels := map[string]string{"envoy.enable": "true", "envoy.http.services.api.loadbalancer.port": "8080"}
		if protocol != "" {
			labels["envoy.http.services.api.loadbalancer.protocol"] = protocol
		}
		return container.Summary{ID: id, Labels: labels, NetworkSettings: &container.NetworkSettingsSummary{Networks: map[string]*network.EndpointSettings{"proxy": {IPAddress: ip}}}}
	}
	cfg := discover([]container.Summary{mk("a", "10.0.0.1", ""), mk("b", "10.0.0.2", "http1")}, "proxy", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if got := cfg.Services["api"]; got.Protocol != "http1" || len(got.Endpoints) != 2 {
		t.Fatalf("service replicas were not merged: %+v", got)
	}
}

func TestRoutesCompatibleRejectsActionAndPortDifferences(t *testing.T) {
	timeout := 5 * time.Second
	a := model.Route{RuleExpr: "Host(a)", RouterName: "web", Endpoints: []model.Endpoint{{Port: 8080}}, Timeout: &timeout, DiscoveryNetwork: "proxy"}
	b := a
	otherTimeout := 6 * time.Second
	b.Timeout = &otherTimeout
	if routesCompatible(a, b) {
		t.Fatal("different timeouts should conflict")
	}
	b = a
	b.Endpoints = []model.Endpoint{{Port: 9090}}
	if routesCompatible(a, b) {
		t.Fatal("different legacy ports should conflict")
	}
}

func TestDiscoverNamedServicesMultiPortWeightedAndCycleIsolation(t *testing.T) {
	mk := func(id, ip string, labels map[string]string) container.Summary {
		return container.Summary{ID: id, Names: []string{"/" + id}, Labels: labels, NetworkSettings: &container.NetworkSettingsSummary{Networks: map[string]*network.EndpointSettings{"proxy": {IPAddress: ip}}}}
	}
	containers := []container.Summary{
		mk("blue", "10.0.0.1", map[string]string{"envoy.enable": "true", "envoy.http.services.blue.loadbalancer.servers.0.port": "8080", "envoy.http.services.blue.loadbalancer.servers.1.port": "8081"}),
		mk("green", "10.0.0.2", map[string]string{"envoy.enable": "true", "envoy.http.services.green.loadbalancer.servers.0.port": "8080"}),
		mk("router", "10.0.0.3", map[string]string{"envoy.enable": "true", "envoy.http.routers.web.subdomain": "app", "envoy.http.routers.web.service": "rollout", "envoy.http.routers.bad.subdomain": "bad", "envoy.http.routers.bad.service": "cycle-a", "envoy.http.services.rollout.weighted.services.0.name": "blue", "envoy.http.services.rollout.weighted.services.0.weight": "9", "envoy.http.services.rollout.weighted.services.1.name": "green", "envoy.http.services.rollout.weighted.services.1.weight": "1", "envoy.http.services.cycle-a.weighted.services.0.name": "cycle-b", "envoy.http.services.cycle-a.weighted.services.0.weight": "1", "envoy.http.services.cycle-b.weighted.services.0.name": "cycle-a", "envoy.http.services.cycle-b.weighted.services.0.weight": "1"}),
	}
	var logs strings.Builder
	cfg := discover(containers, "proxy", slog.New(slog.NewTextHandler(&logs, nil)))
	if len(cfg.Services["blue"].Endpoints) != 2 {
		t.Fatalf("blue endpoints=%+v", cfg.Services["blue"].Endpoints)
	}
	if cfg.Routes["app"].ServiceName != "rollout" {
		t.Fatalf("routes=%+v", cfg.Routes)
	}
	if _, ok := cfg.Routes["bad"]; ok {
		t.Fatal("cycle-referencing router should be isolated")
	}
	if !strings.Contains(logs.String(), "cycle") {
		t.Fatalf("expected actionable cycle log: %s", logs.String())
	}
}
