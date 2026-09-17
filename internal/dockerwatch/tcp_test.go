package dockerwatch

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
)

func TestParseTCPRouters_ExactAndCatchAll(t *testing.T) {
	got, bad, err := parseTCPRouters(map[string]string{
		"envoy.tcp.routers.web.rule":            "HostSNI(app.example.com)",
		"envoy.tcp.routers.web.service":         "svc",
		"envoy.tcp.routers.web.tls.passthrough": "true",
		"envoy.tcp.routers.web.entrypoints":     "websecure,other",
		"envoy.tcp.routers.web.priority":        "10",
		"envoy.tcp.routers.raw.rule":            "HostSNI(*)",
		"envoy.tcp.routers.raw.service":         "svc2",
	})
	if err != nil || len(bad) != 0 {
		t.Fatalf("bad=%v err=%v", bad, err)
	}
	web := got["web"]
	if web.ruleExpr != "HostSNI(app.example.com)" || web.service != "svc" || !web.tlsPassthrough || web.priority != 10 || !web.prioritySet {
		t.Fatalf("web router = %+v", web)
	}
	if len(web.entrypoints) != 2 || web.entrypoints[0] != "websecure" || web.entrypoints[1] != "other" {
		t.Fatalf("entrypoints = %v", web.entrypoints)
	}
	raw := got["raw"]
	if raw.ruleExpr != "HostSNI(*)" || raw.tlsPassthrough {
		t.Fatalf("raw router = %+v", raw)
	}
}

func TestParseTCPRouters_MissingRuleOrServiceRejectedIndividually(t *testing.T) {
	got, bad, err := parseTCPRouters(map[string]string{
		"envoy.tcp.routers.norule.service": "svc",
		"envoy.tcp.routers.noservice.rule": "HostSNI(*)",
		"envoy.tcp.routers.ok.rule":        "HostSNI(*)",
		"envoy.tcp.routers.ok.service":     "svc",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := bad["norule"]; !ok {
		t.Errorf("expected norule rejected, bad=%v", bad)
	}
	if _, ok := bad["noservice"]; !ok {
		t.Errorf("expected noservice rejected, bad=%v", bad)
	}
	if _, ok := got["ok"]; !ok {
		t.Errorf("sibling router should still be parsed, got=%v", got)
	}
}

func TestParseTCPRouters_InvalidPriorityIsolated(t *testing.T) {
	_, bad, err := parseTCPRouters(map[string]string{
		"envoy.tcp.routers.web.rule":     "HostSNI(*)",
		"envoy.tcp.routers.web.service":  "svc",
		"envoy.tcp.routers.web.priority": "nope",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := bad["web"]; !ok {
		t.Fatalf("expected invalid priority rejected, bad=%v", bad)
	}
}

func TestParseTCPServices_MultiEndpointAndWeighted(t *testing.T) {
	got, bad, err := parseTCPServices(map[string]string{
		"envoy.tcp.services.db.loadbalancer.servers.0.port":     "5432",
		"envoy.tcp.services.db.loadbalancer.servers.1.port":     "5433",
		"envoy.tcp.services.rollout.weighted.services.0.name":   "blue",
		"envoy.tcp.services.rollout.weighted.services.0.weight": "9",
		"envoy.tcp.services.rollout.weighted.services.1.name":   "green",
		"envoy.tcp.services.rollout.weighted.services.1.weight": "1",
	})
	if err != nil || len(bad) != 0 {
		t.Fatalf("bad=%v err=%v", bad, err)
	}
	if got["db"].ports[0] != 5432 || got["db"].ports[1] != 5433 {
		t.Fatalf("db ports = %+v", got["db"].ports)
	}
	if len(got["rollout"].weighted) != 2 {
		t.Fatalf("rollout weighted = %+v", got["rollout"].weighted)
	}
}

func TestParseTCPServices_MixedShapeRejected(t *testing.T) {
	_, bad, err := parseTCPServices(map[string]string{
		"envoy.tcp.services.bad.loadbalancer.servers.0.port": "80",
		"envoy.tcp.services.bad.weighted.services.0.name":    "x",
		"envoy.tcp.services.bad.weighted.services.0.weight":  "1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := bad["bad"]; !ok {
		t.Fatalf("expected mixed shape rejected, bad=%v", bad)
	}
}

func mkTCPContainer(id, ip string, labels map[string]string) container.Summary {
	return container.Summary{ID: id, Names: []string{"/" + id}, Labels: labels, NetworkSettings: &container.NetworkSettingsSummary{Networks: map[string]*network.EndpointSettings{"proxy": {IPAddress: ip}}}}
}

func TestDiscoverTCP_RawAndPassthrough(t *testing.T) {
	containers := []container.Summary{
		mkTCPContainer("db", "10.0.0.1", map[string]string{
			"envoy.enable": "true",
			"envoy.tcp.services.db.loadbalancer.servers.0.port": "5432",
		}),
		mkTCPContainer("router", "10.0.0.2", map[string]string{
			"envoy.enable":                              "true",
			"envoy.tcp.routers.dbroute.rule":            "HostSNI(*)",
			"envoy.tcp.routers.dbroute.service":         "db",
			"envoy.tcp.routers.dbroute.tls.passthrough": "false",
		}),
	}
	cfg := discoverTCP(containers, "proxy", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if len(cfg.Routers) != 1 || cfg.Routers["dbroute"].ServiceName != "db" {
		t.Fatalf("routers=%+v", cfg.Routers)
	}
	if len(cfg.Services["db"].Endpoints) != 1 || cfg.Services["db"].Endpoints[0].Port != 5432 {
		t.Fatalf("db service=%+v", cfg.Services["db"])
	}
}

func TestDiscoverTCP_UnknownServiceIsolatesOnlyThatRouter(t *testing.T) {
	containers := []container.Summary{
		mkTCPContainer("router", "10.0.0.2", map[string]string{
			"envoy.enable":                  "true",
			"envoy.tcp.routers.bad.rule":    "HostSNI(*)",
			"envoy.tcp.routers.bad.service": "missing",
		}),
	}
	var logs strings.Builder
	cfg := discoverTCP(containers, "proxy", slog.New(slog.NewTextHandler(&logs, nil)))
	if len(cfg.Routers) != 0 {
		t.Fatalf("expected router with unknown service to be dropped, got %+v", cfg.Routers)
	}
	if !strings.Contains(logs.String(), "unknown or invalid") {
		t.Fatalf("expected actionable log, got %s", logs.String())
	}
}

func TestDiscoverTCP_MultiEndpointReplicaMerge(t *testing.T) {
	containers := []container.Summary{
		mkTCPContainer("db1", "10.0.0.1", map[string]string{
			"envoy.enable": "true",
			"envoy.tcp.services.db.loadbalancer.servers.0.port": "5432",
		}),
		mkTCPContainer("db2", "10.0.0.2", map[string]string{
			"envoy.enable": "true",
			"envoy.tcp.services.db.loadbalancer.servers.0.port": "5432",
		}),
		mkTCPContainer("router", "10.0.0.3", map[string]string{
			"envoy.enable":                "true",
			"envoy.tcp.routers.r.rule":    "HostSNI(*)",
			"envoy.tcp.routers.r.service": "db",
		}),
	}
	cfg := discoverTCP(containers, "proxy", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if len(cfg.Services["db"].Endpoints) != 2 {
		t.Fatalf("expected 2 replica endpoints, got %+v", cfg.Services["db"].Endpoints)
	}
}

func TestDiscoverTCP_MultipleEntrypoints(t *testing.T) {
	containers := []container.Summary{
		mkTCPContainer("db", "10.0.0.1", map[string]string{
			"envoy.enable": "true",
			"envoy.tcp.services.db.loadbalancer.servers.0.port": "5432",
		}),
		mkTCPContainer("router", "10.0.0.2", map[string]string{
			"envoy.enable":                    "true",
			"envoy.tcp.routers.r.rule":        "HostSNI(*)",
			"envoy.tcp.routers.r.service":     "db",
			"envoy.tcp.routers.r.entrypoints": "websecure,internal",
		}),
	}
	cfg := discoverTCP(containers, "proxy", slog.New(slog.NewTextHandler(io.Discard, nil)))
	r, ok := cfg.Routers["r"]
	if !ok || len(r.Entrypoints) != 2 {
		t.Fatalf("router=%+v ok=%v", r, ok)
	}
}
