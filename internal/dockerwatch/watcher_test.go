package dockerwatch

import (
	"reflect"
	"strings"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
	"github.com/bryanpfremm/envoy-control-plane/internal/rule"
)

func TestParseRouters(t *testing.T) {
	tests := []struct {
		name    string
		labels  map[string]string
		want    map[string]parsedRouter
		wantBad []string // router names expected in badRouters
		wantErr bool
	}{
		{
			name: "single valid router",
			labels: map[string]string{
				"envoy.enable":                     "true",
				"envoy.http.routers.web.subdomain": "myapp",
				"envoy.http.routers.web.port":      "8080",
			},
			want: map[string]parsedRouter{
				"web": {subdomain: "myapp", port: 8080},
			},
		},
		{
			name: "router with network override",
			labels: map[string]string{
				"envoy.http.routers.web.subdomain": "myapp",
				"envoy.http.routers.web.port":      "8080",
				"envoy.http.routers.web.network":   "proxy-net",
			},
			want: map[string]parsedRouter{
				"web": {subdomain: "myapp", port: 8080, network: "proxy-net"},
			},
		},
		{
			name: "multiple routers on one container",
			labels: map[string]string{
				"envoy.http.routers.web.subdomain":   "myapp",
				"envoy.http.routers.web.port":        "8080",
				"envoy.http.routers.admin.subdomain": "myapp-admin",
				"envoy.http.routers.admin.port":      "9090",
			},
			want: map[string]parsedRouter{
				"web":   {subdomain: "myapp", port: 8080},
				"admin": {subdomain: "myapp-admin", port: 9090},
			},
		},
		{
			name: "missing subdomain rejects only that router",
			labels: map[string]string{
				"envoy.http.routers.web.port":     "8080",
				"envoy.http.routers.ok.subdomain": "fine",
				"envoy.http.routers.ok.port":      "8081",
			},
			want:    map[string]parsedRouter{"ok": {subdomain: "fine", port: 8081}},
			wantBad: []string{"web"},
		},
		{
			name: "missing port rejects only that router",
			labels: map[string]string{
				"envoy.http.routers.web.subdomain": "myapp",
			},
			wantBad: []string{"web"},
		},
		{
			name: "invalid port rejects only that router",
			labels: map[string]string{
				"envoy.http.routers.web.subdomain": "myapp",
				"envoy.http.routers.web.port":      "not-a-port",
				"envoy.http.routers.ok.subdomain":  "fine",
				"envoy.http.routers.ok.port":       "8081",
			},
			want:    map[string]parsedRouter{"ok": {subdomain: "fine", port: 8081}},
			wantBad: []string{"web"},
		},
		{
			name: "invalid priority rejects only that router",
			labels: map[string]string{
				"envoy.http.routers.web.subdomain": "myapp",
				"envoy.http.routers.web.port":      "8080",
				"envoy.http.routers.web.priority":  "not-an-int",
				"envoy.http.routers.ok.subdomain":  "fine",
				"envoy.http.routers.ok.port":       "8081",
			},
			want:    map[string]parsedRouter{"ok": {subdomain: "fine", port: 8081}},
			wantBad: []string{"web"},
		},
		{
			name:   "no router labels",
			labels: map[string]string{"envoy.enable": "true"},
			want:   map[string]parsedRouter{},
		},
		{
			name: "unrelated labels are ignored",
			labels: map[string]string{
				"com.docker.compose.project":       "stack",
				"envoy.http.routers.web.subdomain": "myapp",
				"envoy.http.routers.web.port":      "8080",
				"envoy.http.routers.web.unknown":   "ignored",
			},
			want: map[string]parsedRouter{
				"web": {subdomain: "myapp", port: 8080},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, bad, err := parseRouters(tt.labels)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseRouters() expected error, got nil (result: %+v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseRouters() unexpected error: %v", err)
			}
			if len(bad) != len(tt.wantBad) {
				t.Fatalf("parseRouters() badRouters = %v, want %v", bad, tt.wantBad)
			}
			for _, name := range tt.wantBad {
				if _, ok := bad[name]; !ok {
					t.Errorf("parseRouters() badRouters missing %q, got %v", name, bad)
				}
			}
			if len(got) != len(tt.want) {
				t.Fatalf("parseRouters() = %+v, want %+v", got, tt.want)
			}
			for name, wantRouter := range tt.want {
				gotRouter, ok := got[name]
				if !ok {
					t.Fatalf("parseRouters() missing router %q, got %+v", name, got)
				}
				if !reflect.DeepEqual(gotRouter, wantRouter) {
					t.Fatalf("parseRouters()[%q] = %+v, want %+v", name, gotRouter, wantRouter)
				}
			}
		})
	}
}

func TestParseRouters_RuleAndPriority(t *testing.T) {
	got, _, err := parseRouters(map[string]string{
		"envoy.enable":                     "true",
		"envoy.http.routers.web.subdomain": "myapp",
		"envoy.http.routers.web.port":      "8080",
		"envoy.http.routers.web.rule":      "Host(myapp.example.com) && PathPrefix(/api)",
		"envoy.http.routers.web.priority":  "42",
	})
	if err != nil {
		t.Fatalf("parseRouters() unexpected error: %v", err)
	}
	r := got["web"]
	if r.ruleExpr != "Host(myapp.example.com) && PathPrefix(/api)" {
		t.Errorf("ruleExpr = %q, want the rule expression", r.ruleExpr)
	}
	if r.priority != 42 || !r.prioritySet {
		t.Errorf("priority = %d (set=%v), want 42 (set=true)", r.priority, r.prioritySet)
	}
	// parseRouters stores the raw expression; the AST is built in scan().
	// Verify the expression is parseable by the rule package.
	if _, perr := rule.Parse(r.ruleExpr); perr != nil {
		t.Errorf("rule.Parse(%q) error: %v", r.ruleExpr, perr)
	}
}

func TestParseRouters_RuleOnlyNoPriority(t *testing.T) {
	got, _, err := parseRouters(map[string]string{
		"envoy.http.routers.web.subdomain": "myapp",
		"envoy.http.routers.web.port":      "8080",
		"envoy.http.routers.web.rule":      "Method(GET)",
	})
	if err != nil {
		t.Fatalf("parseRouters() unexpected error: %v", err)
	}
	r := got["web"]
	if r.prioritySet {
		t.Errorf("prioritySet = true, want false (no priority label)")
	}
	if r.ruleExpr != "Method(GET)" {
		t.Errorf("ruleExpr = %q, want Method(GET)", r.ruleExpr)
	}
}

func TestParseRouters_InvalidPriority(t *testing.T) {
	// An invalid priority rejects only that router, with an actionable
	// message; the sibling router is unaffected.
	got, bad, err := parseRouters(map[string]string{
		"envoy.http.routers.web.subdomain": "myapp",
		"envoy.http.routers.web.port":      "8080",
		"envoy.http.routers.web.priority":  "not-an-int",
		"envoy.http.routers.ok.subdomain":  "fine",
		"envoy.http.routers.ok.port":       "8081",
	})
	if err != nil {
		t.Fatalf("parseRouters() unexpected error: %v", err)
	}
	if _, ok := bad["web"]; !ok {
		t.Fatalf("expected router %q in badRouters, got %v", "web", bad)
	}
	if msg := bad["web"].Error(); !strings.Contains(msg, "priority") {
		t.Errorf("badRouters[web] = %q, want an actionable message mentioning priority", msg)
	}
	if _, ok := got["ok"]; !ok {
		t.Errorf("sibling router %q should still be parsed, got %v", "ok", got)
	}
	if _, ok := got["web"]; ok {
		t.Errorf("router %q should be rejected, got %v", "web", got)
	}
}

func TestParseRouters_EntrypointsAndObservability(t *testing.T) {
	got, bad, err := parseRouters(map[string]string{
		"envoy.enable":                                 "true",
		"envoy.http.routers.web.subdomain":             "myapp",
		"envoy.http.routers.web.port":                  "8080",
		"envoy.http.routers.web.entrypoints":           "http,admin",
		"envoy.http.routers.web.tracing":               "true",
		"envoy.http.routers.web.tracing.operationname": "web-span",
		"envoy.http.routers.web.accesslog":             "true",
	})
	if err != nil {
		t.Fatalf("parseRouters() unexpected error: %v", err)
	}
	if len(bad) != 0 {
		t.Fatalf("parseRouters() badRouters = %v, want none", bad)
	}
	r := got["web"]
	if len(r.entrypoints) != 2 || r.entrypoints[0] != "http" || r.entrypoints[1] != "admin" {
		t.Errorf("entrypoints = %v, want [http admin]", r.entrypoints)
	}
	if !r.tracingSet || !r.tracing {
		t.Errorf("tracing = %v (set=%v), want true (set=true)", r.tracing, r.tracingSet)
	}
	if r.operationName != "web-span" {
		t.Errorf("operationName = %q, want web-span", r.operationName)
	}
	if !r.accesslogSet || !r.accesslog {
		t.Errorf("accesslog = %v (set=%v), want true (set=true)", r.accesslog, r.accesslogSet)
	}
}

func TestParseRouters_TracingFalseDistinctFromUnset(t *testing.T) {
	got, _, err := parseRouters(map[string]string{
		"envoy.http.routers.web.subdomain": "myapp",
		"envoy.http.routers.web.port":      "8080",
		"envoy.http.routers.web.tracing":   "false",
	})
	if err != nil {
		t.Fatalf("parseRouters() unexpected error: %v", err)
	}
	r := got["web"]
	if !r.tracingSet {
		t.Errorf("tracingSet = false, want true (.tracing=false is an explicit hook)")
	}
	if r.tracing {
		t.Errorf("tracing = true, want false")
	}
	if r.operationName != "" {
		t.Errorf("operationName = %q, want empty (no operationname label)", r.operationName)
	}
}

func TestParseRouters_ObservabilityInvalidIsolated(t *testing.T) {
	// An invalid .tracing bool rejects only that router; the sibling is
	// unaffected. An empty entrypoints entry and an empty operationname are
	// also rejected individually.
	got, bad, err := parseRouters(map[string]string{
		"envoy.http.routers.bad.subdomain":              "badsite",
		"envoy.http.routers.bad.port":                   "8080",
		"envoy.http.routers.bad.tracing":                "maybe",
		"envoy.http.routers.bad2.subdomain":             "bad2",
		"envoy.http.routers.bad2.port":                  "8081",
		"envoy.http.routers.bad2.entrypoints":           "http,,admin",
		"envoy.http.routers.bad3.subdomain":             "bad3",
		"envoy.http.routers.bad3.port":                  "8082",
		"envoy.http.routers.bad3.tracing.operationname": "",
		"envoy.http.routers.ok.subdomain":               "fine",
		"envoy.http.routers.ok.port":                    "8083",
	})
	if err != nil {
		t.Fatalf("parseRouters() unexpected error: %v", err)
	}
	for _, name := range []string{"bad", "bad2", "bad3"} {
		if _, ok := bad[name]; !ok {
			t.Errorf("expected router %q in badRouters, got %v", name, bad)
		}
		if _, ok := got[name]; ok {
			t.Errorf("router %q should be rejected, got %v", name, got)
		}
	}
	if _, ok := got["ok"]; !ok {
		t.Errorf("sibling router %q should still be parsed, got %v", "ok", got)
	}
}

func TestMergeDecision(t *testing.T) {
	// No existing route: add.
	if a, _ := mergeDecision(model.Route{}, false, "Host(a)", "o1"); a != mergeAdd {
		t.Errorf("new subdomain action = %v, want mergeAdd", a)
	}
	// Same rule: merge as a replica.
	existing := model.Route{RuleExpr: "Host(a)", Origin: "c1/web"}
	if a, _ := mergeDecision(existing, true, "Host(a)", "c2/web"); a != mergeMerge {
		t.Errorf("same-rule action = %v, want mergeMerge", a)
	}
	// Different rule: skip (conflict).
	if a, msg := mergeDecision(existing, true, "Path(/x)", "c2/web"); a != mergeSkip {
		t.Errorf("different-rule action = %v, want mergeSkip", a)
	} else if msg == "" {
		t.Error("conflict message should be non-empty")
	}
	// Both legacy (no rule): merge as replicas.
	legacy := model.Route{Origin: "c1/web"}
	if a, _ := mergeDecision(legacy, true, "", "c2/web"); a != mergeMerge {
		t.Errorf("two legacy routers action = %v, want mergeMerge", a)
	}
}

func TestContainerName(t *testing.T) {
	c := container.Summary{Names: []string{"/myapp-1"}}
	if got := containerName(c); got != "myapp-1" {
		t.Errorf("containerName() = %q, want %q", got, "myapp-1")
	}

	c = container.Summary{ID: "abcdef0123456789"}
	if got := containerName(c); got != "abcdef012345" {
		t.Errorf("containerName() = %q, want %q", got, "abcdef012345")
	}
}

func TestContainerIP(t *testing.T) {
	c := container.Summary{
		NetworkSettings: &container.NetworkSettingsSummary{
			Networks: map[string]*network.EndpointSettings{
				"proxy-net": {IPAddress: "172.20.0.5"},
			},
		},
	}

	addr, err := containerIP(c, "proxy-net")
	if err != nil {
		t.Fatalf("containerIP() unexpected error: %v", err)
	}
	if addr != "172.20.0.5" {
		t.Errorf("containerIP() = %q, want %q", addr, "172.20.0.5")
	}

	if _, err := containerIP(c, "other-net"); err == nil {
		t.Error("containerIP() expected error for network the container isn't attached to")
	}

	noNetworks := container.Summary{}
	if _, err := containerIP(noNetworks, "proxy-net"); err == nil {
		t.Error("containerIP() expected error when NetworkSettings is nil")
	}
}
