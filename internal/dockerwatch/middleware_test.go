package dockerwatch

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
)

func TestParseMiddlewaresAllVariants(t *testing.T) {
	got, bad, err := parseMiddlewares(map[string]string{
		"envoy.http.middlewares.rs.redirectscheme.scheme":        "https",
		"envoy.http.middlewares.rs.redirectscheme.port":          "8443",
		"envoy.http.middlewares.rs.redirectscheme.permanent":     "true",
		"envoy.http.middlewares.rr.redirectregex.regex":          "^/old/(.*)$",
		"envoy.http.middlewares.rr.redirectregex.replacement":    "/new/$1",
		"envoy.http.middlewares.ap.addprefix.prefix":             "/internal",
		"envoy.http.middlewares.rp.replacepath.path":             "/fixed",
		"envoy.http.middlewares.rx.replacepathregex.regex":       "^/a$",
		"envoy.http.middlewares.rx.replacepathregex.replacement": "/b",
	})
	if err != nil || len(bad) != 0 {
		t.Fatalf("bad=%v err=%v", bad, err)
	}
	if len(got) != 5 || got["rs"].RedirectScheme.Port != 8443 || !got["rs"].RedirectScheme.Permanent || got["rr"].RedirectRegex == nil || got["ap"].AddPrefix == nil || got["rp"].ReplacePath == nil || got["rx"].ReplacePathRegex == nil {
		t.Fatalf("typed variants=%+v", got)
	}
}

func TestParseMiddlewaresRejectsBaseAndIndexedList(t *testing.T) {
	_, bad, err := parseMiddlewares(map[string]string{
		"envoy.http.middlewares.c.cors.alloworigins":   "https://a.example",
		"envoy.http.middlewares.c.cors.alloworigins.0": "https://b.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := bad["c"]; !ok {
		t.Fatalf("mixed list forms should be rejected: %v", bad)
	}
}

func TestParseMiddlewaresTypedAndEscapedLists(t *testing.T) {
	got, bad, err := parseMiddlewares(map[string]string{
		"envoy.http.middlewares.strip.stripprefix.prefixes": `/api\,/literal,/v1`,
		"envoy.http.middlewares.c.cors.alloworigins.10":     "https://b.example",
		"envoy.http.middlewares.c.cors.alloworigins.2":      "https://a.example",
		"envoy.http.middlewares.c.cors.allowmethods":        "GET,POST",
		"envoy.http.middlewares.h.headers.request.X-Trace":  "yes",
		"envoy.http.middlewares.h.headers.removeresponse":   "Server,X-Powered-By",
	})
	if err != nil || len(bad) != 0 {
		t.Fatalf("parseMiddlewares: bad=%v err=%v", bad, err)
	}
	if p := got["strip"].StripPrefix.Prefixes; len(p) != 2 || p[0] != "/api,/literal" || p[1] != "/v1" {
		t.Fatalf("prefixes=%q", p)
	}
	if o := got["c"].CORS.AllowOrigins; len(o) != 2 || !strings.Contains(o[0], "a.example") {
		t.Fatalf("origins=%q", o)
	}
	if _, ok := got["h"].Headers.Request["x-trace"]; !ok {
		t.Fatalf("headers not canonicalized: %+v", got["h"].Headers)
	}
}

func TestParseMiddlewaresRejectsMixedTypeRegexHeaderAndMalformedList(t *testing.T) {
	_, bad, err := parseMiddlewares(map[string]string{
		"envoy.http.middlewares.m.addprefix.prefix":           "/x",
		"envoy.http.middlewares.m.replacepath.path":           "/y",
		"envoy.http.middlewares.r.redirectregex.regex":        "[",
		"envoy.http.middlewares.r.redirectregex.replacement":  "/x",
		"envoy.http.middlewares.h.headers.request.:authority": "evil",
		"envoy.http.middlewares.l.stripprefix.prefixes":       `a\`,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"m", "r", "h", "l"} {
		if _, ok := bad[name]; !ok {
			t.Errorf("%s should be invalid: %v", name, bad)
		}
	}
}

func TestDiscoverResolvesMiddlewareOrderAndIsolatesUnknownReference(t *testing.T) {
	labels := map[string]string{
		"envoy.enable":                      "true",
		"envoy.http.routers.good.subdomain": "good", "envoy.http.routers.good.port": "8080", "envoy.http.routers.good.middlewares": "strip,head",
		"envoy.http.routers.bad.subdomain": "bad", "envoy.http.routers.bad.port": "8080", "envoy.http.routers.bad.middlewares": "missing",
		"envoy.http.middlewares.strip.stripprefix.prefixes":   "/api",
		"envoy.http.middlewares.head.headers.request.X-Order": "second",
	}
	c := container.Summary{ID: "a", Labels: labels, NetworkSettings: &container.NetworkSettingsSummary{Networks: map[string]*network.EndpointSettings{"proxy": {IPAddress: "10.0.0.1"}}}}
	var logs strings.Builder
	cfg := discover([]container.Summary{c}, "proxy", slog.New(slog.NewTextHandler(&logs, nil)))
	if _, ok := cfg.Routes["bad"]; ok {
		t.Fatal("unknown middleware router was retained")
	}
	r := cfg.Routes["good"]
	if len(r.Middlewares) != 2 || r.Middlewares[0].Name != "strip" || r.Middlewares[1].Name != "head" {
		t.Fatalf("order=%+v", r.Middlewares)
	}
	if !strings.Contains(logs.String(), "missing") {
		t.Fatalf("missing actionable log: %s", logs.String())
	}
}
