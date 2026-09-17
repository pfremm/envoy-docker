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

func TestParseSecurityMiddlewareVariants(t *testing.T) {
	got, bad, err := parseMiddlewares(map[string]string{
		"envoy.http.middlewares.basic.basicauth.users":                    "alice:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=,bob:{SHA}2jmj7l5rSw0yVb/vlWAYkK/YBwk=",
		"envoy.http.middlewares.basic.basicauth.realm":                    "private",
		"envoy.http.middlewares.basic.basicauth.headerfield":              "X-Authenticated-User",
		"envoy.http.middlewares.basic.basicauth.removeheader":             "true",
		"envoy.http.middlewares.auth.forwardauth.address":                 "auth.internal:8443",
		"envoy.http.middlewares.auth.forwardauth.trustforwardheader":      "true",
		"envoy.http.middlewares.auth.forwardauth.authrequestheaders":      "X-Token,X-Scope",
		"envoy.http.middlewares.auth.forwardauth.authresponseheaders":     "X-User",
		"envoy.http.middlewares.auth.forwardauth.authresponseheaderregex": "^X-Group-.*$",
		"envoy.http.middlewares.auth.forwardauth.tls.insecure":            "true",
		"envoy.http.middlewares.auth.forwardauth.tls.servername":          "auth.internal",
		"envoy.http.middlewares.allow.ipallowlist.sourcerange":            "10.0.0.0/8,2001:db8::/32",
		"envoy.http.middlewares.allow.ipallowlist.ipstrategy.depth":       "2",
		"envoy.http.middlewares.deny.ipdenylist.sourcerange":              "192.0.2.0/24",
		"envoy.http.middlewares.deny.ipdenylist.ipstrategy.excludedips":   "10.0.0.0/8",
		"envoy.http.middlewares.local.ratelimit.average":                  "10",
		"envoy.http.middlewares.local.ratelimit.burst":                    "20",
		"envoy.http.middlewares.local.ratelimit.period":                   "1s",
	})
	if err != nil || len(bad) != 0 {
		t.Fatalf("security parser failed: bad=%v err=%v", bad, err)
	}
	if len(got) != 5 || !got["basic"].BasicAuth.RemoveHeader || !got["auth"].ForwardAuth.TrustForwardHeader || got["allow"].IPAllowList.Strategy.Depth != 2 || got["local"].RateLimit.Burst != 20 {
		t.Fatalf("security variants not parsed correctly: %+v", got)
	}
}

func TestParseSecurityMiddlewareFailuresAreIsolated(t *testing.T) {
	_, bad, err := parseMiddlewares(map[string]string{
		"envoy.http.middlewares.auth.forwardauth.address":            "auth.internal",
		"envoy.http.middlewares.auth.forwardauth.trustforwardheader": "sometimes",
		"envoy.http.middlewares.allow.ipallowlist.sourcerange":       "invalid",
		"envoy.http.middlewares.rate.ratelimit.average":              "zero",
		"envoy.http.middlewares.rate.ratelimit.burst":                "5",
		"envoy.http.middlewares.rate.ratelimit.period":               "1s",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"auth", "allow", "rate"} {
		if bad[name] == nil {
			t.Errorf("%s should have an isolated parse/validation error: %v", name, bad)
		}
	}
}
