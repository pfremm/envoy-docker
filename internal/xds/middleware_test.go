package xds

import (
	"strings"
	"testing"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	luav3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
)

func middlewareRoute(t *testing.T, chain ...model.Middleware) *routev3.Route {
	t.Helper()
	cfg := model.HTTPConfiguration{Routes: map[string]model.Route{"app": {Subdomain: "app", RouterName: "web", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}}, Middlewares: chain}}, Services: map[string]model.HTTPService{}}
	snap, err := BuildSnapshotForConfig("1", cfg, Config{BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	rc := snap.GetResources(resourcev3.RouteType)[httpsRouteConfigName].(*routev3.RouteConfiguration)
	return rc.VirtualHosts[0].Routes[0]
}

func mutationSource(t *testing.T, r *routev3.Route) string {
	t.Helper()
	perRoute := &luav3.LuaPerRoute{}
	if a := r.GetTypedPerFilterConfig()[mutationFilterName]; a == nil || a.UnmarshalTo(perRoute) != nil {
		t.Fatalf("missing/invalid Lua per-route config: %+v", a)
	}
	return perRoute.GetSourceCode().GetInlineString()
}

func TestCompileRedirectMiddleware(t *testing.T) {
	r := middlewareRoute(t, model.Middleware{Name: "https", RedirectScheme: &model.RedirectSchemeMiddleware{Scheme: "https", Port: 8443, Permanent: true}})
	if r.GetRedirect() == nil || r.GetRedirect().GetSchemeRedirect() != "https" || r.GetRedirect().GetPortRedirect() != 8443 || r.GetRedirect().GetResponseCode() != routev3.RedirectAction_MOVED_PERMANENTLY {
		t.Fatalf("redirect=%+v", r.GetRedirect())
	}
}

func TestCompileRedirectRegexMiddleware(t *testing.T) {
	r := middlewareRoute(t, model.Middleware{Name: "old", RedirectRegex: &model.RedirectRegexMiddleware{Regex: "^/old/(.*)$", Replacement: "/new/$1", Permanent: false}})
	if r.GetRedirect() == nil || r.GetRedirect().GetRegexRewrite().GetPattern().GetRegex() != "^/old/(.*)$" || r.GetRedirect().GetRegexRewrite().GetSubstitution() != "/new/\\1" {
		t.Fatalf("redirect=%+v", r.GetRedirect())
	}
}

func TestCompileOrderedPathAndHeaderMutations(t *testing.T) {
	r := middlewareRoute(t,
		model.Middleware{Name: "strip", StripPrefix: &model.StripPrefixMiddleware{Prefixes: []string{"/api", "/v1"}}},
		model.Middleware{Name: "add", AddPrefix: &model.AddPrefixMiddleware{Prefix: "/internal"}},
		model.Middleware{Name: "head", Headers: &model.HeadersMiddleware{Request: map[string]string{"x-one": "1"}, Response: map[string]string{"x-two": "2"}, RemoveRequest: []string{"x-old"}, RemoveResponse: []string{"server"}}},
	)
	if r.GetRoute() == nil {
		t.Fatal("expected forwarding route")
	}
	lua := r.GetTypedPerFilterConfig()[mutationFilterName]
	if lua == nil {
		t.Fatalf("missing ordered mutation config: %+v", r.GetTypedPerFilterConfig())
	}
	if len(r.RequestHeadersToAdd) != 0 || len(r.ResponseHeadersToRemove) != 0 {
		t.Fatalf("ordered mutations must be compiled together, not split across route fields: %+v", r)
	}
}

func TestHeaderMutationOrderChangesCompiledProgram(t *testing.T) {
	set := model.Middleware{Name: "set", Headers: &model.HeadersMiddleware{Request: map[string]string{"x-order": "set"}}}
	remove := model.Middleware{Name: "remove", Headers: &model.HeadersMiddleware{Request: map[string]string{}, RemoveRequest: []string{"x-order"}}}
	setThenRemove := mutationSource(t, middlewareRoute(t, set, remove))
	removeThenSet := mutationSource(t, middlewareRoute(t, remove, set))
	if setThenRemove == removeThenSet {
		t.Fatal("opposite header chains compiled identically")
	}
	if strings.Index(setThenRemove, ":replace(\"x-order\"") > strings.Index(setThenRemove, ":remove(\"x-order\"") {
		t.Fatalf("set/remove order lost:\n%s", setThenRemove)
	}
	if strings.Index(removeThenSet, ":remove(\"x-order\"") > strings.Index(removeThenSet, ":replace(\"x-order\"") {
		t.Fatalf("remove/set order lost:\n%s", removeThenSet)
	}
}

func TestResponseHeaderMutationsUnwindInReverseOrder(t *testing.T) {
	set := model.Middleware{Name: "set", Headers: &model.HeadersMiddleware{Response: map[string]string{"x-order": "set"}}}
	remove := model.Middleware{Name: "remove", Headers: &model.HeadersMiddleware{Response: map[string]string{}, RemoveResponse: []string{"x-order"}}}
	source := mutationSource(t, middlewareRoute(t, set, remove))
	responseStart := strings.Index(source, "function envoy_on_response")
	if responseStart < 0 {
		t.Fatalf("missing response callback:\n%s", source)
	}
	removeAt := strings.Index(source[responseStart:], ":remove(\"x-order\"")
	setAt := strings.Index(source[responseStart:], ":replace(\"x-order\"")
	if removeAt < 0 || setAt < 0 || removeAt > setAt {
		t.Fatalf("response chain did not unwind in reverse:\n%s", source)
	}
}

func TestCompileReplacePathAndCORS(t *testing.T) {
	r := middlewareRoute(t,
		model.Middleware{Name: "p", ReplacePath: &model.ReplacePathMiddleware{Path: "/fixed"}},
		model.Middleware{Name: "cors", CORS: &model.CORSMiddleware{AllowOrigins: []string{"https://example.com"}, AllowMethods: []string{"GET", "POST"}, AllowHeaders: []string{"x-a"}, ExposeHeaders: []string{"x-b"}, MaxAge: "600", AllowCredentials: true}},
	)
	if r.GetTypedPerFilterConfig()[mutationFilterName] == nil || r.GetTypedPerFilterConfig()[corsFilterName] == nil {
		t.Fatalf("typed filter config=%+v", r.GetTypedPerFilterConfig())
	}
}

func TestCompileReplacePathRegexUsesNativeRE2(t *testing.T) {
	r := middlewareRoute(t, model.Middleware{Name: "rx", ReplacePathRegex: &model.ReplacePathRegexMiddleware{Regex: "^/fixed$", Replacement: "/done"}})
	if r.GetRoute().GetRegexRewrite().GetPattern().GetRegex() != "^/fixed$" || r.GetTypedPerFilterConfig()[mutationFilterName] != nil {
		t.Fatalf("regex rewrite must use Envoy RE2 action: %+v", r)
	}
}

func TestBuildSnapshotForConfigRejectsUnknownMiddlewareReference(t *testing.T) {
	cfg := model.HTTPConfiguration{Routes: map[string]model.Route{"app": {Subdomain: "app", RouterName: "web", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}}, MiddlewareNames: []string{"missing"}}}}
	if _, err := BuildSnapshotForConfig("1", cfg, Config{BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443}); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("expected actionable unknown middleware error, got %v", err)
	}
}

func TestNoMiddlewarePreservesLegacyRouteShape(t *testing.T) {
	r := middlewareRoute(t)
	if r.GetRoute() == nil || len(r.TypedPerFilterConfig) != 0 || len(r.RequestHeadersToAdd) != 0 || len(r.ResponseHeadersToAdd) != 0 {
		t.Fatalf("legacy route changed: %+v", r)
	}
}

func TestApplyRouteMiddlewares_BasicAuthRemoveHeader(t *testing.T) {
	r := middlewareRoute(t, model.Middleware{Name: "auth", BasicAuth: &model.BasicAuthMiddleware{
		Users: []string{"alice:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="}, RemoveHeader: true,
	}})
	cfg := &luav3.LuaPerRoute{}
	if err := r.TypedPerFilterConfig[basicAuthRemoveFilterName].UnmarshalTo(cfg); err != nil {
		t.Fatal(err)
	}
	source := cfg.GetSourceCode().GetInlineString()
	if !strings.Contains(source, `remove("authorization")`) {
		t.Fatalf("basic auth removeheader did not compile to the final cleanup filter: %s", source)
	}
}
