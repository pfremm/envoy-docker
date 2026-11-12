package xds

import (
	"strings"
	"testing"

	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	bufferv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/buffer/v3"
	luav3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
)

// unwrapBufferRouteConfig decodes a route's buffer per-filter config, which
// must be a FilterConfig{disabled:false} wrapping a BufferPerRoute, which
// explicitly enables the listener-disabled filter on that route.
func unwrapBufferRouteConfig(t *testing.T, cfg *anypb.Any) *bufferv3.BufferPerRoute {
	t.Helper()
	fc := &routev3.FilterConfig{}
	if err := cfg.UnmarshalTo(fc); err != nil {
		t.Fatalf("buffer per-route config is not a FilterConfig: %v", err)
	}
	if fc.Disabled {
		t.Fatalf("buffer FilterConfig disabled = true, want false")
	}
	bpr := &bufferv3.BufferPerRoute{}
	if err := fc.GetConfig().UnmarshalTo(bpr); err != nil {
		t.Fatalf("buffer FilterConfig.config is not a BufferPerRoute: %v", err)
	}
	return bpr
}

// bufferLimitSource decodes a route's Lua size-guard per-filter config and
// returns its inline script.
func bufferLimitSource(t *testing.T, cfg *anypb.Any) string {
	t.Helper()
	lpr := &luav3.LuaPerRoute{}
	if err := cfg.UnmarshalTo(lpr); err != nil {
		t.Fatalf("buffer-limit per-route config is not a LuaPerRoute: %v", err)
	}
	src := lpr.GetSourceCode().GetInlineString()
	if src == "" {
		t.Fatalf("buffer-limit LuaPerRoute has no inline source: %v", lpr)
	}
	return src
}

func findHTTPFilter(hcm *hcmv3.HttpConnectionManager, name string) (*hcmv3.HttpFilter, int) {
	for i, f := range hcm.HttpFilters {
		if f.Name == name {
			return f, i
		}
	}
	return nil, -1
}

func bufferTestRoutes(t *testing.T, withBuffer bool) (map[string]model.Route, map[string]model.Middleware) {
	ep := []model.Endpoint{{Address: "10.0.0.1", Port: 8080}}
	routes := map[string]model.Route{
		"plain": {Subdomain: "plain", RouterName: "plain", Endpoints: ep, Source: model.SourceDocker},
	}
	mws := map[string]model.Middleware{}
	if withBuffer {
		buf := model.Middleware{Name: "buf", Buffering: &model.BufferingMiddleware{MaxRequestBytes: 1024}}
		mws["buf"] = buf
		routes["buf"] = model.Route{Subdomain: "buf", RouterName: "buf", Endpoints: ep, Source: model.SourceDocker,
			MiddlewareNames: []string{"buf"}, Middlewares: []model.Middleware{buf}}
		// Multi-term rule: every emitted Envoy route carries the config.
		routes["bufmulti"] = model.Route{Subdomain: "bufmulti", RouterName: "bufmulti", Endpoints: ep, Source: model.SourceDocker,
			Rule: mustRule(t, "Host(bufmulti.example.com) && (PathPrefix(/a) || PathPrefix(/b))"), RuleExpr: "x",
			MiddlewareNames: []string{"buf"}, Middlewares: []model.Middleware{buf}}
		// Buffering next to a header mutation: both Lua filters get their own
		// per-route config, and the guard carries this route's limit.
		hdr := model.Middleware{Name: "hdr", Headers: &model.HeadersMiddleware{Request: map[string]string{"x-test": "1"}}}
		buf2 := model.Middleware{Name: "buf2", Buffering: &model.BufferingMiddleware{MaxRequestBytes: 2048}}
		mws["hdr"], mws["buf2"] = hdr, buf2
		routes["bufhdr"] = model.Route{Subdomain: "bufhdr", RouterName: "bufhdr", Endpoints: ep, Source: model.SourceDocker,
			MiddlewareNames: []string{"hdr", "buf2"}, Middlewares: []model.Middleware{hdr, buf2}}
	}
	return routes, mws
}

func TestBuffering_ListenerFilterOnlyWhenNeeded(t *testing.T) {
	cfg := Config{
		BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443,
		CertSecretName: "cert", ACMESDSClusterName: "acme",
	}
	for _, withBuffer := range []bool{false, true} {
		routes, mws := bufferTestRoutes(t, withBuffer)
		for path, build := range map[string]func() (cachev3.ResourceSnapshot, error){
			"legacy": func() (cachev3.ResourceSnapshot, error) { return BuildSnapshot("1", routes, cfg) },
			"config": func() (cachev3.ResourceSnapshot, error) {
				return BuildSnapshotForConfig("1", model.HTTPConfiguration{Routes: routes, Middlewares: mws}, cfg)
			},
		} {
			snap, err := build()
			if err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			hcm := decodeHCM(t, snap.GetResources(resourcev3.ListenerType)[httpsListenerName].(*listenerv3.Listener))
			f, idx := findHTTPFilter(hcm, bufferFilterName)
			guard, guardIdx := findHTTPFilter(hcm, bufferLimitFilterName)
			if !withBuffer {
				if f != nil {
					t.Errorf("%s: buffer filter present without any buffered route", path)
				}
				if guard != nil {
					t.Errorf("%s: buffer-limit Lua filter present without any buffered route", path)
				}
				continue
			}
			if f == nil {
				t.Fatalf("%s: buffer filter missing although a route uses buffering", path)
			}
			if !f.Disabled {
				t.Errorf("%s: listener buffer filter disabled = false, want true (would hang WebSocket handshakes)", path)
			}
			b := &bufferv3.Buffer{}
			if err := f.GetTypedConfig().UnmarshalTo(b); err != nil || b.GetMaxRequestBytes().GetValue() == 0 {
				t.Errorf("%s: listener buffer typed_config = %v (err %v), want max_request_bytes > 0", path, b, err)
			}
			_, corsIdx := findHTTPFilter(hcm, corsFilterName)
			if corsIdx > idx || idx != len(hcm.HttpFilters)-3 {
				t.Errorf("%s: buffer filter at %d, want after cors (%d) and directly before the buffer-limit guard and router", path, idx, corsIdx)
			}
			if guard == nil {
				t.Fatalf("%s: buffer-limit Lua filter missing although a route uses buffering", path)
			}
			if !guard.Disabled {
				t.Errorf("%s: listener buffer-limit filter disabled = false, want true (would act on every route)", path)
			}
			if guardIdx != idx+1 || guardIdx != len(hcm.HttpFilters)-2 || hcm.HttpFilters[len(hcm.HttpFilters)-1].Name != wellknown.Router {
				t.Errorf("%s: buffer-limit filter at %d, want right after the buffer filter (%d) and right before the router", path, guardIdx, idx)
			}
			lua := &luav3.Lua{}
			if err := guard.GetTypedConfig().UnmarshalTo(lua); err != nil || !strings.Contains(lua.GetDefaultSourceCode().GetInlineString(), "envoy_on_request") {
				t.Errorf("%s: listener buffer-limit typed_config = %v (err %v), want a Lua filter with a default source", path, lua, err)
			}
		}
	}
}

func TestBuffering_PerRouteEnableAndWebSocketDisable(t *testing.T) {
	routes, mws := bufferTestRoutes(t, true)
	cfg := Config{
		BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443,
		CertSecretName: "cert", ACMESDSClusterName: "acme",
	}
	build := map[string]func() (*routev3.RouteConfiguration, error){
		"legacy": func() (*routev3.RouteConfiguration, error) {
			snap, err := BuildSnapshot("1", routes, cfg)
			if err != nil {
				return nil, err
			}
			return httpsRouteConfig(t, snap), nil
		},
		"config": func() (*routev3.RouteConfiguration, error) {
			snap, err := BuildSnapshotForConfig("1", model.HTTPConfiguration{Routes: routes, Middlewares: mws}, cfg)
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
			buffered := 0
			for _, vh := range rc.VirtualHosts {
				for _, er := range vh.Routes {
					switch er.Name {
					case "plain":
						if len(er.TypedPerFilterConfig) != 0 {
							t.Errorf("non-buffered route has per-filter config %v, want none", er.TypedPerFilterConfig)
						}
						if wsDisabled(t, er) {
							t.Errorf("non-buffered route must keep the HCM websocket default")
						}
					case "buf", "bufmulti":
						buffered++
						cfg, ok := er.TypedPerFilterConfig[bufferFilterName]
						if !ok {
							t.Fatalf("buffered route %q has no buffer per-filter config", er.Name)
						}
						if got := unwrapBufferRouteConfig(t, cfg).GetBuffer().GetMaxRequestBytes().GetValue(); got != 1024 {
							t.Errorf("route %q max_request_bytes = %d, want 1024", er.Name, got)
						}
						if !wsDisabled(t, er) {
							t.Errorf("buffered route %q must disable the websocket upgrade", er.Name)
						}
						guard, ok := er.TypedPerFilterConfig[bufferLimitFilterName]
						if !ok {
							t.Fatalf("buffered route %q has no buffer-limit Lua config", er.Name)
						}
						if src := bufferLimitSource(t, guard); !strings.Contains(src, "> 1024 then") || strings.Contains(src, "2048") {
							t.Errorf("route %q buffer-limit source does not enforce 1024:\n%s", er.Name, src)
						}
						if _, ok := er.TypedPerFilterConfig[mutationFilterName]; ok {
							t.Errorf("route %q without header middleware has a mutation Lua config", er.Name)
						}
					case "bufhdr":
						cfg, ok := er.TypedPerFilterConfig[bufferFilterName]
						if !ok {
							t.Fatalf("route bufhdr has no buffer per-filter config")
						}
						if got := unwrapBufferRouteConfig(t, cfg).GetBuffer().GetMaxRequestBytes().GetValue(); got != 2048 {
							t.Errorf("route bufhdr max_request_bytes = %d, want 2048", got)
						}
						guard, ok := er.TypedPerFilterConfig[bufferLimitFilterName]
						if !ok {
							t.Fatalf("route bufhdr has no buffer-limit Lua config")
						}
						if src := bufferLimitSource(t, guard); !strings.Contains(src, "> 2048 then") {
							t.Errorf("route bufhdr buffer-limit source does not enforce 2048:\n%s", src)
						}
						mut, ok := er.TypedPerFilterConfig[mutationFilterName]
						if !ok {
							t.Fatalf("route bufhdr lost its header mutation Lua config")
						}
						lpr := &luav3.LuaPerRoute{}
						if err := mut.UnmarshalTo(lpr); err != nil || !strings.Contains(lpr.GetSourceCode().GetInlineString(), `replace("x-test", "1")`) {
							t.Errorf("route bufhdr mutation Lua = %v (err %v), want the x-test header replace", lpr, err)
						}
					}
				}
			}
			if buffered < 3 {
				t.Errorf("found %d buffered routes, want 3 (buf + two bufmulti DNF terms)", buffered)
			}
		})
	}
}

func TestBufferLimitLua(t *testing.T) {
	src := bufferLimitLua(1024)
	for _, want := range []string{
		"function envoy_on_request(handle)",
		// Declared size first: no body is read for an oversized Content-Length.
		`handle:headers():get("content-length")`,
		"if n == nil or n > 1024 then",
		// Actual size; body() is nil for header-only requests.
		"local body = handle:body()",
		"if body ~= nil and body:length() > 1024 then",
		`handle:respond({[":status"] = "413", ["content-type"] = "text/plain"}, "Payload Too Large")`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("bufferLimitLua(1024) missing %q:\n%s", want, src)
		}
	}
	if strings.Index(src, "content-length") > strings.Index(src, "handle:body()") {
		t.Errorf("Content-Length check must precede handle:body():\n%s", src)
	}
	if strings.Contains(src, "envoy_on_response") {
		t.Errorf("guard must not touch responses:\n%s", src)
	}
}
