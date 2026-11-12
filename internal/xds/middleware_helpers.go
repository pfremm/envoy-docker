package xds

import (
	"fmt"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	bufferv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/buffer/v3"
	luav3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
)

// bufferPerRoute builds the per-route buffer configuration.
// Envoy's buffer filter only supports max_request_bytes at the per-route level.
func bufferPerRoute(b *model.BufferingMiddleware) *bufferv3.BufferPerRoute {
	cfg := &bufferv3.BufferPerRoute{
		Override: &bufferv3.BufferPerRoute_Buffer{
			Buffer: &bufferv3.Buffer{},
		},
	}
	if b.MaxRequestBytes > 0 {
		cfg.GetBuffer().MaxRequestBytes = wrapperspb.UInt32(b.MaxRequestBytes)
	}
	return cfg
}

// bufferFilterPlaceholderBytes satisfies the buffer filter's required
// max_request_bytes on the listener-level filter. It never takes effect: the
// listener filter is disabled and every route that enables it supplies its
// own limit via bufferPerRoute.
const bufferFilterPlaceholderBytes = 1 << 20

// bufferHTTPFilter builds the listener-level buffer HTTP filter, disabled by
// default. A buffer filter active listener-wide would hold every request until
// end of body, which never arrives on a WebSocket upgrade, hanging every
// handshake on the listener. Routes with a buffering middleware enable it
// individually (bufferRouteFilterConfig).
func bufferHTTPFilter() *hcmv3.HttpFilter {
	return &hcmv3.HttpFilter{
		Name: bufferFilterName,
		ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: mustAny(&bufferv3.Buffer{
			MaxRequestBytes: wrapperspb.UInt32(bufferFilterPlaceholderBytes),
		})},
		Disabled: true,
	}
}

// bufferRouteFilterConfig enables the (listener-disabled) buffer filter on one
// route with that route's limit. Any per-route config enables a filter that is
// disabled in the HCM; wrapping it in a FilterConfig with disabled=false makes
// the enable explicit instead of a side effect of carrying an override.
func bufferRouteFilterConfig(b *model.BufferingMiddleware) *anypb.Any {
	return mustAny(&routev3.FilterConfig{Config: mustAny(bufferPerRoute(b)), Disabled: false})
}

// bufferLimitHTTPFilter builds the listener-level Lua size guard that backs up
// the buffer filter, disabled by default like it. Envoy's buffer filter only
// checks max_request_bytes while it accumulates a body across several
// decodeData calls; an HTTP/2 body that arrives complete in one DATA frame
// with END_STREAM is passed straight through and never checked. Buffered
// routes enable this filter with bufferLimitRouteFilterConfig.
func bufferLimitHTTPFilter() *hcmv3.HttpFilter {
	noop := &corev3.DataSource{Specifier: &corev3.DataSource_InlineString{InlineString: "function envoy_on_request(handle) end\n"}}
	return &hcmv3.HttpFilter{
		Name:       bufferLimitFilterName,
		ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: mustAny(&luav3.Lua{DefaultSourceCode: noop})},
		Disabled:   true,
	}
}

// bufferLimitLua rejects a request whose declared (Content-Length) or actual
// body size exceeds limit with the same 413 and body Envoy's buffer filter
// sends. handle:body() returns nil for header-only requests (GET), so those
// are never held. The guard runs after the buffer filter, which has already
// received the whole body (or rejected it) by the time this script starts
// and sets Content-Length to the received size, so reading the body here adds
// no extra wait and memory stays bounded by the buffer filter's limit.
func bufferLimitLua(limit uint32) string {
	return fmt.Sprintf(`function envoy_on_request(handle)
  local cl = handle:headers():get("content-length")
  if cl ~= nil then
    local n = tonumber(cl)
    if n == nil or n > %[1]d then
      handle:respond({[":status"] = "413", ["content-type"] = "text/plain"}, "Payload Too Large")
      return
    end
  end
  local body = handle:body()
  if body ~= nil and body:length() > %[1]d then
    handle:respond({[":status"] = "413", ["content-type"] = "text/plain"}, "Payload Too Large")
  end
end
`, limit)
}

// bufferLimitRouteFilterConfig enables the (listener-disabled) Lua size guard
// on one buffered route with that route's limit.
func bufferLimitRouteFilterConfig(b *model.BufferingMiddleware) *anypb.Any {
	source := &corev3.DataSource{Specifier: &corev3.DataSource_InlineString{InlineString: bufferLimitLua(b.MaxRequestBytes)}}
	return mustAny(&luav3.LuaPerRoute{Override: &luav3.LuaPerRoute_SourceCode{SourceCode: source}})
}

// routeHasBuffering reports whether a route's middleware chain buffers
// request bodies.
func routeHasBuffering(route model.Route) bool {
	for _, m := range route.Middlewares {
		if m.Buffering != nil {
			return true
		}
	}
	return false
}

// parseDuration is a helper to parse Go duration strings. We trust that
// validation has already happened in the model layer, so errors are
// ignored and return zero.
func parseDuration(s string) (time.Duration, error) {
	return time.ParseDuration(s)
}
