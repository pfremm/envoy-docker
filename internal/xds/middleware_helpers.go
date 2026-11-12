package xds

import (
	"time"

	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	bufferv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/buffer/v3"
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
