package xds

import (
	"time"

	bufferv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/buffer/v3"
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

// parseDuration is a helper to parse Go duration strings. We trust that
// validation has already happened in the model layer, so errors are
// ignored and return zero.
func parseDuration(s string) (time.Duration, error) {
	return time.ParseDuration(s)
}
