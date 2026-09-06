package xds

import (
	"os"
	"sort"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	brotlicompressorv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/compression/brotli/compressor/v3"
	gzipcompressorv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/compression/gzip/compressor/v3"
	compressorv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/compressor/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
)

// gzipCompressorFilterName and brotliCompressorFilterName are distinct HTTP
// filter instance names: Envoy allows multiple envoy.filters.http.compressor
// instances in one filter chain as long as each has a unique filter name, and
// negotiates between them using the request's Accept-Encoding q-values.
const (
	gzipCompressorFilterName   = "envoy.filters.http.compressor.gzip"
	brotliCompressorFilterName = "envoy.filters.http.compressor.brotli"
)

// brotliSupported reports whether the linked Envoy build is assumed to
// support the brotli compressor extension. The go-control-plane API module
// pinned by this control plane (v1.37.0) always carries the brotli compressor
// proto definitions (compile-time feature detection: this file would fail to
// build against an older go-control-plane API lacking that package), but the
// *deployed Envoy binary* may have been built without brotli (it is an
// optional, non-default-in-some-distros extension). COMPRESSION_BROTLI_ENABLED
// lets an operator disable brotli negotiation for a build that lacks it,
// rather than this control plane silently assuming every Envoy binary
// supports it.
func brotliSupported() bool {
	return envBoolDefault("COMPRESSION_BROTLI_ENABLED", true)
}

// buildCompressorFilters returns the listener-level compressor HTTP filter(s)
// for the given merged compress configuration: always gzip, plus brotli when
// the linked Envoy build is expected to support it. Returns nil when cm is
// nil (no route configured a compress middleware).
func buildCompressorFilters(cm *model.CompressMiddleware) []*hcmv3.HttpFilter {
	if cm == nil {
		return nil
	}
	common := compressorCommonDirectionConfig(cm)

	filters := []*hcmv3.HttpFilter{
		compressorHTTPFilter(gzipCompressorFilterName, common, cm, "gzip", mustAny(&gzipcompressorv3.Gzip{})),
	}
	if brotliSupported() {
		filters = append(filters, compressorHTTPFilter(brotliCompressorFilterName, common, cm, "brotli", mustAny(&brotlicompressorv3.Brotli{})))
	}
	return filters
}

func compressorCommonDirectionConfig(cm *model.CompressMiddleware) *compressorv3.Compressor_CommonDirectionConfig {
	common := &compressorv3.Compressor_CommonDirectionConfig{}
	if cm.MinResponseBytes > 0 {
		common.MinContentLength = wrapperspb.UInt32(cm.MinResponseBytes)
	}
	if len(cm.ContentTypes) > 0 {
		types := append([]string(nil), cm.ContentTypes...)
		sort.Strings(types)
		common.ContentType = types
	}
	return common
}

// compressorHTTPFilter builds one compressor HTTP filter instance bound to a
// specific compression library (gzip or brotli). Only response-direction
// compression is configured: this control plane does not accept a
// request-direction knob in the compress middleware contract.
func compressorHTTPFilter(filterName string, common *compressorv3.Compressor_CommonDirectionConfig, cm *model.CompressMiddleware, libraryName string, libraryConfig *anypb.Any) *hcmv3.HttpFilter {
	compressor := &compressorv3.Compressor{
		CompressorLibrary: &corev3.TypedExtensionConfig{
			Name:        libraryName,
			TypedConfig: libraryConfig,
		},
		ResponseDirectionConfig: &compressorv3.Compressor_ResponseDirectionConfig{
			CommonConfig:        common,
			DisableOnEtagHeader: cm.DisableOnETagHeader,
		},
	}
	return &hcmv3.HttpFilter{
		Name:       filterName,
		ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: mustAny(compressor)},
	}
}

func envBoolDefault(name string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}
