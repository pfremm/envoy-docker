package xds

import (
	"fmt"
	"sort"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	corsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/cors/v3"
	luav3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	matcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
)

const (
	mutationFilterName   = "envoy.filters.http.lua"
	corsFilterName       = "envoy.filters.http.cors"
	compressorFilterName = "envoy.filters.http.compressor"
	bufferFilterName     = "envoy.filters.http.buffer"
	// bufferLimitFilterName is the Lua guard enforcing maxrequestbytes on
	// bodies the buffer filter lets through unchecked (bufferLimitHTTPFilter).
	bufferLimitFilterName = "envoy.filters.http.lua.buffer_limit"
	grpcWebFilterName     = "envoy.filters.http.grpc_web"
)

func applyRouteMiddlewares(er *routev3.Route, chain []model.Middleware) error {
	if len(chain) == 0 {
		return nil
	}
	if err := model.ValidateMiddlewareChain(chain); err != nil {
		return err
	}
	// The config-aware builder reapplies middleware after replacing the base
	// forwarding action, so reset only fields owned by this compiler.
	er.RequestHeadersToAdd = nil
	er.ResponseHeadersToAdd = nil
	er.RequestHeadersToRemove = nil
	er.ResponseHeadersToRemove = nil
	if er.TypedPerFilterConfig != nil {
		delete(er.TypedPerFilterConfig, mutationFilterName)
		delete(er.TypedPerFilterConfig, corsFilterName)
		delete(er.TypedPerFilterConfig, compressorFilterName)
		delete(er.TypedPerFilterConfig, bufferFilterName)
		delete(er.TypedPerFilterConfig, bufferLimitFilterName)
		delete(er.TypedPerFilterConfig, grpcWebFilterName)
	}
	var mutationOps []model.Middleware
	for _, m := range chain {
		switch {
		case m.RedirectScheme != nil:
			r := m.RedirectScheme
			code := routev3.RedirectAction_FOUND
			if r.Permanent {
				code = routev3.RedirectAction_MOVED_PERMANENTLY
			}
			er.Action = &routev3.Route_Redirect{Redirect: &routev3.RedirectAction{SchemeRewriteSpecifier: &routev3.RedirectAction_SchemeRedirect{SchemeRedirect: r.Scheme}, PortRedirect: r.Port, ResponseCode: code}}
		case m.RedirectRegex != nil:
			r := m.RedirectRegex
			code := routev3.RedirectAction_FOUND
			if r.Permanent {
				code = routev3.RedirectAction_MOVED_PERMANENTLY
			}
			er.Action = &routev3.Route_Redirect{Redirect: &routev3.RedirectAction{PathRewriteSpecifier: &routev3.RedirectAction_RegexRewrite{RegexRewrite: regexSubstitution(r.Regex, r.Replacement)}, ResponseCode: code}}
		case m.ReplacePathRegex != nil:
			// Keep regex rewriting in Envoy's native RE2 action. Lua patterns are
			// not regex-compatible, so chain validation makes this the sole path action.
			er.GetRoute().RegexRewrite = regexSubstitution(m.ReplacePathRegex.Regex, m.ReplacePathRegex.Replacement)
		case m.StripPrefix != nil || m.AddPrefix != nil || m.ReplacePath != nil || m.Headers != nil:
			mutationOps = append(mutationOps, m)
		case m.CORS != nil:
			if er.TypedPerFilterConfig == nil {
				er.TypedPerFilterConfig = map[string]*anypb.Any{}
			}
			er.TypedPerFilterConfig[corsFilterName] = mustAny(corsPolicy(m.CORS))
		case m.Retry != nil:
			if ra := er.GetRoute(); ra != nil {
				timeout, _ := parseDuration(m.Retry.PerTryTimeout)
				numRetries := uint32(0)
				if m.Retry.Attempts > 1 {
					numRetries = m.Retry.Attempts - 1
				}
				ra.RetryPolicy = &routev3.RetryPolicy{
					RetryOn:       m.Retry.RetryOn,
					NumRetries:    wrapperspb.UInt32(numRetries),
					PerTryTimeout: durationpb.New(timeout),
				}
			}
		case m.Buffering != nil:
			if er.TypedPerFilterConfig == nil {
				er.TypedPerFilterConfig = map[string]*anypb.Any{}
			}
			er.TypedPerFilterConfig[bufferFilterName] = bufferRouteFilterConfig(m.Buffering)
			er.TypedPerFilterConfig[bufferLimitFilterName] = bufferLimitRouteFilterConfig(m.Buffering)
		case m.Compress != nil:
			// Compression is listener-level in Envoy v1.37; per-route config is too limited.
			// Handled in planSecurity/listener assembly instead.
		case m.GRPCWeb != nil:
			// gRPC-Web is listener-level; handled in planSecurity/listener assembly.
		case m.CircuitBreaker != nil:
			// Circuit breakers are cluster-scoped; handled in cluster building.
		case m.Errors != nil:
			// Error pages require internal redirect; handled in route building.
		}
	}
	if len(mutationOps) > 0 {
		if er.TypedPerFilterConfig == nil {
			er.TypedPerFilterConfig = map[string]*anypb.Any{}
		}
		source := &corev3.DataSource{Specifier: &corev3.DataSource_InlineString{InlineString: mutationLua(mutationOps)}}
		er.TypedPerFilterConfig[mutationFilterName] = mustAny(&luav3.LuaPerRoute{Override: &luav3.LuaPerRoute_SourceCode{SourceCode: source}})
	}
	return nil
}

func regexSubstitution(pattern, replacement string) *matcherv3.RegexMatchAndSubstitute {
	return &matcherv3.RegexMatchAndSubstitute{Pattern: &matcherv3.RegexMatcher{EngineType: &matcherv3.RegexMatcher_GoogleRe2{GoogleRe2: &matcherv3.RegexMatcher_GoogleRE2{}}, Regex: pattern}, Substitution: envoyRegexReplacement(replacement)}
}

// envoyRegexReplacement translates Traefik/Go-style $1 and ${1} capture
// references to Envoy's RE2 substitution syntax (\1). $$ remains a literal $.
func envoyRegexReplacement(value string) string {
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] != '$' || i+1 >= len(value) {
			b.WriteByte(value[i])
			continue
		}
		if value[i+1] == '$' {
			b.WriteByte('$')
			i++
			continue
		}
		start, end := i+1, i+1
		braced := value[start] == '{'
		if braced {
			start++
			end = start
		}
		for end < len(value) && value[end] >= '0' && value[end] <= '9' {
			end++
		}
		if end == start || (braced && (end >= len(value) || value[end] != '}')) {
			b.WriteByte(value[i])
			continue
		}
		b.WriteByte('\\')
		b.WriteString(value[start:end])
		if braced {
			i = end
		} else {
			i = end - 1
		}
	}
	return b.String()
}

func corsPolicy(c *model.CORSMiddleware) *corsv3.CorsPolicy {
	p := &corsv3.CorsPolicy{AllowMethods: strings.Join(c.AllowMethods, ","), AllowHeaders: strings.Join(c.AllowHeaders, ","), ExposeHeaders: strings.Join(c.ExposeHeaders, ","), MaxAge: c.MaxAge, AllowCredentials: wrapperspb.Bool(c.AllowCredentials)}
	for _, origin := range c.AllowOrigins {
		matcher := &matcherv3.StringMatcher{MatchPattern: &matcherv3.StringMatcher_Exact{Exact: origin}}
		if origin == "*" {
			matcher.MatchPattern = &matcherv3.StringMatcher_Prefix{Prefix: ""}
		}
		p.AllowOriginStringMatch = append(p.AllowOriginStringMatch, matcher)
	}
	return p
}

func luaString(s string) string {
	r := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", "\\n", "\r", "\\r")
	return "\"" + r.Replace(s) + "\""
}

// mutationLua serializes path and header operations in router-list order.
// Query strings are preserved while only :path's path component changes.
func mutationLua(chain []model.Middleware) string {
	var request, response strings.Builder
	request.WriteString("function envoy_on_request(handle)\n  local full = handle:headers():get(\":path\")\n  local q = string.find(full, \"?\", 1, true)\n  local path = full\n  local query = \"\"\n  if q then path = string.sub(full, 1, q - 1); query = string.sub(full, q) end\n")
	response.WriteString("function envoy_on_response(handle)\n")
	pathChanged, responseChanged := false, false
	for _, m := range chain {
		switch {
		case m.StripPrefix != nil:
			pathChanged = true
			for i, p := range m.StripPrefix.Prefixes {
				kw := "if"
				if i > 0 {
					kw = "elseif"
				}
				fmt.Fprintf(&request, "  %s string.sub(path, 1, %d) == %s then path = string.sub(path, %d)\n", kw, len(p), luaString(p), len(p)+1)
			}
			request.WriteString("  end\n")
		case m.AddPrefix != nil:
			pathChanged = true
			fmt.Fprintf(&request, "  path = %s .. path\n", luaString(m.AddPrefix.Prefix))
		case m.ReplacePath != nil:
			pathChanged = true
			fmt.Fprintf(&request, "  path = %s\n", luaString(m.ReplacePath.Path))
		case m.Headers != nil:
			h := m.Headers
			requestKeys := make([]string, 0, len(h.Request))
			for k := range h.Request {
				requestKeys = append(requestKeys, k)
			}
			sort.Strings(requestKeys)
			for _, k := range requestKeys {
				fmt.Fprintf(&request, "  handle:headers():replace(%s, %s)\n", luaString(k), luaString(h.Request[k]))
			}
			for _, k := range h.RemoveRequest {
				fmt.Fprintf(&request, "  handle:headers():remove(%s)\n", luaString(k))
			}
		}
	}
	// Response callbacks unwind a middleware stack, so apply response mutations
	// in reverse chain order.
	for i := len(chain) - 1; i >= 0; i-- {
		h := chain[i].Headers
		if h == nil {
			continue
		}
		keys := make([]string, 0, len(h.Response))
		for k := range h.Response {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			responseChanged = true
			fmt.Fprintf(&response, "  handle:headers():replace(%s, %s)\n", luaString(k), luaString(h.Response[k]))
		}
		for _, k := range h.RemoveResponse {
			responseChanged = true
			fmt.Fprintf(&response, "  handle:headers():remove(%s)\n", luaString(k))
		}
	}
	if pathChanged {
		request.WriteString("  handle:headers():replace(\":path\", path .. query)\n")
	}
	request.WriteString("end\n")
	if responseChanged {
		response.WriteString("end\n")
		request.WriteString(response.String())
	}
	return request.String()
}
