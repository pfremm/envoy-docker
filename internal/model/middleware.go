package model

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type RedirectSchemeMiddleware struct {
	Scheme    string
	Port      uint32
	Permanent bool
}
type RedirectRegexMiddleware struct {
	Regex, Replacement string
	Permanent          bool
}
type StripPrefixMiddleware struct{ Prefixes []string }
type AddPrefixMiddleware struct{ Prefix string }
type ReplacePathMiddleware struct{ Path string }
type ReplacePathRegexMiddleware struct{ Regex, Replacement string }
type HeadersMiddleware struct {
	Request, Response             map[string]string
	RemoveRequest, RemoveResponse []string
}
type CORSMiddleware struct {
	AllowOrigins, AllowMethods, AllowHeaders, ExposeHeaders []string
	MaxAge                                                  string
	AllowCredentials                                        bool
}

// BasicAuthMiddleware configures Envoy's basic_auth filter. Users holds
// "user:htpasswd-hash" entries. It is security-critical: never log the Users
// values directly; use RedactedString() for any diagnostic output.
type BasicAuthMiddleware struct {
	Users        []string
	Realm        string
	HeaderField  string
	RemoveHeader bool
}

// ForwardAuthMiddleware configures Envoy's ext_authz filter to forward each
// request to an external authorization server at Address before it is routed.
// The server is modeled as an explicit Envoy cluster (see the xDS layer).
type ForwardAuthMiddleware struct {
	Address                 string
	TrustForwardHeader      bool
	AuthRequestHeaders      []string
	AuthResponseHeaders     []string
	AuthResponseHeaderRegex []string
	TLSInsecure             bool
	TLSServerName           string
}

// IPStrategy controls how the client IP is inferred for IP allow/deny lists.
// By default (Depth==0 and no ExcludedIPs) only the direct downstream address
// is trusted. Setting Depth trusts that many X-Forwarded-For hops.
type IPStrategy struct {
	Depth       uint32
	ExcludedIPs []string
}

// IPAllowListMiddleware allows only requests whose source IP matches one of
// SourceRange (CIDRs). Everything else is rejected (403).
type IPAllowListMiddleware struct {
	SourceRange []string
	Strategy    IPStrategy
}

// IPDenyListMiddleware rejects requests whose source IP matches one of
// SourceRange (CIDRs). Everything else is allowed.
type IPDenyListMiddleware struct {
	SourceRange []string
	Strategy    IPStrategy
}

// RateLimitMiddleware configures Envoy's local_ratelimit token bucket. The
// bucket is LOCAL to each Envoy proxy instance and route: it is not a shared or
// distributed limiter.
type RateLimitMiddleware struct {
	Average uint32
	Burst   uint32
	Period  string
}

// CompressMiddleware configures Envoy's compressor filter. ContentTypes and
// ExcludedContentTypes are MIME prefixes. DisableOnETagHeader prevents
// compression when a weak or strong ETag exists. Gzip is always enabled; brotli
// is enabled only if the linked Envoy build supports it (verified at build time).
type CompressMiddleware struct {
	MinResponseBytes     uint32
	ContentTypes         []string
	ExcludedContentTypes []string
	DisableOnETagHeader  bool
}

// RetryMiddleware configures Envoy's per-route retry policy. Attempts is the
// maximum number of tries (including the original request). PerTryTimeout is the
// timeout for each individual attempt. RetryOn is an Envoy retry condition string.
type RetryMiddleware struct {
	Attempts      uint32
	PerTryTimeout string
	RetryOn       string
}

// CircuitBreakerMiddleware configures Envoy cluster-scoped circuit breaker
// thresholds. Because breakers are cluster-scoped, the xDS layer derives
// deterministic cluster variants when policies differ and deduplicates identical ones.
type CircuitBreakerMiddleware struct {
	MaxConnections     uint32
	MaxPendingRequests uint32
	MaxRequests        uint32
	MaxRetries         uint32
}

// BufferingMiddleware configures Envoy's buffer filter. MaxRequestBytes and
// MaxResponseBytes set the maximum body sizes. MemRequestBytes and MemResponseBytes
// set in-memory buffer limits before spilling to disk. RetryExpression is unsupported
// and rejected.
type BufferingMiddleware struct {
	MaxRequestBytes  uint32
	MaxResponseBytes uint32
	MemRequestBytes  uint32
	MemResponseBytes uint32
	RetryExpression  string
}

// ErrorsMiddleware configures custom error-page handling. Status is a comma-separated
// list of HTTP status codes or ranges (e.g. "404,500-599"). Service must resolve
// through named HTTP services. Query is the path/query to forward to the error service.
// Error handling must not recurse.
type ErrorsMiddleware struct {
	Status  []string
	Service string
	Query   string
}

// GRPCWebMiddleware enables Envoy's grpc_web filter. When enabled, CORS, compression,
// and filter ordering must be valid, and upstream protocol validation is enforced.
type GRPCWebMiddleware struct {
	Enabled bool
}

// Middleware is a closed typed union. Exactly one variant must be non-nil.
type Middleware struct {
	Name             string
	RedirectScheme   *RedirectSchemeMiddleware
	RedirectRegex    *RedirectRegexMiddleware
	StripPrefix      *StripPrefixMiddleware
	AddPrefix        *AddPrefixMiddleware
	ReplacePath      *ReplacePathMiddleware
	ReplacePathRegex *ReplacePathRegexMiddleware
	Headers          *HeadersMiddleware
	CORS             *CORSMiddleware
	BasicAuth        *BasicAuthMiddleware
	ForwardAuth      *ForwardAuthMiddleware
	IPAllowList      *IPAllowListMiddleware
	IPDenyList       *IPDenyListMiddleware
	RateLimit        *RateLimitMiddleware
	Compress         *CompressMiddleware
	Retry            *RetryMiddleware
	CircuitBreaker   *CircuitBreakerMiddleware
	Buffering        *BufferingMiddleware
	Errors           *ErrorsMiddleware
	GRPCWeb          *GRPCWebMiddleware
}

func (m Middleware) Type() string {
	values := []struct {
		name string
		set  bool
	}{
		{"redirectscheme", m.RedirectScheme != nil}, {"redirectregex", m.RedirectRegex != nil},
		{"stripprefix", m.StripPrefix != nil}, {"addprefix", m.AddPrefix != nil},
		{"replacepath", m.ReplacePath != nil}, {"replacepathregex", m.ReplacePathRegex != nil},
		{"headers", m.Headers != nil}, {"cors", m.CORS != nil},
		{"basicauth", m.BasicAuth != nil}, {"forwardauth", m.ForwardAuth != nil},
		{"ipallowlist", m.IPAllowList != nil}, {"ipdenylist", m.IPDenyList != nil},
		{"ratelimit", m.RateLimit != nil},
		{"compress", m.Compress != nil}, {"retry", m.Retry != nil},
		{"circuitbreaker", m.CircuitBreaker != nil}, {"buffering", m.Buffering != nil},
		{"errors", m.Errors != nil}, {"grpcweb", m.GRPCWeb != nil},
	}
	found := ""
	for _, v := range values {
		if v.set {
			if found != "" {
				return ""
			}
			found = v.name
		}
	}
	return found
}

// RedactedString renders a middleware for logging/diagnostics WITHOUT leaking
// secrets. Basic auth user:hash entries are replaced with [REDACTED]; no other
// middleware type carries secret material but is rendered uniformly.
func (m Middleware) RedactedString() string {
	switch m.Type() {
	case "basicauth":
		return fmt.Sprintf("basicauth(users=[REDACTED], realm=%q, headerfield=%q, removeheader=%v)",
			m.BasicAuth.Realm, m.BasicAuth.HeaderField, m.BasicAuth.RemoveHeader)
	case "forwardauth":
		return fmt.Sprintf("forwardauth(address=%q, trustforwardheader=%v, tls.insecure=%v, tls.servername=%q)",
			m.ForwardAuth.Address, m.ForwardAuth.TrustForwardHeader, m.ForwardAuth.TLSInsecure, m.ForwardAuth.TLSServerName)
	case "ipallowlist":
		return fmt.Sprintf("ipallowlist(sourcerange=%v)", m.IPAllowList.SourceRange)
	case "ipdenylist":
		return fmt.Sprintf("ipdenylist(sourcerange=%v)", m.IPDenyList.SourceRange)
	case "ratelimit":
		return fmt.Sprintf("ratelimit(average=%d, burst=%d, period=%s)", m.RateLimit.Average, m.RateLimit.Burst, m.RateLimit.Period)
	default:
		return m.Type()
	}
}

var headerToken = regexp.MustCompile("^[!#$%&'*+\\-.^_`|~0-9A-Za-z]+$")

func validateHeaderName(name string) error {
	if strings.HasPrefix(name, ":") {
		return fmt.Errorf("unsafe pseudo-header %q cannot be mutated", name)
	}
	if !headerToken.MatchString(name) {
		return fmt.Errorf("invalid HTTP header name %q", name)
	}
	return nil
}

// parseCIDR parses a CIDR ("10.0.0.0/8") or a bare IP ("10.0.0.5") into a
// network prefix and prefix length. It is used to validate IP allow/deny lists
// and to build Envoy CidrRange principals.
func parseCIDR(value string) (prefix string, prefixLen uint32, err error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", 0, fmt.Errorf("empty CIDR")
	}
	if strings.Contains(value, "/") {
		_, ipNet, perr := net.ParseCIDR(value)
		if perr != nil {
			return "", 0, fmt.Errorf("invalid CIDR %q: %w", value, perr)
		}
		ones, _ := ipNet.Mask.Size()
		return ipNet.IP.String(), uint32(ones), nil
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return "", 0, fmt.Errorf("invalid IP address %q", value)
	}
	if ip.To4() != nil {
		return ip.String(), 32, nil
	}
	return ip.String(), 128, nil
}

func validateIPList(name string, list []string) error {
	if len(list) == 0 {
		return fmt.Errorf("%s cannot be empty", name)
	}
	for _, c := range list {
		if _, _, err := parseCIDR(c); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func ValidateMiddlewareChain(chain []Middleware) error {
	redirects := 0
	pathOps := 0
	hasRegexPath := false
	redirectSeen := false
	corsSeen := false
	securityFilters := map[string]string{}
	for _, m := range chain {
		if err := m.Validate(); err != nil {
			return err
		}
		if corsSeen {
			return fmt.Errorf("middleware %q follows CORS; CORS must be last when composed", m.Name)
		}
		isRedirect := m.RedirectScheme != nil || m.RedirectRegex != nil
		if redirectSeen {
			return fmt.Errorf("middleware %q follows a terminal redirect", m.Name)
		}
		if isRedirect {
			redirects++
			redirectSeen = true
		}
		if m.StripPrefix != nil || m.AddPrefix != nil || m.ReplacePath != nil || m.ReplacePathRegex != nil {
			pathOps++
		}
		if m.ReplacePathRegex != nil {
			hasRegexPath = true
		}
		if m.CORS != nil {
			corsSeen = true
		}
		filter := ""
		switch {
		case m.BasicAuth != nil:
			filter = "basic_auth"
		case m.ForwardAuth != nil:
			filter = "ext_authz"
		case m.IPAllowList != nil || m.IPDenyList != nil:
			filter = "rbac"
		case m.RateLimit != nil:
			filter = "local_ratelimit"
		// Resilience/protocol middleware are each a singleton concept at the
		// listener, cluster, or route level: two of the same type in one
		// chain would be ambiguous (which policy wins?) rather than a
		// deliberate composition, so reject it the same way security
		// filters are protected from silent overwrite.
		case m.Retry != nil:
			filter = "retry"
		case m.Compress != nil:
			filter = "compress"
		case m.CircuitBreaker != nil:
			filter = "circuitbreaker"
		case m.Buffering != nil:
			filter = "buffering"
		case m.Errors != nil:
			filter = "errors"
		case m.GRPCWeb != nil:
			filter = "grpcweb"
		}
		if filter != "" {
			if prior := securityFilters[filter]; prior != "" {
				return fmt.Errorf("middleware %q and %q both configure Envoy filter %s; same-filter security middleware cannot be composed without silent overwrite", prior, m.Name, filter)
			}
			securityFilters[filter] = m.Name
		}
	}
	if redirects > 1 {
		return fmt.Errorf("middleware chain contains %d redirects; at most one terminal redirect is allowed", redirects)
	}
	if hasRegexPath && (pathOps > 1 || redirects > 0) {
		return fmt.Errorf("replacepathregex must be the chain's only path/redirect action so Envoy can preserve RE2 semantics")
	}
	return nil
}

func (m Middleware) Validate() error {
	if strings.TrimSpace(m.Name) == "" {
		return fmt.Errorf("middleware name is empty")
	}
	t := m.Type()
	if t == "" {
		return fmt.Errorf("middleware %q must define exactly one type", m.Name)
	}
	requiredPath := func(field, value string) error {
		if value == "" || !strings.HasPrefix(value, "/") {
			return fmt.Errorf("middleware %q %s must start with /", m.Name, field)
		}
		return nil
	}
	switch t {
	case "redirectscheme":
		if m.RedirectScheme.Scheme == "" {
			return fmt.Errorf("middleware %q redirectscheme.scheme is required", m.Name)
		}
		if m.RedirectScheme.Port > 65535 {
			return fmt.Errorf("middleware %q redirectscheme.port is out of range", m.Name)
		}
	case "redirectregex":
		if _, err := regexp.Compile(m.RedirectRegex.Regex); err != nil {
			return fmt.Errorf("middleware %q redirectregex.regex: %w", m.Name, err)
		}
		if m.RedirectRegex.Regex == "" || m.RedirectRegex.Replacement == "" {
			return fmt.Errorf("middleware %q redirectregex requires regex and replacement", m.Name)
		}
	case "stripprefix":
		if len(m.StripPrefix.Prefixes) == 0 {
			return fmt.Errorf("middleware %q stripprefix.prefixes cannot be empty", m.Name)
		}
		for _, p := range m.StripPrefix.Prefixes {
			if err := requiredPath("stripprefix.prefixes", p); err != nil {
				return err
			}
		}
	case "addprefix":
		return requiredPath("addprefix.prefix", m.AddPrefix.Prefix)
	case "replacepath":
		return requiredPath("replacepath.path", m.ReplacePath.Path)
	case "replacepathregex":
		if _, err := regexp.Compile(m.ReplacePathRegex.Regex); err != nil {
			return fmt.Errorf("middleware %q replacepathregex.regex: %w", m.Name, err)
		}
		if m.ReplacePathRegex.Regex == "" || m.ReplacePathRegex.Replacement == "" {
			return fmt.Errorf("middleware %q replacepathregex requires regex and replacement", m.Name)
		}
	case "headers":
		if len(m.Headers.Request)+len(m.Headers.Response)+len(m.Headers.RemoveRequest)+len(m.Headers.RemoveResponse) == 0 {
			return fmt.Errorf("middleware %q headers has no operations", m.Name)
		}
		for n := range m.Headers.Request {
			if err := validateHeaderName(n); err != nil {
				return err
			}
		}
		for n := range m.Headers.Response {
			if err := validateHeaderName(n); err != nil {
				return err
			}
		}
		for _, names := range [][]string{m.Headers.RemoveRequest, m.Headers.RemoveResponse} {
			for _, n := range names {
				if err := validateHeaderName(n); err != nil {
					return err
				}
			}
		}
	case "cors":
		if len(m.CORS.AllowOrigins) == 0 {
			return fmt.Errorf("middleware %q cors.alloworigins cannot be empty", m.Name)
		}
		if m.CORS.MaxAge != "" {
			age, err := strconv.ParseUint(m.CORS.MaxAge, 10, 64)
			if err != nil {
				return fmt.Errorf("middleware %q cors.maxage must be a non-negative integer number of seconds", m.Name)
			}
			_ = age
		}
	case "basicauth":
		if len(m.BasicAuth.Users) == 0 {
			return fmt.Errorf("middleware %q basicauth.users cannot be empty", m.Name)
		}
		for _, u := range m.BasicAuth.Users {
			if strings.ContainsAny(u, "\r\n") {
				return fmt.Errorf("middleware %q basicauth.users entries cannot contain CR or LF", m.Name)
			}
			user, hash, ok := strings.Cut(u, ":")
			if !ok {
				// Do not echo the raw entry: it may contain a hash.
				return fmt.Errorf("middleware %q basicauth.users entries must be user:htpasswd-hash", m.Name)
			}
			if strings.TrimSpace(user) == "" {
				return fmt.Errorf("middleware %q basicauth.users has an entry with an empty username", m.Name)
			}
			if hash == "" {
				return fmt.Errorf("middleware %q basicauth.users has an entry with an empty hash", m.Name)
			}
			if !strings.HasPrefix(hash, "{SHA}") {
				return fmt.Errorf("middleware %q basicauth.users contains an htpasswd hash unsupported by this Envoy build; use {SHA}", m.Name)
			}
			decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(hash, "{SHA}"))
			if err != nil || len(decoded) != 20 {
				return fmt.Errorf("middleware %q basicauth.users contains an invalid {SHA} htpasswd hash", m.Name)
			}
		}
		if m.BasicAuth.HeaderField != "" {
			if err := validateHeaderName(m.BasicAuth.HeaderField); err != nil {
				return fmt.Errorf("middleware %q basicauth.headerfield: %w", m.Name, err)
			}
		}
		if strings.ContainsAny(m.BasicAuth.Realm, "\r\n") {
			return fmt.Errorf("middleware %q basicauth.realm cannot contain CR or LF", m.Name)
		}
	case "forwardauth":
		if strings.TrimSpace(m.ForwardAuth.Address) == "" {
			return fmt.Errorf("middleware %q forwardauth.address is required", m.Name)
		}
		address := m.ForwardAuth.Address
		if strings.Contains(address, "://") {
			u, err := url.ParseRequestURI(address)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
				return fmt.Errorf("middleware %q forwardauth.address must be an http(s) URL or host[:port]", m.Name)
			}
			if u.RawQuery != "" || u.Fragment != "" {
				return fmt.Errorf("middleware %q forwardauth.address query strings and fragments are not supported by Envoy ext_authz", m.Name)
			}
			address = u.Host
		}
		host, portStr, perr := net.SplitHostPort(address)
		if perr != nil {
			// Allow a bare host (no port); a bare IP or hostname is fine.
			if net.ParseIP(address) == nil && !isLikelyHostname(address) {
				return fmt.Errorf("middleware %q forwardauth.address %q is not a valid host:port", m.Name, m.ForwardAuth.Address)
			}
			host = address
			portStr = ""
		}
		if host == "" {
			return fmt.Errorf("middleware %q forwardauth.address has an empty host", m.Name)
		}
		if portStr != "" {
			p, uerr := strconv.ParseUint(portStr, 10, 16)
			if uerr != nil || p == 0 || p > 65535 {
				return fmt.Errorf("middleware %q forwardauth.address has an invalid port", m.Name)
			}
		}
		if m.ForwardAuth.TLSInsecure && m.ForwardAuth.TLSServerName == "" {
			// insecure without SNI is allowed (e.g. IP endpoints); nothing to reject.
		}
		for _, header := range append(append([]string(nil), m.ForwardAuth.AuthRequestHeaders...), m.ForwardAuth.AuthResponseHeaders...) {
			if err := validateHeaderName(header); err != nil {
				return fmt.Errorf("middleware %q forwardauth header: %w", m.Name, err)
			}
		}
		for _, pattern := range m.ForwardAuth.AuthResponseHeaderRegex {
			if _, err := regexp.Compile(pattern); err != nil {
				return fmt.Errorf("middleware %q forwardauth.authresponseheaderregex %q: %w", m.Name, pattern, err)
			}
		}
	case "ipallowlist":
		if err := validateIPList(fmt.Sprintf("middleware %q ipallowlist.sourcerange", m.Name), m.IPAllowList.SourceRange); err != nil {
			return err
		}
		if err := validateIPStrategy(m.Name, "ipallowlist", m.IPAllowList.Strategy); err != nil {
			return err
		}
	case "ipdenylist":
		if err := validateIPList(fmt.Sprintf("middleware %q ipdenylist.sourcerange", m.Name), m.IPDenyList.SourceRange); err != nil {
			return err
		}
		if err := validateIPStrategy(m.Name, "ipdenylist", m.IPDenyList.Strategy); err != nil {
			return err
		}
	case "ratelimit":
		if m.RateLimit.Average == 0 {
			return fmt.Errorf("middleware %q ratelimit.average must be > 0", m.Name)
		}
		if m.RateLimit.Burst == 0 {
			return fmt.Errorf("middleware %q ratelimit.burst must be > 0", m.Name)
		}
		if m.RateLimit.Period == "" {
			return fmt.Errorf("middleware %q ratelimit.period is required", m.Name)
		}
		period, err := time.ParseDuration(m.RateLimit.Period)
		if err != nil {
			return fmt.Errorf("middleware %q ratelimit.period %q is not a valid duration", m.Name, m.RateLimit.Period)
		}
		if period < 50*time.Millisecond {
			return fmt.Errorf("middleware %q ratelimit.period must be at least 50ms for Envoy local_ratelimit", m.Name)
		}
	case "compress":
		// MinResponseBytes defaults to 30 if zero; no validation error
		for _, ct := range m.Compress.ContentTypes {
			if strings.TrimSpace(ct) == "" {
				return fmt.Errorf("middleware %q compress.contenttypes cannot contain empty values", m.Name)
			}
		}
		// Envoy's compressor filter only exposes an allow-list
		// (content_type on CommonDirectionConfig); there is no native
		// deny-list. Reject rather than silently ignoring so a
		// configured exclusion is never mistaken for enforced behavior.
		if len(m.Compress.ExcludedContentTypes) > 0 {
			return fmt.Errorf("middleware %q compress.excludedcontenttypes is not supported by this Envoy build (the compressor filter only exposes an allow-list via contenttypes, no deny-list); omit it or use contenttypes instead", m.Name)
		}
	case "retry":
		if m.Retry.Attempts == 0 {
			return fmt.Errorf("middleware %q retry.attempts must be > 0", m.Name)
		}
		if m.Retry.PerTryTimeout == "" {
			return fmt.Errorf("middleware %q retry.pertrytimeout is required", m.Name)
		}
		if _, err := time.ParseDuration(m.Retry.PerTryTimeout); err != nil {
			return fmt.Errorf("middleware %q retry.pertrytimeout %q is not a valid duration", m.Name, m.Retry.PerTryTimeout)
		}
		if m.Retry.RetryOn == "" {
			return fmt.Errorf("middleware %q retry.retryon is required", m.Name)
		}
	case "circuitbreaker":
		if m.CircuitBreaker.MaxConnections == 0 && m.CircuitBreaker.MaxPendingRequests == 0 &&
			m.CircuitBreaker.MaxRequests == 0 && m.CircuitBreaker.MaxRetries == 0 {
			return fmt.Errorf("middleware %q circuitbreaker must configure at least one threshold", m.Name)
		}
	case "buffering":
		// Envoy's buffer filter (envoy.filters.http.buffer) only exposes
		// max_request_bytes; it has no response-body limit and no
		// in-memory-vs-disk spill knob. Reject the unsupported settings
		// clearly instead of silently dropping them.
		if m.Buffering.RetryExpression != "" {
			return fmt.Errorf("middleware %q buffering.retryexpression is not supported by this Envoy build", m.Name)
		}
		if m.Buffering.MaxResponseBytes != 0 {
			return fmt.Errorf("middleware %q buffering.maxresponsebytes is not supported by this Envoy build (the buffer filter only limits request bodies); omit it", m.Name)
		}
		if m.Buffering.MemRequestBytes != 0 {
			return fmt.Errorf("middleware %q buffering.memrequestbytes is not supported by this Envoy build (the buffer filter has no in-memory-vs-disk spill setting); omit it", m.Name)
		}
		if m.Buffering.MemResponseBytes != 0 {
			return fmt.Errorf("middleware %q buffering.memresponsebytes is not supported by this Envoy build (the buffer filter has no in-memory-vs-disk spill setting); omit it", m.Name)
		}
		if m.Buffering.MaxRequestBytes == 0 {
			return fmt.Errorf("middleware %q buffering.maxrequestbytes is required (the only supported buffering threshold)", m.Name)
		}
	case "errors":
		if len(m.Errors.Status) == 0 {
			return fmt.Errorf("middleware %q errors.status cannot be empty", m.Name)
		}
		for _, s := range m.Errors.Status {
			// Accept "404" or "500-599"
			if strings.Contains(s, "-") {
				parts := strings.Split(s, "-")
				if len(parts) != 2 {
					return fmt.Errorf("middleware %q errors.status range %q must be start-end", m.Name, s)
				}
				start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
				end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
				if err1 != nil || err2 != nil || start < 100 || end > 599 || start > end {
					return fmt.Errorf("middleware %q errors.status range %q is invalid", m.Name, s)
				}
			} else {
				code, err := strconv.Atoi(strings.TrimSpace(s))
				if err != nil || code < 100 || code > 599 {
					return fmt.Errorf("middleware %q errors.status code %q is invalid", m.Name, s)
				}
			}
		}
		if strings.TrimSpace(m.Errors.Service) == "" {
			return fmt.Errorf("middleware %q errors.service is required", m.Name)
		}
		if m.Errors.Query != "" && !strings.HasPrefix(m.Errors.Query, "/") {
			return fmt.Errorf("middleware %q errors.query must start with /", m.Name)
		}
	case "grpcweb":
		if !m.GRPCWeb.Enabled {
			return fmt.Errorf("middleware %q grpcweb.enabled must be true (or omit the middleware)", m.Name)
		}
	}
	return nil
}

func validateIPStrategy(mwName, field string, s IPStrategy) error {
	if s.Depth > 0 && len(s.ExcludedIPs) > 0 {
		return fmt.Errorf("middleware %q %s.ipstrategy.depth and excludedips are mutually exclusive", mwName, field)
	}
	if len(s.ExcludedIPs) > 0 {
		for _, c := range s.ExcludedIPs {
			if _, _, err := parseCIDR(c); err != nil {
				return fmt.Errorf("middleware %q %s.ipstrategy.excludedips: %w", mwName, field, err)
			}
		}
	}
	return nil
}

// isLikelyHostname reports whether s looks like a DNS hostname (labels of
// letters/digits/hyphens, dot-separated). Used to accept a bare host in a
// forwardauth.address that has no explicit port.
func isLikelyHostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
