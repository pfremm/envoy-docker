// Package xds builds Envoy xDS resources (LDS/RDS/CDS/EDS) from a route map
// and serves them over ADS.
package xds

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	rbacv3 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	basicauthv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/basic_auth/v3"
	extauthzv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	localrlv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/local_ratelimit/v3"
	luav3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	rbachttpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	matcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	tokenbucketv3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
)

// Security filter names. Listener assembly keeps cheap/local checks before
// mutation, runs external authorization after mutation so it sees the request
// the upstream would receive, then removes BasicAuth credentials before
// CORS/router dispatch.
const (
	extAuthzFilterName        = "envoy.filters.http.ext_authz"
	basicAuthFilterName       = "envoy.filters.http.basic_auth"
	basicAuthRealmFilterName  = "envoy.filters.http.lua.basic_auth_realm"
	basicAuthRemoveFilterName = "envoy.filters.http.lua.basic_auth_remove"
	rbacFilterName            = "envoy.filters.http.rbac"
	localRLFilterName         = "envoy.filters.http.local_ratelimit"
)

// defaultAuthzTimeout bounds how long a forwardauth check may take before the
// request fails closed (503). Envoy's ext_authz default is 20s, far too long
// for a gateway; 2s fails fast without punishing a slow-but-healthy service.
const defaultAuthzTimeout = 2 * time.Second

// securityPlan is the listener-wide security configuration derived from every
// route's middleware chain: the HTTPS listener's security filter chain, the
// static CDS auth clusters, and the XFF trust depth. It is computed once per
// snapshot so the listener filter chain and the CDS auth clusters agree.
//
// Per-route security configs (basic_auth user list, ext_authz cluster
// override, RBAC IP policy) are NOT stored here: they depend on a specific
// route's middleware chain and are computed on demand by
// applyRouteSecurity, so that routes using the same filter type with
// different settings (e.g. two forwardauth middlewares pointing at different
// auth services) do not overwrite each other.
type securityPlan struct {
	listenerFilters   []*hcmv3.HttpFilter
	authClusters      []*clusterv3.Cluster
	xffNumTrustedHops uint32
	xffTrustedCIDRs   []string
}

// planSecurity inspects every route's middleware chain and produces the
// listener-wide security configuration. It returns an error when settings that
// Envoy exposes only listener-wide conflict, such as BasicAuth username-header
// configuration or original-IP detection strategy.
func planSecurity(routes map[string]model.Route) (*securityPlan, error) {
	p := &securityPlan{}

	var (
		needExtAuthz, needBasicAuth, needBasicAuthRealm, needBasicAuthRemove, needRBAC, needLocalRL bool
		basicAuthMain                                                                               *basicauthv3.BasicAuth
		authServices                                                                                = map[string]*authService{}
		firstForwardAuth                                                                            *model.ForwardAuthMiddleware
		firstForwardAuthCluster                                                                     string
	)

	names := sortedSubdomains(routes)
	for _, name := range names {
		route := routes[name]
		for _, m := range route.Middlewares {
			switch {
			case m.BasicAuth != nil:
				needBasicAuth = true
				needBasicAuthRealm = needBasicAuthRealm || m.BasicAuth.Realm != ""
				needBasicAuthRemove = needBasicAuthRemove || m.BasicAuth.RemoveHeader
				if basicAuthMain == nil {
					// BasicAuth requires a global users source even though every
					// route supplies its own override. HeaderField follows the
					// Traefik contract: it receives the authenticated username.
					basicAuthMain = &basicauthv3.BasicAuth{
						Users: basicAuthUsers(m.BasicAuth.Users),
					}
					if m.BasicAuth.HeaderField != "" {
						basicAuthMain.ForwardUsernameHeader = m.BasicAuth.HeaderField
					}
				} else if m.BasicAuth.HeaderField != basicAuthMain.ForwardUsernameHeader {
					return nil, fmt.Errorf(
						"route %q: conflicting basicauth.headerfield %q; all routes must agree on the basic-auth username header",
						name, m.BasicAuth.HeaderField)
				}
			case m.ForwardAuth != nil:
				needExtAuthz = true
				clusterName := authClusterName(m.Name)
				if firstForwardAuth == nil {
					firstForwardAuth = m.ForwardAuth
					firstForwardAuthCluster = clusterName
				}
				if svc, exists := authServices[clusterName]; !exists {
					authServices[clusterName] = &authService{
						address:    m.ForwardAuth.Address,
						insecure:   m.ForwardAuth.TLSInsecure,
						serverName: m.ForwardAuth.TLSServerName,
						useTLS:     !strings.HasPrefix(strings.ToLower(m.ForwardAuth.Address), "http://"),
					}
				} else if svc.address != m.ForwardAuth.Address || svc.insecure != m.ForwardAuth.TLSInsecure || svc.serverName != m.ForwardAuth.TLSServerName {
					return nil, fmt.Errorf(
						"route %q: forwardauth middleware %q maps to cluster %q but a different middleware already defined conflicting address/TLS settings",
						name, m.Name, clusterName)
				}
			case m.IPAllowList != nil:
				needRBAC = true
			case m.IPDenyList != nil:
				needRBAC = true
			case m.RateLimit != nil:
				needLocalRL = true
			}
		}
	}

	// Envoy v1.37 cannot disable basic_auth per route. Reject mixed BasicAuth
	// coverage rather than accidentally protecting a route that did not opt in.
	// ext_authz does support an explicit per-route disabled override, which is
	// installed later for routes that do not reference ForwardAuth.
	if needBasicAuth {
		for _, name := range names {
			hasBasic := false
			for _, m := range routes[name].Middlewares {
				hasBasic = hasBasic || m.BasicAuth != nil
			}
			if !hasBasic {
				return nil, fmt.Errorf("route %q has no basicauth middleware; Envoy basic_auth cannot be disabled per route", name)
			}
		}
	}

	// Build the security portion in deterministic order. Listener assembly later
	// moves ext_authz after mutation and keeps credential removal after ext_authz.
	if needLocalRL {
		p.listenerFilters = append(p.listenerFilters, &hcmv3.HttpFilter{
			Name: localRLFilterName,
			ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: mustAny(&localrlv3.LocalRateLimit{
				StatPrefix: "local_ratelimit",
			})},
		})
	}
	if needBasicAuthRealm {
		noop := &corev3.DataSource{Specifier: &corev3.DataSource_InlineString{InlineString: "function envoy_on_response(handle) end\n"}}
		p.listenerFilters = append(p.listenerFilters, &hcmv3.HttpFilter{
			Name: basicAuthRealmFilterName,
			ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: mustAny(&luav3.Lua{
				DefaultSourceCode: noop,
			})},
		})
	}
	if needBasicAuth {
		p.listenerFilters = append(p.listenerFilters, &hcmv3.HttpFilter{
			Name:       basicAuthFilterName,
			ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: mustAny(basicAuthMain)},
		})
	}
	if needRBAC {
		p.listenerFilters = append(p.listenerFilters, &hcmv3.HttpFilter{
			Name:       rbacFilterName,
			ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: mustAny(&rbachttpv3.RBAC{})},
		})
	}
	if needExtAuthz {
		defaultHTTPService := extAuthzPerRoute(firstForwardAuthCluster, firstForwardAuth).GetCheckSettings().GetHttpService()
		p.listenerFilters = append(p.listenerFilters, &hcmv3.HttpFilter{
			Name: extAuthzFilterName,
			ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: mustAny(&extauthzv3.ExtAuthz{
				Services:         &extauthzv3.ExtAuthz_HttpService{HttpService: defaultHTTPService},
				FailureModeAllow: false,
			})},
		})
	}
	if needBasicAuthRemove {
		noop := &corev3.DataSource{Specifier: &corev3.DataSource_InlineString{InlineString: "function envoy_on_request(handle) end\n"}}
		p.listenerFilters = append(p.listenerFilters, &hcmv3.HttpFilter{
			Name:       basicAuthRemoveFilterName,
			ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: mustAny(&luav3.Lua{DefaultSourceCode: noop})},
		})
	}

	// Build the static auth clusters, deterministically ordered by name.
	for _, clusterName := range sortedStringKeys(authServices) {
		p.authClusters = append(p.authClusters, buildAuthCluster(clusterName, authServices[clusterName]))
	}

	// IP detection is listener-wide. Direct-peer policies remain independent,
	// but all policies that opt into XFF must agree on one depth or one trusted
	// CIDR set; mixing the two modes would make route behavior ambiguous.
	var strategyKey string
	for _, name := range names {
		for _, m := range routes[name].Middlewares {
			var strategy model.IPStrategy
			if m.IPAllowList != nil {
				strategy = m.IPAllowList.Strategy
			} else if m.IPDenyList != nil {
				strategy = m.IPDenyList.Strategy
			} else {
				continue
			}
			if strategy.Depth == 0 && len(strategy.ExcludedIPs) == 0 {
				continue
			}
			key := fmt.Sprintf("depth:%d", strategy.Depth)
			if len(strategy.ExcludedIPs) > 0 {
				cidrs := append([]string(nil), strategy.ExcludedIPs...)
				sort.Strings(cidrs)
				key = "cidrs:" + strings.Join(cidrs, ",")
				strategy.ExcludedIPs = cidrs
			}
			if strategyKey != "" && strategyKey != key {
				return nil, fmt.Errorf("route %q: conflicting ipstrategy settings; XFF client-IP detection is listener-wide", name)
			}
			strategyKey = key
			p.xffNumTrustedHops = strategy.Depth
			p.xffTrustedCIDRs = strategy.ExcludedIPs
		}
	}

	return p, nil
}

// authService records the original address and TLS settings for a forwardauth
// cluster so the CDS cluster can be built with the real host:port and the
// correct upstream TLS context.
type authService struct {
	address    string
	insecure   bool
	serverName string
	useTLS     bool
}

// applyRouteSecurity merges the per-route security configs for this route's
// middleware chain into the generated route. It is called after
// applyRouteMiddlewares so the two sets of typed per-filter configs
// (mutation/CORS vs. security) do not collide.
func applyRouteSecurity(er *routev3.Route, chain []model.Middleware) {
	if len(chain) == 0 {
		return
	}
	perRoute := map[string]*anypb.Any{}
	for _, m := range chain {
		switch {
		case m.BasicAuth != nil:
			perRoute[basicAuthFilterName] = mustAny(basicAuthPerRoute(m.BasicAuth))
			if m.BasicAuth.Realm != "" {
				perRoute[basicAuthRealmFilterName] = mustAny(basicAuthRealmPerRoute(m.BasicAuth.Realm))
			}
			if m.BasicAuth.RemoveHeader {
				perRoute[basicAuthRemoveFilterName] = mustAny(basicAuthRemovePerRoute())
			}
		case m.ForwardAuth != nil:
			clusterName := authClusterName(m.Name)
			perRoute[extAuthzFilterName] = mustAny(extAuthzPerRoute(clusterName, m.ForwardAuth))
		case m.IPAllowList != nil:
			perRoute[rbacFilterName] = mustAny(ipRBACPerRoute(m.IPAllowList.SourceRange, m.IPAllowList.Strategy, true))
		case m.IPDenyList != nil:
			perRoute[rbacFilterName] = mustAny(ipRBACPerRoute(m.IPDenyList.SourceRange, m.IPDenyList.Strategy, false))
		case m.RateLimit != nil:
			perRoute[localRLFilterName] = mustAny(localRateLimitPerRoute(m.RateLimit))
		}
	}
	if len(perRoute) == 0 {
		return
	}
	if er.TypedPerFilterConfig == nil {
		er.TypedPerFilterConfig = map[string]*anypb.Any{}
	}
	for name, cfg := range perRoute {
		er.TypedPerFilterConfig[name] = cfg
	}
}

func applySecurityDefaults(rc *routev3.RouteConfiguration, plan *securityPlan) {
	needExtAuthz := false
	for _, filter := range plan.listenerFilters {
		if filter.Name == extAuthzFilterName {
			needExtAuthz = true
			break
		}
	}
	if !needExtAuthz {
		return
	}
	for _, vh := range rc.VirtualHosts {
		for _, er := range vh.Routes {
			if er.TypedPerFilterConfig == nil {
				er.TypedPerFilterConfig = map[string]*anypb.Any{}
			}
			if _, configured := er.TypedPerFilterConfig[extAuthzFilterName]; !configured {
				er.TypedPerFilterConfig[extAuthzFilterName] = mustAny(&extauthzv3.ExtAuthzPerRoute{
					Override: &extauthzv3.ExtAuthzPerRoute_Disabled{Disabled: true},
				})
			}
		}
	}
}

// basicAuthPerRoute builds the per-route BasicAuthPerRoute carrying the user
// list as an inline htpasswd-format DataSource.
func basicAuthPerRoute(ba *model.BasicAuthMiddleware) *basicauthv3.BasicAuthPerRoute {
	return &basicauthv3.BasicAuthPerRoute{
		Users: basicAuthUsers(ba.Users),
	}
}

func basicAuthUsers(users []string) *corev3.DataSource {
	return &corev3.DataSource{Specifier: &corev3.DataSource_InlineString{
		InlineString: strings.Join(users, "\n"),
	}}
}

func basicAuthRealmPerRoute(realm string) *luav3.LuaPerRoute {
	script := "function envoy_on_response(handle)\n" +
		"  local challenge = handle:headers():get(\"www-authenticate\")\n" +
		"  if handle:headers():get(\":status\") == \"401\" and challenge ~= nil and string.lower(string.sub(challenge, 1, 6)) == \"basic \" then\n" +
		"    handle:headers():replace(\"www-authenticate\", " + luaString("Basic realm=\""+httpQuotedString(realm)+"\"") + ")\n" +
		"  end\nend\n"
	source := &corev3.DataSource{Specifier: &corev3.DataSource_InlineString{InlineString: script}}
	return &luav3.LuaPerRoute{Override: &luav3.LuaPerRoute_SourceCode{SourceCode: source}}
}

func httpQuotedString(value string) string {
	return strings.NewReplacer("\\", "\\\\", "\"", "\\\"").Replace(value)
}

// basicAuthRemovePerRoute runs after ForwardAuth so credentials remain
// available to every authentication filter but never reach the upstream.
func basicAuthRemovePerRoute() *luav3.LuaPerRoute {
	source := &corev3.DataSource{Specifier: &corev3.DataSource_InlineString{
		InlineString: "function envoy_on_request(handle)\n  handle:headers():remove(\"authorization\")\nend\n",
	}}
	return &luav3.LuaPerRoute{Override: &luav3.LuaPerRoute_SourceCode{SourceCode: source}}
}

// extAuthzPerRoute builds the per-route ExtAuthzPerRoute that enables
// ext_authz for this route and points it at the named auth cluster. It wires
// the forwardauth middleware's TLS and header settings into the check
// settings.
//
// Header forwarding semantics (Envoy ext_authz):
//   - Authorization, Host, Method, Path, and Content-Length are forwarded to
//     the auth service by default.
//   - trustforwardheader=true forwards existing X-Forwarded-For,
//     X-Forwarded-Host, and X-Forwarded-Proto values to the auth service.
//   - authrequestheaders lists further client headers to forward.
//   - authresponseheaders / authresponseheaderregex list successful auth
//     response headers to copy into the upstream request.
func extAuthzPerRoute(clusterName string, fa *model.ForwardAuthMiddleware) *extauthzv3.ExtAuthzPerRoute {
	httpService := &extauthzv3.HttpService{
		ServerUri: &corev3.HttpUri{
			Uri:              authServiceURI(fa),
			HttpUpstreamType: &corev3.HttpUri_Cluster{Cluster: clusterName},
			Timeout:          durationpb.New(defaultAuthzTimeout),
		},
		PathPrefix: authServicePathPrefix(fa),
	}
	var reqExact []string
	if fa.TrustForwardHeader {
		reqExact = append(reqExact, "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto")
	}
	reqExact = append(reqExact, fa.AuthRequestHeaders...)
	if len(reqExact) > 0 {
		httpService.AuthorizationRequest = &extauthzv3.AuthorizationRequest{
			AllowedHeaders: stringMatcherList(reqExact, nil),
		}
	}
	if len(fa.AuthResponseHeaders) > 0 || len(fa.AuthResponseHeaderRegex) > 0 {
		httpService.AuthorizationResponse = &extauthzv3.AuthorizationResponse{
			AllowedUpstreamHeaders: stringMatcherList(fa.AuthResponseHeaders, fa.AuthResponseHeaderRegex),
		}
	}
	return &extauthzv3.ExtAuthzPerRoute{
		Override: &extauthzv3.ExtAuthzPerRoute_CheckSettings{
			CheckSettings: &extauthzv3.CheckSettings{
				ServiceOverride: &extauthzv3.CheckSettings_HttpService{
					HttpService: httpService,
				},
			},
		},
	}
}

func authServiceURI(fa *model.ForwardAuthMiddleware) string {
	if u, err := url.ParseRequestURI(fa.Address); err == nil && u.Scheme != "" && u.Host != "" {
		return u.Scheme + "://" + u.Host
	}
	if ip := net.ParseIP(fa.Address); ip != nil && strings.Contains(fa.Address, ":") {
		return "https://[" + fa.Address + "]"
	}
	return "https://" + fa.Address
}

func authServicePathPrefix(fa *model.ForwardAuthMiddleware) string {
	if u, err := url.ParseRequestURI(fa.Address); err == nil && u.Scheme != "" && u.Host != "" {
		return u.EscapedPath()
	}
	return ""
}

// stringMatcherList builds a ListStringMatcher from exact-match names and
// regex patterns.
func stringMatcherList(exact, regex []string) *matcherv3.ListStringMatcher {
	lsm := &matcherv3.ListStringMatcher{}
	for _, e := range exact {
		lsm.Patterns = append(lsm.Patterns, &matcherv3.StringMatcher{
			MatchPattern: &matcherv3.StringMatcher_Exact{Exact: e},
		})
	}
	for _, r := range regex {
		lsm.Patterns = append(lsm.Patterns, &matcherv3.StringMatcher{
			MatchPattern: &matcherv3.StringMatcher_SafeRegex{
				SafeRegex: &matcherv3.RegexMatcher{
					EngineType: &matcherv3.RegexMatcher_GoogleRe2{GoogleRe2: &matcherv3.RegexMatcher_GoogleRE2{}},
					Regex:      r,
				},
			},
		})
	}
	return lsm
}

// ipRBACPerRoute builds the per-route RBAC config for an IP allow or deny
// list. allow=true means ALLOW (only matching IPs are permitted);
// allow=false means DENY (matching IPs are rejected).
func ipRBACPerRoute(ranges []string, strategy model.IPStrategy, allow bool) *rbachttpv3.RBACPerRoute {
	cidrs := cidrRanges(ranges)
	action := rbacv3.RBAC_ALLOW
	if !allow {
		action = rbacv3.RBAC_DENY
	}
	policy := &rbacv3.Policy{
		Permissions: []*rbacv3.Permission{
			{Rule: &rbacv3.Permission_Any{Any: true}},
		},
		Principals: principalsForRanges(cidrs, strategy),
	}
	return &rbachttpv3.RBACPerRoute{
		Rbac: &rbachttpv3.RBAC{
			Rules: &rbacv3.RBAC{
				Action:   action,
				Policies: map[string]*rbacv3.Policy{"ip_policy": policy},
			},
		},
	}
}

// principalsForRanges builds the RBAC principals for a set of CIDR ranges.
// The principal type depends on the IP strategy: when the strategy trusts
// X-Forwarded-For hops (depth > 0), RemoteIp is used (which honors XFF);
// otherwise DirectRemoteIp is used (the physical peer only, which cannot be
// spoofed by a client-supplied XFF header).
func principalsForRanges(ranges []*corev3.CidrRange, strategy model.IPStrategy) []*rbacv3.Principal {
	useXFF := strategy.Depth > 0 || len(strategy.ExcludedIPs) > 0
	principals := make([]*rbacv3.Principal, 0, len(ranges))
	for _, r := range ranges {
		p := &rbacv3.Principal{}
		if useXFF {
			p.Identifier = &rbacv3.Principal_RemoteIp{RemoteIp: r}
		} else {
			p.Identifier = &rbacv3.Principal_DirectRemoteIp{DirectRemoteIp: r}
		}
		principals = append(principals, p)
	}
	return principals
}

// localRateLimitBucket maps the model's average/burst/period to an Envoy
// TokenBucket: tokens_per_fill = average, max_tokens = burst, fill_interval =
// period.
func localRateLimitBucket(rl *model.RateLimitMiddleware) *tokenbucketv3.TokenBucket {
	period, _ := time.ParseDuration(rl.Period)
	return &tokenbucketv3.TokenBucket{
		MaxTokens:     rl.Burst,
		TokensPerFill: wrapperspb.UInt32(rl.Average),
		FillInterval:  durationpb.New(period),
	}
}

func localRateLimitPerRoute(rl *model.RateLimitMiddleware) *localrlv3.LocalRateLimit {
	hundredPercent := &corev3.RuntimeFractionalPercent{DefaultValue: &tokenbucketv3.FractionalPercent{
		Numerator:   100,
		Denominator: tokenbucketv3.FractionalPercent_HUNDRED,
	}}
	return &localrlv3.LocalRateLimit{
		StatPrefix:     "local_ratelimit",
		TokenBucket:    localRateLimitBucket(rl),
		FilterEnabled:  hundredPercent,
		FilterEnforced: hundredPercent,
	}
}

func tokenBucketsEqual(a, b *tokenbucketv3.TokenBucket) bool {
	if a == nil || b == nil {
		return a == b
	}
	aTPF, bTPF := uint32(0), uint32(0)
	if a.TokensPerFill != nil {
		aTPF = a.TokensPerFill.Value
	}
	if b.TokensPerFill != nil {
		bTPF = b.TokensPerFill.Value
	}
	aFI, bFI := time.Duration(0), time.Duration(0)
	if a.FillInterval != nil {
		aFI = a.FillInterval.AsDuration()
	}
	if b.FillInterval != nil {
		bFI = b.FillInterval.AsDuration()
	}
	return a.MaxTokens == b.MaxTokens && aTPF == bTPF && aFI == bFI
}

// buildAuthCluster builds an explicit cluster for a forwardauth service. It
// uses STATIC discovery for literal IPs and STRICT_DNS for hostnames. Unlike
// EDS-backed application service clusters, the auth service address is a fixed
// host:port rather than a Docker-discovered endpoint set. When the service is
// not marked insecure, the cluster carries an upstream TLS context (with SNI
// set to the server name when provided).
func buildAuthCluster(name string, svc *authService) *clusterv3.Cluster {
	address := svc.address
	host, portStr := "", ""
	if u, err := url.ParseRequestURI(address); err == nil && u.Hostname() != "" {
		// URL.Host preserves IPv6 brackets; SocketAddress.Address must not.
		host, portStr = u.Hostname(), u.Port()
	} else if parsedHost, parsedPort, err := net.SplitHostPort(address); err == nil {
		host, portStr = parsedHost, parsedPort
	} else {
		host = strings.Trim(address, "[]")
	}
	if portStr == "" {
		// Bare host (no port): default to 80 (or 443 when TLS).
		portStr = "80"
		if svc.useTLS {
			portStr = "443"
		}
	}
	port, _ := strconv.ParseUint(portStr, 10, 32)

	discoveryType := clusterv3.Cluster_STRICT_DNS
	if net.ParseIP(host) != nil {
		discoveryType = clusterv3.Cluster_STATIC
	}
	cluster := &clusterv3.Cluster{
		Name:                 name,
		ConnectTimeout:       durationpb.New(2 * time.Second),
		ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: discoveryType},
		LoadAssignment: &endpointv3.ClusterLoadAssignment{
			ClusterName: name,
			Endpoints: []*endpointv3.LocalityLbEndpoints{
				{
					LbEndpoints: []*endpointv3.LbEndpoint{
						{
							HostIdentifier: &endpointv3.LbEndpoint_Endpoint{
								Endpoint: &endpointv3.Endpoint{
									Address: &corev3.Address{
										Address: &corev3.Address_SocketAddress{
											SocketAddress: &corev3.SocketAddress{
												Address: host,
												PortSpecifier: &corev3.SocketAddress_PortValue{
													PortValue: uint32(port),
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		LbPolicy: clusterv3.Cluster_ROUND_ROBIN,
	}

	if svc.useTLS {
		tlsContext := &tlsv3.UpstreamTlsContext{}
		if svc.serverName != "" {
			// SNI: the server name to present during the TLS handshake.
			tlsContext.Sni = svc.serverName
		}
		if !svc.insecure {
			validation := &tlsv3.CertificateValidationContext{TrustedCa: &corev3.DataSource{Specifier: &corev3.DataSource_Filename{Filename: "/etc/ssl/certs/ca-certificates.crt"}}}
			if svc.serverName != "" {
				validation.MatchTypedSubjectAltNames = []*tlsv3.SubjectAltNameMatcher{{
					SanType: tlsv3.SubjectAltNameMatcher_DNS,
					Matcher: &matcherv3.StringMatcher{MatchPattern: &matcherv3.StringMatcher_Exact{Exact: svc.serverName}},
				}}
			}
			tlsContext.CommonTlsContext = &tlsv3.CommonTlsContext{ValidationContextType: &tlsv3.CommonTlsContext_ValidationContext{ValidationContext: validation}}
			cluster.UpstreamHttpProtocolOptions = &corev3.UpstreamHttpProtocolOptions{AutoSni: svc.serverName == "", AutoSanValidation: svc.serverName == ""}
		}
		cluster.TransportSocket = &corev3.TransportSocket{
			Name:       transportSocketTLS,
			ConfigType: &corev3.TransportSocket_TypedConfig{TypedConfig: mustAny(tlsContext)},
		}
	}

	return cluster
}

// authClusterName derives a deterministic, Envoy-valid cluster name for a
// forwardauth middleware: "auth-" followed by the sanitized middleware name.
// Middleware names are globally unique (docker labels are keyed by name), so
// the name alone identifies the auth service; the real host:port is carried
// by the cluster's static endpoint, built in buildAuthCluster.
func authClusterName(middlewareName string) string {
	return "auth-" + sanitizeClusterName(middlewareName)
}

func sanitizeClusterName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}

// cidrRanges parses a list of CIDR strings into Envoy CidrRange messages.
func cidrRanges(cidrs []string) []*corev3.CidrRange {
	out := make([]*corev3.CidrRange, 0, len(cidrs))
	for _, c := range cidrs {
		prefix, prefixLen, err := parseCIDRForXDS(c)
		if err != nil {
			// Validation already rejected bad CIDRs; this is defensive.
			continue
		}
		out = append(out, &corev3.CidrRange{
			AddressPrefix: prefix,
			PrefixLen:     wrapperspb.UInt32(prefixLen),
		})
	}
	return out
}

// parseCIDRForXDS parses a CIDR or bare IP into a prefix string and length.
// It mirrors model.parseCIDR but is local to the xds package to avoid an
// import cycle.
func parseCIDRForXDS(value string) (string, uint32, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", 0, fmt.Errorf("empty CIDR")
	}
	if strings.Contains(value, "/") {
		_, ipNet, err := net.ParseCIDR(value)
		if err != nil {
			return "", 0, err
		}
		ones, _ := ipNet.Mask.Size()
		return ipNet.IP.String(), uint32(ones), nil
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return "", 0, fmt.Errorf("invalid IP %q", value)
	}
	if ip.To4() != nil {
		return ip.String(), 32, nil
	}
	return ip.String(), 128, nil
}

func sortedStringKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
