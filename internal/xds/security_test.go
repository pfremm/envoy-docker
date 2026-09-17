package xds

import (
	"strings"
	"testing"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
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
	cachetypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
	"github.com/bryanpfremm/envoy-control-plane/internal/rule"
)

// unmarshalAny decodes a typed config Any into msg.
func unmarshalAny(t *testing.T, any *anypb.Any, msg proto.Message) {
	t.Helper()
	if err := any.UnmarshalTo(msg); err != nil {
		t.Fatalf("unmarshaling %s: %v", any.GetTypeUrl(), err)
	}
}

// httpsHCM returns the HTTPS listener's HttpConnectionManager from a snapshot.
func httpsHCM(t *testing.T, snap interface {
	GetResources(string) map[string]cachetypes.Resource
}) *hcmv3.HttpConnectionManager {
	t.Helper()
	listeners := snap.GetResources(resourcev3.ListenerType)
	l, ok := listeners[httpsListenerName].(*listenerv3.Listener)
	if !ok {
		t.Fatalf("no https listener in snapshot")
	}
	return decodeHCM(t, l)
}

// filterNames returns the HTTP filter names of an HCM in order.
func filterNames(hcm *hcmv3.HttpConnectionManager) []string {
	names := make([]string, 0, len(hcm.HttpFilters))
	for _, f := range hcm.HttpFilters {
		names = append(names, f.Name)
	}
	return names
}

func TestPlanSecurity_NoSecurityMiddleware_EmptyPlan(t *testing.T) {
	routes := map[string]model.Route{
		"app": {Subdomain: "app", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}}, Source: model.SourceDocker},
	}
	plan, err := planSecurity(routes)
	if err != nil {
		t.Fatalf("planSecurity() unexpected error: %v", err)
	}
	if len(plan.listenerFilters) != 0 {
		t.Errorf("expected no listener security filters, got %v", plan.listenerFilters)
	}
	if len(plan.authClusters) != 0 {
		t.Errorf("expected no auth clusters, got %d", len(plan.authClusters))
	}
	if plan.xffNumTrustedHops != 0 {
		t.Errorf("expected xffNumTrustedHops 0, got %d", plan.xffNumTrustedHops)
	}
}

func TestPlanSecurity_FilterOrdering(t *testing.T) {
	routes := map[string]model.Route{
		"app": {
			Subdomain: "app",
			Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}},
			Source:    model.SourceDocker,
			Middlewares: []model.Middleware{
				{Name: "rl", RateLimit: &model.RateLimitMiddleware{Average: 10, Burst: 20, Period: "1s"}},
				{Name: "ba", BasicAuth: &model.BasicAuthMiddleware{Users: []string{"alice:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="}}},
				{Name: "allow", IPAllowList: &model.IPAllowListMiddleware{SourceRange: []string{"10.0.0.0/8"}}},
				{Name: "fa", ForwardAuth: &model.ForwardAuthMiddleware{Address: "auth.example.com:8080"}},
			},
		},
	}
	plan, err := planSecurity(routes)
	if err != nil {
		t.Fatalf("planSecurity() unexpected error: %v", err)
	}
	got := make([]string, 0, len(plan.listenerFilters))
	for _, f := range plan.listenerFilters {
		got = append(got, f.Name)
	}
	want := []string{localRLFilterName, basicAuthFilterName, rbacFilterName, extAuthzFilterName}
	if len(got) != len(want) {
		t.Fatalf("listener filter count = %d, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("listener filter[%d] = %q, want %q (order: %v)", i, got[i], want[i], got)
		}
	}
}

func TestPlanSecurity_OnlyNeededFiltersPresent(t *testing.T) {
	routes := map[string]model.Route{
		"app": {
			Subdomain: "app",
			Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}},
			Source:    model.SourceDocker,
			Middlewares: []model.Middleware{
				{Name: "deny", IPDenyList: &model.IPDenyListMiddleware{SourceRange: []string{"192.168.0.0/16"}}},
			},
		},
	}
	plan, err := planSecurity(routes)
	if err != nil {
		t.Fatalf("planSecurity() unexpected error: %v", err)
	}
	got := make([]string, 0, len(plan.listenerFilters))
	for _, f := range plan.listenerFilters {
		got = append(got, f.Name)
	}
	if len(got) != 1 || got[0] != rbacFilterName {
		t.Errorf("expected only the rbac filter, got %v", got)
	}
}

func TestPlanSecurity_LocalRateLimitBucket(t *testing.T) {
	routes := map[string]model.Route{
		"app": {
			Subdomain: "app",
			Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}},
			Source:    model.SourceDocker,
			Middlewares: []model.Middleware{
				{Name: "rl", RateLimit: &model.RateLimitMiddleware{Average: 10, Burst: 20, Period: "1s"}},
			},
		},
	}
	plan, err := planSecurity(routes)
	if err != nil {
		t.Fatalf("planSecurity() unexpected error: %v", err)
	}
	if len(plan.listenerFilters) != 1 {
		t.Fatalf("expected 1 listener filter, got %d", len(plan.listenerFilters))
	}
	global := &localrlv3.LocalRateLimit{}
	unmarshalAny(t, plan.listenerFilters[0].GetTypedConfig(), global)
	if global.TokenBucket != nil {
		t.Fatal("listener-wide local rate filter must not share one bucket across routes")
	}
	er := &routev3.Route{}
	applyRouteSecurity(er, routes["app"].Middlewares)
	lrl := &localrlv3.LocalRateLimit{}
	unmarshalAny(t, er.TypedPerFilterConfig[localRLFilterName], lrl)
	tb := lrl.TokenBucket
	if tb == nil {
		t.Fatal("local_ratelimit has no token bucket")
	}
	if tb.MaxTokens != 20 {
		t.Errorf("TokenBucket.MaxTokens = %d, want 20 (burst)", tb.MaxTokens)
	}
	if tb.GetTokensPerFill().Value != 10 {
		t.Errorf("TokenBucket.TokensPerFill = %d, want 10 (average)", tb.GetTokensPerFill().Value)
	}
	if tb.FillInterval == nil || tb.FillInterval.AsDuration() != time.Second {
		t.Errorf("TokenBucket.FillInterval = %v, want 1s (period)", tb.FillInterval)
	}
	if lrl.GetFilterEnabled().GetDefaultValue().GetNumerator() != 100 || lrl.GetFilterEnforced().GetDefaultValue().GetNumerator() != 100 {
		t.Fatal("local rate limiter must be explicitly enabled and enforced for 100% of requests")
	}
}

func TestPlanSecurity_DifferentRouteRateLimitBuckets_AreAllowed(t *testing.T) {
	mk := func(sub string, rl model.RateLimitMiddleware) model.Route {
		return model.Route{
			Subdomain: sub,
			Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}},
			Source:    model.SourceDocker,
			Middlewares: []model.Middleware{
				{Name: "rl", RateLimit: &rl},
			},
		}
	}
	routes := map[string]model.Route{
		"a": mk("a", model.RateLimitMiddleware{Average: 10, Burst: 20, Period: "1s"}),
		"b": mk("b", model.RateLimitMiddleware{Average: 10, Burst: 30, Period: "1s"}),
	}
	if _, err := planSecurity(routes); err != nil {
		t.Fatalf("per-route local rate-limit buckets must not conflict: %v", err)
	}
}

func TestPlanSecurity_ForwardAuthCluster(t *testing.T) {
	routes := map[string]model.Route{
		"app": {
			Subdomain: "app",
			Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}},
			Source:    model.SourceDocker,
			Middlewares: []model.Middleware{
				{Name: "authsvc", ForwardAuth: &model.ForwardAuthMiddleware{Address: "auth.example.com:8443"}},
			},
		},
	}
	plan, err := planSecurity(routes)
	if err != nil {
		t.Fatalf("planSecurity() unexpected error: %v", err)
	}
	if len(plan.authClusters) != 1 {
		t.Fatalf("expected 1 auth cluster, got %d", len(plan.authClusters))
	}
	main := &extauthzv3.ExtAuthz{}
	for _, filter := range plan.listenerFilters {
		if filter.Name == extAuthzFilterName {
			unmarshalAny(t, filter.GetTypedConfig(), main)
		}
	}
	if main.GetHttpService() == nil || main.FailureModeAllow {
		t.Fatal("listener ext_authz must have a valid default HTTP service and fail closed")
	}
	c := plan.authClusters[0]
	if c.Name != "auth-authsvc" {
		t.Errorf("auth cluster name = %q, want auth-authsvc", c.Name)
	}
	if c.GetType() != clusterv3.Cluster_STRICT_DNS {
		t.Errorf("auth cluster type = %v, want STRICT_DNS for hostname endpoint", c.GetType())
	}
	// The endpoint carries the real host:port.
	las := c.LoadAssignment
	if len(las.Endpoints) == 0 || len(las.Endpoints[0].LbEndpoints) == 0 {
		t.Fatalf("auth cluster has no endpoints: %+v", las)
	}
	ep := las.Endpoints[0].LbEndpoints[0].GetEndpoint().GetAddress().GetSocketAddress()
	if ep.Address != "auth.example.com" || ep.GetPortValue() != 8443 {
		t.Errorf("auth endpoint = %s:%d, want auth.example.com:8443", ep.Address, ep.GetPortValue())
	}
	// Not insecure -> TLS transport socket with SNI.
	if c.TransportSocket == nil {
		t.Fatal("expected a TLS transport socket on the auth cluster (not insecure)")
	}
}

func TestPlanSecurity_ForwardAuthInsecure_NoTLS(t *testing.T) {
	routes := map[string]model.Route{
		"app": {
			Subdomain: "app",
			Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}},
			Source:    model.SourceDocker,
			Middlewares: []model.Middleware{
				{Name: "authsvc", ForwardAuth: &model.ForwardAuthMiddleware{Address: "http://10.0.0.9:8080", TLSInsecure: true}},
			},
		},
	}
	plan, err := planSecurity(routes)
	if err != nil {
		t.Fatalf("planSecurity() unexpected error: %v", err)
	}
	if len(plan.authClusters) != 1 {
		t.Fatalf("expected 1 auth cluster, got %d", len(plan.authClusters))
	}
	c := plan.authClusters[0]
	if c.GetType() != clusterv3.Cluster_STATIC {
		t.Errorf("auth cluster type = %v, want STATIC for literal IP endpoint", c.GetType())
	}
	if c.TransportSocket != nil {
		t.Errorf("insecure forwardauth should not carry a TLS transport socket, got %+v", c.TransportSocket)
	}
}

func TestPlanSecurity_ForwardAuthSNI(t *testing.T) {
	routes := map[string]model.Route{
		"app": {
			Subdomain: "app",
			Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}},
			Source:    model.SourceDocker,
			Middlewares: []model.Middleware{
				{Name: "authsvc", ForwardAuth: &model.ForwardAuthMiddleware{Address: "10.0.0.9:8443", TLSServerName: "auth.internal"}},
			},
		},
	}
	plan, err := planSecurity(routes)
	if err != nil {
		t.Fatalf("planSecurity() unexpected error: %v", err)
	}
	c := plan.authClusters[0]
	ts := c.TransportSocket
	if ts == nil {
		t.Fatal("expected a TLS transport socket")
	}
	upstream := &tlsv3.UpstreamTlsContext{}
	unmarshalAny(t, ts.GetTypedConfig(), upstream)
	if upstream.Sni != "auth.internal" {
		t.Errorf("upstream TLS SNI = %q, want auth.internal", upstream.Sni)
	}
}

func TestPlanSecurity_ConflictingForwardAuthAddress_Errors(t *testing.T) {
	// Two routes define the same forwardauth middleware name but different
	// addresses: the single static cluster cannot express both.
	routes := map[string]model.Route{
		"a": {
			Subdomain: "a",
			Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}},
			Source:    model.SourceDocker,
			Middlewares: []model.Middleware{
				{Name: "authsvc", ForwardAuth: &model.ForwardAuthMiddleware{Address: "auth1.example.com:8080"}},
			},
		},
		"b": {
			Subdomain: "b",
			Endpoints: []model.Endpoint{{Address: "10.0.0.2", Port: 8080}},
			Source:    model.SourceDocker,
			Middlewares: []model.Middleware{
				{Name: "authsvc", ForwardAuth: &model.ForwardAuthMiddleware{Address: "auth2.example.com:8080"}},
			},
		},
	}
	if _, err := planSecurity(routes); err == nil {
		t.Fatal("expected an error for conflicting forwardauth addresses, got nil")
	}
}

func TestPlanSecurity_XFFDepth(t *testing.T) {
	routes := map[string]model.Route{
		"app": {
			Subdomain: "app",
			Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}},
			Source:    model.SourceDocker,
			Middlewares: []model.Middleware{
				{Name: "allow", IPAllowList: &model.IPAllowListMiddleware{
					SourceRange: []string{"10.0.0.0/8"},
					Strategy:    model.IPStrategy{Depth: 2},
				}},
			},
		},
	}
	plan, err := planSecurity(routes)
	if err != nil {
		t.Fatalf("planSecurity() unexpected error: %v", err)
	}
	if plan.xffNumTrustedHops != 2 {
		t.Errorf("xffNumTrustedHops = %d, want 2", plan.xffNumTrustedHops)
	}
}

func TestBuildSnapshot_XFFExcludedIPsUsesTrustedCIDRExtension(t *testing.T) {
	routes := map[string]model.Route{"app": {
		Subdomain: "app", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}}, Source: model.SourceDocker,
		Middlewares: []model.Middleware{{Name: "allow", IPAllowList: &model.IPAllowListMiddleware{
			SourceRange: []string{"192.0.2.0/24"}, Strategy: model.IPStrategy{ExcludedIPs: []string{"10.0.0.0/8"}},
		}}},
	}}
	snap, err := BuildSnapshot("1", routes, Config{BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443, CertSecretName: "cert", ACMESDSClusterName: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	hcm := httpsHCM(t, snap)
	if hcm.XffNumTrustedHops != 0 || len(hcm.OriginalIpDetectionExtensions) != 1 {
		t.Fatalf("excludedips must use one XFF trusted-CIDR extension, got hops=%d extensions=%d", hcm.XffNumTrustedHops, len(hcm.OriginalIpDetectionExtensions))
	}
}

func TestComposedAuthFilterOrderAuthorizesFinalRequestAndRemovesCredentials(t *testing.T) {
	routes := map[string]model.Route{"app": {
		Subdomain: "app", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}}, Source: model.SourceDocker,
		Middlewares: []model.Middleware{
			{Name: "basic", BasicAuth: &model.BasicAuthMiddleware{Users: []string{"alice:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="}, RemoveHeader: true}},
			{Name: "rewrite", ReplacePath: &model.ReplacePathMiddleware{Path: "/authorized"}},
			{Name: "forward", ForwardAuth: &model.ForwardAuthMiddleware{Address: "http://auth:9000/check"}},
		},
	}}
	plan, err := planSecurity(routes)
	if err != nil {
		t.Fatal(err)
	}
	hcm := decodeHCM(t, buildHTTPSListener(httpsListenerName, 443, httpsRouteConfigName, "cert", "sds", plan))
	got := strings.Join(filterNames(hcm), ",")
	want := strings.Join([]string{
		basicAuthFilterName,
		mutationFilterName,
		extAuthzFilterName,
		basicAuthRemoveFilterName,
		wellknown.CORS,
		wellknown.Router,
	}, ",")
	if got != want {
		t.Fatalf("unsafe composed auth filter order:\n got %s\nwant %s", got, want)
	}
}

func TestBasicAuthRealmUsesPreAuthResponseFilter(t *testing.T) {
	routes := map[string]model.Route{"app": {
		Subdomain: "app", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}}, Source: model.SourceDocker,
		Middlewares: []model.Middleware{{Name: "basic", BasicAuth: &model.BasicAuthMiddleware{
			Users: []string{"alice:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="}, Realm: "private area",
		}}},
	}}
	plan, err := planSecurity(routes)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.listenerFilters) != 2 || plan.listenerFilters[0].Name != basicAuthRealmFilterName || plan.listenerFilters[1].Name != basicAuthFilterName {
		t.Fatalf("realm response filter must run before basic auth: %v", filterNames(&hcmv3.HttpConnectionManager{HttpFilters: plan.listenerFilters}))
	}
	er := &routev3.Route{}
	applyRouteSecurity(er, routes["app"].Middlewares)
	cfg := &luav3.LuaPerRoute{}
	if err := er.TypedPerFilterConfig[basicAuthRealmFilterName].UnmarshalTo(cfg); err != nil {
		t.Fatal(err)
	}
	if source := cfg.GetSourceCode().GetInlineString(); !strings.Contains(source, `Basic realm=\"private area\"`) {
		t.Fatalf("realm override missing from Lua response filter: %s", source)
	}
}

func TestApplyRouteSecurity_BasicAuthPerRoute(t *testing.T) {
	er := &routev3.Route{}
	chain := []model.Middleware{
		{Name: "ba", BasicAuth: &model.BasicAuthMiddleware{Users: []string{"alice:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=", "bob:{SHA}2jmj7l5rSw0yVb/vlWAYkK/YBwk="}}},
	}
	applyRouteSecurity(er, chain)
	cfg, ok := er.TypedPerFilterConfig[basicAuthFilterName]
	if !ok {
		t.Fatalf("no per-route basic_auth config; got keys %v", keys(er.TypedPerFilterConfig))
	}
	perRoute := &basicauthv3.BasicAuthPerRoute{}
	unmarshalAny(t, cfg, perRoute)
	users := perRoute.GetUsers().GetInlineString()
	if users != "alice:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=\nbob:{SHA}2jmj7l5rSw0yVb/vlWAYkK/YBwk=" {
		t.Errorf("per-route basic_auth users = %q, want the two entries joined by newline", users)
	}
}

func TestApplyRouteSecurity_ForwardAuthPerRoute(t *testing.T) {
	er := &routev3.Route{}
	chain := []model.Middleware{
		{Name: "authsvc", ForwardAuth: &model.ForwardAuthMiddleware{
			Address:                 "auth.example.com:8443",
			TrustForwardHeader:      true,
			AuthRequestHeaders:      []string{"X-Api-Key"},
			AuthResponseHeaders:     []string{"X-Auth-User"},
			AuthResponseHeaderRegex: []string{"X-Auth-.*"},
		}},
	}
	applyRouteSecurity(er, chain)
	cfg, ok := er.TypedPerFilterConfig[extAuthzFilterName]
	if !ok {
		t.Fatalf("no per-route ext_authz config; got keys %v", keys(er.TypedPerFilterConfig))
	}
	perRoute := &extauthzv3.ExtAuthzPerRoute{}
	unmarshalAny(t, cfg, perRoute)
	cs := perRoute.GetCheckSettings()
	if cs == nil {
		t.Fatal("per-route ext_authz has no check settings")
	}
	hsvc := cs.GetHttpService()
	if hsvc == nil {
		t.Fatal("per-route ext_authz has no http service override")
	}
	if hsvc.GetServerUri().GetCluster() != "auth-authsvc" {
		t.Errorf("ext_authz server cluster = %q, want auth-authsvc", hsvc.GetServerUri().GetCluster())
	}
	if hsvc.GetServerUri().GetUri() != "https://auth.example.com:8443" {
		t.Errorf("ext_authz server URI = %q, want normalized HTTPS URI", hsvc.GetServerUri().GetUri())
	}
	if hsvc.GetServerUri().GetTimeout().AsDuration() != defaultAuthzTimeout {
		t.Errorf("ext_authz timeout = %v, want %v", hsvc.GetServerUri().GetTimeout(), defaultAuthzTimeout)
	}
	// Request headers: trustforwardheader + authrequestheaders, exact match.
	req := hsvc.GetAuthorizationRequest()
	if req == nil {
		t.Fatal("expected an authorization_request with allowed headers")
	}
	var reqHeaders []string
	for _, p := range req.GetAllowedHeaders().GetPatterns() {
		reqHeaders = append(reqHeaders, p.GetExact())
	}
	if len(reqHeaders) != 4 || reqHeaders[0] != "x-forwarded-for" || reqHeaders[3] != "X-Api-Key" {
		t.Errorf("auth request headers = %v, want trusted X-Forwarded headers plus X-Api-Key", reqHeaders)
	}
	// Response headers: exact + regex.
	resp := hsvc.GetAuthorizationResponse()
	if resp == nil {
		t.Fatal("expected an authorization_response")
	}
	pats := resp.GetAllowedUpstreamHeaders().GetPatterns()
	if len(pats) != 2 {
		t.Fatalf("expected 2 response header patterns, got %d", len(pats))
	}
	if pats[0].GetExact() != "X-Auth-User" {
		t.Errorf("response header[0] exact = %q, want X-Auth-User", pats[0].GetExact())
	}
	if pats[1].GetSafeRegex().GetRegex() != "X-Auth-.*" {
		t.Errorf("response header[1] regex = %q, want X-Auth-.*", pats[1].GetSafeRegex().GetRegex())
	}
}

func TestApplyRouteSecurity_IPAllowList(t *testing.T) {
	er := &routev3.Route{}
	chain := []model.Middleware{
		{Name: "allow", IPAllowList: &model.IPAllowListMiddleware{
			SourceRange: []string{"10.0.0.0/8", "192.168.1.1"},
			Strategy:    model.IPStrategy{Depth: 1},
		}},
	}
	applyRouteSecurity(er, chain)
	cfg, ok := er.TypedPerFilterConfig[rbacFilterName]
	if !ok {
		t.Fatalf("no per-route rbac config; got keys %v", keys(er.TypedPerFilterConfig))
	}
	perRoute := &rbachttpv3.RBACPerRoute{}
	unmarshalAny(t, cfg, perRoute)
	rbac := perRoute.GetRbac().GetRules()
	if rbac.GetAction() != rbacv3.RBAC_ALLOW {
		t.Errorf("allow-list RBAC action = %v, want ALLOW", rbac.GetAction())
	}
	pol, ok := rbac.GetPolicies()["ip_policy"]
	if !ok {
		t.Fatalf("no ip_policy in RBAC rules: %v", rbac.GetPolicies())
	}
	if len(pol.Principals) != 2 {
		t.Fatalf("expected 2 principals, got %d", len(pol.Principals))
	}
	// Depth > 0 -> RemoteIp (honors XFF).
	for i, p := range pol.Principals {
		if p.GetRemoteIp() == nil {
			t.Errorf("principal[%d] = %v, want RemoteIp (depth>0)", i, p)
		}
	}
	if pol.Principals[0].GetRemoteIp().GetAddressPrefix() != "10.0.0.0" || pol.Principals[0].GetRemoteIp().GetPrefixLen().Value != 8 {
		t.Errorf("principal[0] = %v, want 10.0.0.0/8", pol.Principals[0].GetRemoteIp())
	}
	if pol.Principals[1].GetRemoteIp().GetAddressPrefix() != "192.168.1.1" || pol.Principals[1].GetRemoteIp().GetPrefixLen().Value != 32 {
		t.Errorf("principal[1] = %v, want 192.168.1.1/32", pol.Principals[1].GetRemoteIp())
	}
}

func TestApplyRouteSecurity_IPDenyList(t *testing.T) {
	er := &routev3.Route{}
	chain := []model.Middleware{
		{Name: "deny", IPDenyList: &model.IPDenyListMiddleware{
			SourceRange: []string{"172.16.0.0/12"},
			Strategy:    model.IPStrategy{},
		}},
	}
	applyRouteSecurity(er, chain)
	cfg, ok := er.TypedPerFilterConfig[rbacFilterName]
	if !ok {
		t.Fatalf("no per-route rbac config; got keys %v", keys(er.TypedPerFilterConfig))
	}
	perRoute := &rbachttpv3.RBACPerRoute{}
	unmarshalAny(t, cfg, perRoute)
	rbac := perRoute.GetRbac().GetRules()
	if rbac.GetAction() != rbacv3.RBAC_DENY {
		t.Errorf("deny-list RBAC action = %v, want DENY", rbac.GetAction())
	}
	pol := rbac.GetPolicies()["ip_policy"]
	if len(pol.Principals) != 1 {
		t.Fatalf("expected 1 principal, got %d", len(pol.Principals))
	}
	// Depth == 0 -> DirectRemoteIp (physical peer, not spoofable via XFF).
	if pol.Principals[0].GetDirectRemoteIp() == nil {
		t.Errorf("principal = %v, want DirectRemoteIp (depth==0)", pol.Principals[0])
	}
}

func TestApplyRouteSecurity_NoSecurityMiddleware_NoPerRoute(t *testing.T) {
	er := &routev3.Route{}
	chain := []model.Middleware{
		{Name: "strip", StripPrefix: &model.StripPrefixMiddleware{Prefixes: []string{"/api"}}},
	}
	applyRouteSecurity(er, chain)
	if len(er.TypedPerFilterConfig) != 0 {
		t.Errorf("expected no per-route security config, got %v", keys(er.TypedPerFilterConfig))
	}
}

func TestApplyRouteSecurity_MultipleMiddlewares(t *testing.T) {
	er := &routev3.Route{}
	chain := []model.Middleware{
		{Name: "ba", BasicAuth: &model.BasicAuthMiddleware{Users: []string{"alice:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="}}},
		{Name: "allow", IPAllowList: &model.IPAllowListMiddleware{SourceRange: []string{"10.0.0.0/8"}}},
		{Name: "fa", ForwardAuth: &model.ForwardAuthMiddleware{Address: "auth.example.com:8080"}},
	}
	applyRouteSecurity(er, chain)
	want := []string{basicAuthFilterName, rbacFilterName, extAuthzFilterName}
	for _, w := range want {
		if _, ok := er.TypedPerFilterConfig[w]; !ok {
			t.Errorf("expected per-route config for %q, got keys %v", w, keys(er.TypedPerFilterConfig))
		}
	}
}

func TestBuildSnapshot_SecurityWiring(t *testing.T) {
	routes := map[string]model.Route{
		"app": {
			Subdomain: "app",
			Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}},
			Source:    model.SourceDocker,
			Middlewares: []model.Middleware{
				{Name: "rl", RateLimit: &model.RateLimitMiddleware{Average: 10, Burst: 20, Period: "1s"}},
				{Name: "ba", BasicAuth: &model.BasicAuthMiddleware{Users: []string{"alice:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="}}},
				{Name: "allow", IPAllowList: &model.IPAllowListMiddleware{
					SourceRange: []string{"10.0.0.0/8"},
					Strategy:    model.IPStrategy{Depth: 1},
				}},
				{Name: "fa", ForwardAuth: &model.ForwardAuthMiddleware{Address: "auth.example.com:8443"}},
			},
		},
	}
	cfg := Config{BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443, CertSecretName: "cert", ACMESDSClusterName: "acme"}
	snap, err := BuildSnapshot("1", routes, cfg)
	if err != nil {
		t.Fatalf("BuildSnapshot() unexpected error: %v", err)
	}

	// CDS: the auth cluster is present alongside the app cluster.
	clusters := snap.GetResources(resourcev3.ClusterType)
	if _, ok := clusters["auth-fa"]; !ok {
		t.Errorf("expected auth cluster auth-fa in CDS, got %v", clusterNames(clusters))
	}

	// LDS: cheap/local security runs first, request mutation precedes the
	// external authorization decision, then CORS/router finish the chain.
	hcm := httpsHCM(t, snap)
	names := filterNames(hcm)
	wantOrder := []string{localRLFilterName, basicAuthFilterName, rbacFilterName, mutationFilterName, extAuthzFilterName, corsFilterName, wellknown.Router}
	if len(names) != len(wantOrder) {
		t.Fatalf("HTTPS filter count = %d, want %d: %v", len(names), len(wantOrder), names)
	}
	for i := range wantOrder {
		if names[i] != wantOrder[i] {
			t.Errorf("HTTPS filter[%d] = %q, want %q (order: %v)", i, names[i], wantOrder[i], names)
		}
	}
	// XFF trusted hops from the IP strategy depth.
	if hcm.XffNumTrustedHops != 1 {
		t.Errorf("XffNumTrustedHops = %d, want 1", hcm.XffNumTrustedHops)
	}
	if !hcm.GetUseRemoteAddress().GetValue() {
		t.Error("depth-based XFF strategy must set use_remote_address so depth N selects the Nth address from the right")
	}

	// RDS: the app route carries per-route security configs.
	rcs := snap.GetResources(resourcev3.RouteType)
	rc := rcs[httpsRouteConfigName].(*routev3.RouteConfiguration)
	var appRoute *routev3.Route
	for _, vh := range rc.VirtualHosts {
		for _, r := range vh.Routes {
			if r.GetRoute().GetCluster() == "app" {
				appRoute = r
			}
		}
	}
	if appRoute == nil {
		t.Fatal("no route for cluster app in RDS")
	}
	for _, w := range []string{basicAuthFilterName, rbacFilterName, extAuthzFilterName} {
		if _, ok := appRoute.TypedPerFilterConfig[w]; !ok {
			t.Errorf("app route missing per-route %q config; keys %v", w, keys(appRoute.TypedPerFilterConfig))
		}
	}
}

func TestForwardAuthURLPathBecomesAuthorizationPathPrefix(t *testing.T) {
	fa := &model.ForwardAuthMiddleware{Address: "https://auth.example.com:8443/verify/session"}
	cfg := extAuthzPerRoute("auth-fa", fa).GetCheckSettings().GetHttpService()
	if got, want := cfg.GetServerUri().GetUri(), "https://auth.example.com:8443"; got != want {
		t.Fatalf("server URI = %q, want origin %q", got, want)
	}
	if got, want := cfg.GetPathPrefix(), "/verify/session"; got != want {
		t.Fatalf("path prefix = %q, want %q", got, want)
	}
}

func TestBasicAuthRealmOnlyRewritesBasicChallenges(t *testing.T) {
	script := basicAuthRealmPerRoute("private").GetSourceCode().GetInlineString()
	for _, fragment := range []string{"www-authenticate", "string.lower", "basic "} {
		if !strings.Contains(script, fragment) {
			t.Fatalf("realm hook lacks Basic-challenge guard %q:\n%s", fragment, script)
		}
	}
}

func TestHTTPQuotedStringEscapesRealmDelimiters(t *testing.T) {
	if got, want := httpQuotedString(`private"area\one`), `private\"area\\one`; got != want {
		t.Fatalf("quoted realm = %q, want %q", got, want)
	}
}

func TestBuildSnapshotRejectsApplicationAuthClusterCollision(t *testing.T) {
	routes := map[string]model.Route{
		"auth-fa": {
			Subdomain: "auth-fa",
			Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}},
			Middlewares: []model.Middleware{{Name: "fa", ForwardAuth: &model.ForwardAuthMiddleware{
				Address: "https://auth.example.com/check",
			}}},
		},
	}
	_, err := BuildSnapshot("1", routes, Config{BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443})
	if err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatalf("expected auth/application cluster collision error, got %v", err)
	}
}

func TestBuildSnapshotAllowsSelectiveForwardAuthAndDisablesPublicRoute(t *testing.T) {
	routes := map[string]model.Route{
		"private": {Subdomain: "private", Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}}, Middlewares: []model.Middleware{{Name: "fa", ForwardAuth: &model.ForwardAuthMiddleware{Address: "http://auth.internal/check"}}}},
		"public":  {Subdomain: "public", Endpoints: []model.Endpoint{{Address: "10.0.0.2", Port: 8080}}},
	}
	snap, err := BuildSnapshot("1", routes, Config{BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	rc := snap.GetResources(resourcev3.RouteType)[httpsRouteConfigName].(*routev3.RouteConfiguration)
	for _, vh := range rc.VirtualHosts {
		for _, er := range vh.Routes {
			if er.Name != "public" {
				continue
			}
			cfg := &extauthzv3.ExtAuthzPerRoute{}
			unmarshalAny(t, er.TypedPerFilterConfig[extAuthzFilterName], cfg)
			if !cfg.GetDisabled() {
				t.Fatalf("public route ext_authz config = %+v, want disabled", cfg)
			}
			return
		}
	}
	t.Fatal("public route not found")
}

func TestSkippedUntranslatableRouteDoesNotAffectSecurityPlan(t *testing.T) {
	badRule, err := rule.Parse(`Host(bad.example.com) && ClientIP(10.0.0.0/8)`)
	if err != nil {
		t.Fatal(err)
	}
	routes := map[string]model.Route{
		"bad":  {Subdomain: "bad", RouterName: "bad", Rule: badRule, RuleExpr: `Host(bad.example.com) && ClientIP(10.0.0.0/8)`, Endpoints: []model.Endpoint{{Address: "10.0.0.1", Port: 8080}}, Middlewares: []model.Middleware{{Name: "basic", BasicAuth: &model.BasicAuthMiddleware{Users: []string{"alice:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="}}}}},
		"good": {Subdomain: "good", RouterName: "good", Endpoints: []model.Endpoint{{Address: "10.0.0.2", Port: 8080}}},
	}
	snap, err := BuildSnapshot("1", routes, Config{BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443})
	if err != nil {
		t.Fatalf("skipped route affected security plan: %v", err)
	}
	for _, name := range filterNames(httpsHCM(t, snap)) {
		if name == basicAuthFilterName {
			t.Fatal("unpublished route caused BasicAuth listener filter to be installed")
		}
	}
}

func TestBuildSnapshotForConfig_SecurityWiring(t *testing.T) {
	httpCfg := model.HTTPConfiguration{
		Routes: map[string]model.Route{
			"app": {
				Subdomain:       "app",
				RouterName:      "app",
				Endpoints:       []model.Endpoint{{Address: "10.0.0.1", Port: 8080}},
				Source:          model.SourceDocker,
				MiddlewareNames: []string{"fa"},
			},
		},
		Middlewares: map[string]model.Middleware{
			"fa": {Name: "fa", ForwardAuth: &model.ForwardAuthMiddleware{Address: "auth.example.com:8443"}},
		},
	}
	cfg := Config{BaseDomain: "example.com", HTTPPort: 80, HTTPSPort: 443, CertSecretName: "cert", ACMESDSClusterName: "acme"}
	snap, err := BuildSnapshotForConfig("1", httpCfg, cfg)
	if err != nil {
		t.Fatalf("BuildSnapshotForConfig() unexpected error: %v", err)
	}
	clusters := snap.GetResources(resourcev3.ClusterType)
	if _, ok := clusters["auth-fa"]; !ok {
		t.Errorf("expected auth cluster auth-fa in CDS, got %v", clusterNames(clusters))
	}
	hcm := httpsHCM(t, snap)
	names := filterNames(hcm)
	// Only ext_authz is present (single forwardauth middleware).
	foundExtAuthz := false
	for _, n := range names {
		if n == extAuthzFilterName {
			foundExtAuthz = true
		}
	}
	if !foundExtAuthz {
		t.Errorf("expected ext_authz filter in HTTPS chain, got %v", names)
	}
}

// keys returns the sorted keys of a per-filter config map for stable error
// messages.
func keys(m map[string]*anypb.Any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func clusterNames(m map[string]cachetypes.Resource) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

var _ = durationpb.New
var _ = matcherv3.StringMatcher{}
var _ = endpointv3.LbEndpoint{}
var _ = corev3.Address{}
