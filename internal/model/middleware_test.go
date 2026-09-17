package model

import (
	"strings"
	"testing"
)

func TestMiddlewareValidateExactlyOneTypedVariant(t *testing.T) {
	valid := Middleware{Name: "strip", StripPrefix: &StripPrefixMiddleware{Prefixes: []string{"/api"}}}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid middleware: %v", err)
	}
	for _, m := range []Middleware{
		{Name: "empty"},
		{Name: "two", AddPrefix: &AddPrefixMiddleware{Prefix: "/v1"}, ReplacePath: &ReplacePathMiddleware{Path: "/x"}},
	} {
		if err := m.Validate(); err == nil {
			t.Fatalf("expected invalid middleware: %+v", m)
		}
	}
}

func TestMiddlewareChainRejectsNonTerminalRedirectAndComposedRegexRewrite(t *testing.T) {
	cases := [][]Middleware{
		{{Name: "r", RedirectScheme: &RedirectSchemeMiddleware{Scheme: "https"}}, {Name: "h", Headers: &HeadersMiddleware{Request: map[string]string{"x": "y"}}}},
		{{Name: "rx", ReplacePathRegex: &ReplacePathRegexMiddleware{Regex: "^/a$", Replacement: "/b"}}, {Name: "add", AddPrefix: &AddPrefixMiddleware{Prefix: "/x"}}},
		{{Name: "cors", CORS: &CORSMiddleware{AllowOrigins: []string{"*"}}}, {Name: "h", Headers: &HeadersMiddleware{Request: map[string]string{"x": "y"}}}},
	}
	for _, chain := range cases {
		if err := ValidateMiddlewareChain(chain); err == nil {
			t.Errorf("expected invalid chain: %+v", chain)
		}
	}
}

func TestMiddlewareChainRejectsSameSecurityFilterOverwrite(t *testing.T) {
	chains := [][]Middleware{
		{{Name: "a", BasicAuth: &BasicAuthMiddleware{Users: []string{"a:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="}}}, {Name: "b", BasicAuth: &BasicAuthMiddleware{Users: []string{"b:{SHA}2jmj7l5rSw0yVb/vlWAYkK/YBwk="}}}},
		{{Name: "allow", IPAllowList: &IPAllowListMiddleware{SourceRange: []string{"10.0.0.0/8"}}}, {Name: "deny", IPDenyList: &IPDenyListMiddleware{SourceRange: []string{"192.0.2.0/24"}}}},
		{{Name: "fast", RateLimit: &RateLimitMiddleware{Average: 1, Burst: 1, Period: "1s"}}, {Name: "slow", RateLimit: &RateLimitMiddleware{Average: 2, Burst: 2, Period: "1s"}}},
	}
	for _, chain := range chains {
		if err := ValidateMiddlewareChain(chain); err == nil {
			t.Errorf("expected same-filter chain rejection: %+v", chain)
		}
	}
}

func TestMiddlewareValidateRejectsUnsafeHeadersAndRegex(t *testing.T) {
	cases := []Middleware{
		{Name: "pseudo", Headers: &HeadersMiddleware{Request: map[string]string{":authority": "evil"}}},
		{Name: "bad-name", Headers: &HeadersMiddleware{Response: map[string]string{"bad header": "x"}}},
		{Name: "bad-regex", RedirectRegex: &RedirectRegexMiddleware{Regex: "[", Replacement: "/"}},
		{Name: "empty-list", StripPrefix: &StripPrefixMiddleware{}},
	}
	for _, m := range cases {
		if err := m.Validate(); err == nil {
			t.Errorf("expected validation error for %+v", m)
		}
	}
}

func TestSecurityMiddlewareValidationAndRedaction(t *testing.T) {
	secret := "alice:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
	valid := []Middleware{
		{Name: "basic", BasicAuth: &BasicAuthMiddleware{Users: []string{secret}, HeaderField: "X-Authenticated-User", RemoveHeader: true}},
		{Name: "forward", ForwardAuth: &ForwardAuthMiddleware{Address: "auth.internal:8443", TrustForwardHeader: true}},
		{Name: "allow", IPAllowList: &IPAllowListMiddleware{SourceRange: []string{"10.0.0.0/8", "2001:db8::/32"}}},
		{Name: "deny", IPDenyList: &IPDenyListMiddleware{SourceRange: []string{"192.0.2.1"}, Strategy: IPStrategy{Depth: 1}}},
		{Name: "rate", RateLimit: &RateLimitMiddleware{Average: 10, Burst: 20, Period: "1s"}},
	}
	for _, m := range valid {
		if err := m.Validate(); err != nil {
			t.Errorf("%s should be valid: %v", m.Name, err)
		}
	}
	if got := valid[0].RedactedString(); strings.Contains(got, "alice") || strings.Contains(got, "{SHA}") {
		t.Fatalf("basic-auth credentials leaked from redacted rendering: %s", got)
	}
}

func TestSecurityMiddlewareValidationFailuresDoNotLeakHashes(t *testing.T) {
	secret := "super-secret-hash"
	cases := []Middleware{
		{Name: "basic", BasicAuth: &BasicAuthMiddleware{Users: []string{secret}}},
		{Name: "basic-newline", BasicAuth: &BasicAuthMiddleware{Users: []string{"alice:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=\n"}}},
		{Name: "forward", ForwardAuth: &ForwardAuthMiddleware{Address: "https:// bad"}},
		{Name: "forward-query", ForwardAuth: &ForwardAuthMiddleware{Address: "https://auth.internal/check?tenant=one"}},
		{Name: "allow", IPAllowList: &IPAllowListMiddleware{SourceRange: []string{"not-a-cidr"}}},
		{Name: "deny", IPDenyList: &IPDenyListMiddleware{}},
		{Name: "rate-average", RateLimit: &RateLimitMiddleware{Burst: 1, Period: "1s"}},
		{Name: "rate-burst", RateLimit: &RateLimitMiddleware{Average: 1, Period: "1s"}},
		{Name: "rate-period", RateLimit: &RateLimitMiddleware{Average: 1, Burst: 1, Period: "soon"}},
		{Name: "rate-too-fast", RateLimit: &RateLimitMiddleware{Average: 1, Burst: 1, Period: "10ms"}},
		{Name: "bad-auth-header", BasicAuth: &BasicAuthMiddleware{Users: []string{"alice:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="}, HeaderField: "bad header"}},
		{Name: "bad-auth-regex", ForwardAuth: &ForwardAuthMiddleware{Address: "auth.internal", AuthResponseHeaderRegex: []string{"["}}},
		{Name: "ambiguous-ip", IPAllowList: &IPAllowListMiddleware{SourceRange: []string{"10.0.0.0/8"}, Strategy: IPStrategy{Depth: 1, ExcludedIPs: []string{"10.0.0.0/8"}}}},
	}
	for _, m := range cases {
		err := m.Validate()
		if err == nil {
			t.Errorf("%s should be invalid", m.Name)
		} else if strings.Contains(err.Error(), secret) {
			t.Fatalf("%s leaked a basic-auth hash: %v", m.Name, err)
		}
	}
}
