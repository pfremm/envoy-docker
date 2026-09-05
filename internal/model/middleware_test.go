package model

import "testing"

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
