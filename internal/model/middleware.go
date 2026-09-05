package model

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
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

func ValidateMiddlewareChain(chain []Middleware) error {
	redirects := 0
	pathOps := 0
	hasRegexPath := false
	redirectSeen := false
	corsSeen := false
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
	}
	return nil
}
