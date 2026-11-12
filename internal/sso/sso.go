// Package sso loads and validates the operator's OAuth SSO profiles
// (SSO_CONFIG_PATH). A profile describes one OIDC client: the identity
// provider endpoints, the client credentials (as file-based SDS secret
// references, never inline secret material), and the callback host. Routers
// opt in to a profile with the envoy.http.routers.<name>.sso label; the xds
// package turns the profiles referenced by accepted routers into Envoy's
// native oauth2 + jwt_authn filters.
//
// Validation is per profile: one broken profile is recorded with its error
// and never prevents the other profiles from loading, so only the routers
// that reference it are rejected (mirroring the per-router failure isolation
// of label parsing).
package sso

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Defaults applied to optional profile fields.
const (
	DefaultRedirectPath  = "/oauth2/callback"
	DefaultSignoutPath   = "/oauth2/signout"
	DefaultTimeout       = 5 * time.Second
	DefaultCacheDuration = 300 * time.Second
)

// DefaultAuthScopes is used when a profile omits auth_scopes.
var DefaultAuthScopes = []string{"openid", "email"}

// Endpoint is an IdP HTTPS endpoint reached through a control-plane
// generated upstream cluster.
type Endpoint struct {
	// Cluster is the Envoy cluster name the endpoint is fetched through.
	Cluster string
	// URI is the absolute https URI.
	URI string
	// Host and Port are the URI's authority (Port defaults to 443); they
	// define the generated cluster's single upstream address.
	Host    string
	Port    uint32
	Timeout time.Duration
}

// Authority is the scheme-qualified host:port an Endpoint's cluster points
// at. Two endpoints may share a cluster name only if their authorities match.
func (e Endpoint) Authority() string {
	return "https://" + net.JoinHostPort(e.Host, strconv.FormatUint(uint64(e.Port), 10))
}

// Secret is a file-based SDS secret reference. The control plane only emits
// the reference; the file at SDSPath is read by Envoy (it must be mounted
// into the Envoy container), never by the control plane.
type Secret struct {
	Name    string
	SDSPath string
}

// PassThroughMatcher lets requests carrying a matching header bypass the
// interactive oauth2 flow (they are still validated by jwt_authn).
type PassThroughMatcher struct {
	Header string
	Prefix string
}

// Profile is one validated SSO profile.
type Profile struct {
	Name string
	// RedirectURIHost is the fixed callback host, optionally with :port
	// (for HTTPS on a non-standard port).
	RedirectURIHost       string
	RedirectPath          string
	SignoutPath           string
	CookieDomain          string
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         Endpoint
	JWKS                  Endpoint
	JWKSCacheDuration     time.Duration
	ClientID              string
	HMACSecret            Secret
	// TokenSecret is unset (zero) when ClientSecret is set and the
	// token_secret field was omitted.
	TokenSecret Secret
	// ClientSecret is the confidential client's secret (zero for a public
	// client).
	ClientSecret Secret
	AuthScopes   []string
	PassThrough  PassThroughMatcher
}

// HasClientSecret reports whether the profile is a confidential client
// configured with credentials.client_secret.
func (p Profile) HasClientSecret() bool {
	return p.ClientSecret.Name != ""
}

// ClientSecretRef is the secret emitted as OAuth2Credentials.token_secret
// (Envoy's only client-secret slot): credentials.client_secret when set,
// otherwise token_secret.
func (p Profile) ClientSecretRef() Secret {
	if p.HasClientSecret() {
		return p.ClientSecret
	}
	return p.TokenSecret
}

// secrets lists every configured secret reference of the profile.
func (p Profile) secrets() []Secret {
	out := []Secret{p.HMACSecret}
	for _, s := range []Secret{p.TokenSecret, p.ClientSecret} {
		if s.Name != "" {
			out = append(out, s)
		}
	}
	return out
}

// RedirectURI is the absolute OAuth2 callback URI.
func (p Profile) RedirectURI() string {
	return "https://" + p.RedirectURIHost + p.RedirectPath
}

// RedirectHostname is RedirectURIHost without any :port, i.e. the virtual
// host domain the callback is served on (route configs ignore the port in
// host matching).
func (p Profile) RedirectHostname() string {
	if h, _, err := net.SplitHostPort(p.RedirectURIHost); err == nil {
		return h
	}
	return p.RedirectURIHost
}

// Config is the result of loading SSO_CONFIG_PATH.
type Config struct {
	// Path is the file the config was loaded from.
	Path string
	// LoadErr is non-nil when the file could not be read or parsed at all.
	// Every router referencing any profile is then rejected with it.
	LoadErr error
	// Profiles holds the valid profiles by name.
	Profiles map[string]Profile
	// Invalid holds the rejected profiles by name, with the reason.
	Invalid map[string]error
}

// Lookup resolves a router's sso label value to a profile, or returns the
// actionable reason the router must be rejected. A nil Config means
// SSO_CONFIG_PATH is not set.
func (c *Config) Lookup(name string) (Profile, error) {
	if c == nil {
		return Profile{}, fmt.Errorf("sso profile %q requested but SSO_CONFIG_PATH is not set", name)
	}
	if c.LoadErr != nil {
		return Profile{}, fmt.Errorf("sso profile %q requested but the SSO config failed to load: %w", name, c.LoadErr)
	}
	if err, bad := c.Invalid[name]; bad {
		return Profile{}, fmt.Errorf("sso profile %q is invalid: %w", name, err)
	}
	p, ok := c.Profiles[name]
	if !ok {
		return Profile{}, fmt.Errorf("sso profile %q is not defined in %s (defined profiles: %s)", name, c.Path, strings.Join(sortedKeys(c.Profiles), ","))
	}
	return p, nil
}

// SortedProfileNames returns the valid profile names in sorted order.
func (c *Config) SortedProfileNames() []string {
	if c == nil {
		return nil
	}
	return sortedKeys(c.Profiles)
}

// Load reads and validates the SSO profiles file. An empty path returns
// (nil, nil): SSO is disabled. A file-level failure (unreadable, not YAML,
// unknown top-level keys) is returned both as the error and in
// Config.LoadErr, so callers can log it and keep running with every
// sso-labeled router rejected.
func Load(path string) (*Config, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		err = fmt.Errorf("reading SSO config %s: %w", path, err)
		return &Config{Path: path, LoadErr: err}, err
	}
	cfg := Parse(path, data)
	return cfg, cfg.LoadErr
}

type fileFormat struct {
	SSOProfiles map[string]yaml.Node `yaml:"sso_profiles"`
}

type endpointYAML struct {
	Cluster       string `yaml:"cluster"`
	URI           string `yaml:"uri"`
	Timeout       string `yaml:"timeout"`
	CacheDuration string `yaml:"cache_duration"`
}

type secretYAML struct {
	Name    string `yaml:"name"`
	SDSPath string `yaml:"sds_path"`
}

type profileYAML struct {
	RedirectURIHost       string        `yaml:"redirect_uri_host"`
	RedirectPath          string        `yaml:"redirect_path"`
	SignoutPath           string        `yaml:"signout_path"`
	CookieDomain          string        `yaml:"cookie_domain"`
	Issuer                string        `yaml:"issuer"`
	AuthorizationEndpoint string        `yaml:"authorization_endpoint"`
	TokenEndpoint         *endpointYAML `yaml:"token_endpoint"`
	JWKS                  *endpointYAML `yaml:"jwks"`
	Credentials           *struct {
		ClientID string `yaml:"client_id"`
		// ClientSecret is decoded by hand (see parseClientSecret) so an
		// inline secret value gets a clear error rather than a type error.
		ClientSecret yaml.Node `yaml:"client_secret"`
	} `yaml:"credentials"`
	HMACSecret         *secretYAML `yaml:"hmac_secret"`
	TokenSecret        *secretYAML `yaml:"token_secret"`
	AuthScopes         []string    `yaml:"auth_scopes"`
	PassThroughMatcher *struct {
		Header string `yaml:"header"`
		Prefix string `yaml:"prefix"`
	} `yaml:"pass_through_matcher"`
}

// Parse validates file contents. It never fails as a whole except for a
// file-level problem (recorded in LoadErr); individual profile problems are
// recorded in Invalid.
func Parse(path string, data []byte) *Config {
	cfg := &Config{Path: path, Profiles: map[string]Profile{}, Invalid: map[string]error{}}
	var file fileFormat
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&file); err != nil && !errors.Is(err, io.EOF) {
		cfg.LoadErr = fmt.Errorf("parsing SSO config %s: %w", path, err)
		return cfg
	}

	names := make([]string, 0, len(file.SSOProfiles))
	for name := range file.SSOProfiles {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		node := file.SSOProfiles[name]
		p, err := parseProfile(name, &node)
		if err != nil {
			cfg.Invalid[name] = err
			continue
		}
		cfg.Profiles[name] = p
	}
	validateCrossProfile(cfg)
	return cfg
}

var profileNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`)

// clusterNameRE restricts generated cluster names to a conservative,
// Envoy-safe charset.
var clusterNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

var hostnameRE = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

var headerNameRE = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+.^_|~-]+$`)

func parseProfile(name string, node *yaml.Node) (Profile, error) {
	if !profileNameRE.MatchString(name) {
		return Profile{}, fmt.Errorf("profile name %q is invalid (use 1-63 letters, digits, '-' or '_', starting with a letter or digit)", name)
	}
	// Decode strictly so a typo (or an inline client_secret, which is
	// deliberately unsupported) is reported instead of silently ignored.
	// Strictness is scoped to this profile: other profiles still load.
	raw, err := yaml.Marshal(node)
	if err != nil {
		return Profile{}, fmt.Errorf("re-encoding profile: %w", err)
	}
	var y profileYAML
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&y); err != nil {
		return Profile{}, fmt.Errorf("decoding profile: %w", err)
	}

	p := Profile{
		Name:                  name,
		RedirectURIHost:       strings.TrimSpace(y.RedirectURIHost),
		RedirectPath:          y.RedirectPath,
		SignoutPath:           y.SignoutPath,
		CookieDomain:          strings.TrimSpace(y.CookieDomain),
		Issuer:                strings.TrimSpace(y.Issuer),
		AuthorizationEndpoint: strings.TrimSpace(y.AuthorizationEndpoint),
		JWKSCacheDuration:     DefaultCacheDuration,
	}
	if p.RedirectPath == "" {
		p.RedirectPath = DefaultRedirectPath
	}
	if p.SignoutPath == "" {
		p.SignoutPath = DefaultSignoutPath
	}

	if p.RedirectURIHost == "" {
		return Profile{}, fmt.Errorf("redirect_uri_host is required (the fixed callback host, e.g. sso.example.com)")
	}
	if err := validateHostPort(p.RedirectURIHost); err != nil {
		return Profile{}, fmt.Errorf("redirect_uri_host %q: %w", p.RedirectURIHost, err)
	}
	for field, v := range map[string]string{"redirect_path": p.RedirectPath, "signout_path": p.SignoutPath} {
		if !strings.HasPrefix(v, "/") || strings.ContainsAny(v, "?# \t") {
			return Profile{}, fmt.Errorf("%s %q must be an absolute path starting with '/' without query, fragment or whitespace", field, v)
		}
	}
	if p.RedirectPath == p.SignoutPath {
		return Profile{}, fmt.Errorf("redirect_path and signout_path must differ (both %q)", p.RedirectPath)
	}

	if p.CookieDomain == "" {
		return Profile{}, fmt.Errorf("cookie_domain is required: the callback is served on redirect_uri_host, so the session cookies must be scoped to a parent domain shared with the protected hosts")
	}
	p.CookieDomain = strings.TrimPrefix(p.CookieDomain, ".")
	if !hostnameRE.MatchString(p.CookieDomain) {
		return Profile{}, fmt.Errorf("cookie_domain %q is not a valid domain name", y.CookieDomain)
	}
	if rh := strings.ToLower(p.RedirectHostname()); rh != strings.ToLower(p.CookieDomain) && !strings.HasSuffix(rh, "."+strings.ToLower(p.CookieDomain)) {
		return Profile{}, fmt.Errorf("redirect_uri_host %q is not within cookie_domain %q; cookies set by the callback would not be sent to the protected hosts", p.RedirectURIHost, p.CookieDomain)
	}

	// The issuer is matched verbatim against the token's iss claim (RFC 7519
	// treats it as an opaque string), so it is only required to be present.
	if p.Issuer == "" {
		return Profile{}, fmt.Errorf("issuer is required (must equal the iss claim of the IdP's tokens)")
	}
	if p.AuthorizationEndpoint == "" {
		return Profile{}, fmt.Errorf("authorization_endpoint is required")
	}
	if _, _, err := parseHTTPSURI(p.AuthorizationEndpoint); err != nil {
		return Profile{}, fmt.Errorf("authorization_endpoint: %w", err)
	}

	if y.TokenEndpoint == nil {
		return Profile{}, fmt.Errorf("token_endpoint is required ({cluster, uri, timeout})")
	}
	if y.TokenEndpoint.CacheDuration != "" {
		return Profile{}, fmt.Errorf("token_endpoint: cache_duration is only valid on jwks")
	}
	if p.TokenEndpoint, err = parseEndpoint(*y.TokenEndpoint); err != nil {
		return Profile{}, fmt.Errorf("token_endpoint: %w", err)
	}
	if y.JWKS == nil {
		return Profile{}, fmt.Errorf("jwks is required ({cluster, uri})")
	}
	if p.JWKS, err = parseEndpoint(*y.JWKS); err != nil {
		return Profile{}, fmt.Errorf("jwks: %w", err)
	}
	if y.JWKS.CacheDuration != "" {
		if p.JWKSCacheDuration, err = parsePositiveDuration(y.JWKS.CacheDuration); err != nil {
			return Profile{}, fmt.Errorf("jwks.cache_duration: %w", err)
		}
	}
	if p.TokenEndpoint.Cluster == p.JWKS.Cluster && p.TokenEndpoint.Authority() != p.JWKS.Authority() {
		return Profile{}, fmt.Errorf("token_endpoint and jwks share cluster %q but point at different upstreams (%s vs %s)", p.JWKS.Cluster, p.TokenEndpoint.Authority(), p.JWKS.Authority())
	}

	if y.Credentials == nil || strings.TrimSpace(y.Credentials.ClientID) == "" {
		return Profile{}, fmt.Errorf("credentials.client_id is required")
	}
	p.ClientID = strings.TrimSpace(y.Credentials.ClientID)

	if p.HMACSecret, err = parseSecret("hmac_secret", y.HMACSecret); err != nil {
		return Profile{}, err
	}
	if p.ClientSecret, err = parseClientSecret(&y.Credentials.ClientSecret); err != nil {
		return Profile{}, err
	}
	// Envoy's OAuth2Credentials requires token_secret, which is the client
	// secret sent to the token endpoint. A confidential client sets
	// credentials.client_secret (emitted there instead); a public
	// (PKCE-only) client points token_secret at a dummy generic secret.
	// token_secret stays allowed (but unused) alongside client_secret so an
	// existing deployment can add client_secret without removing it.
	if y.TokenSecret != nil || !p.HasClientSecret() {
		if y.TokenSecret == nil {
			return Profile{}, fmt.Errorf("token_secret is required ({name, sds_path}) unless credentials.client_secret is set")
		}
		if p.TokenSecret, err = parseSecret("token_secret", y.TokenSecret); err != nil {
			return Profile{}, err
		}
		if p.HMACSecret.Name == p.TokenSecret.Name {
			return Profile{}, fmt.Errorf("hmac_secret and token_secret must use different secret names (both %q)", p.HMACSecret.Name)
		}
	}
	if p.HasClientSecret() {
		for _, o := range []struct {
			field string
			s     Secret
		}{{"hmac_secret", p.HMACSecret}, {"token_secret", p.TokenSecret}} {
			if o.s.Name == "" {
				continue
			}
			if p.ClientSecret.Name == o.s.Name {
				return Profile{}, fmt.Errorf("credentials.client_secret and %s must use different secret names (both %q)", o.field, o.s.Name)
			}
			if p.ClientSecret.SDSPath == o.s.SDSPath {
				return Profile{}, fmt.Errorf("credentials.client_secret and %s must use different sds_path files (both %s)", o.field, o.s.SDSPath)
			}
		}
	}

	if y.AuthScopes == nil {
		p.AuthScopes = append([]string(nil), DefaultAuthScopes...)
	} else {
		if len(y.AuthScopes) == 0 {
			return Profile{}, fmt.Errorf("auth_scopes must not be empty (omit it for the default %v)", DefaultAuthScopes)
		}
		for _, s := range y.AuthScopes {
			if s == "" || strings.ContainsAny(s, " \t") {
				return Profile{}, fmt.Errorf("auth_scopes entry %q must be a non-empty token without whitespace", s)
			}
		}
		p.AuthScopes = append([]string(nil), y.AuthScopes...)
	}

	p.PassThrough = PassThroughMatcher{Header: "authorization", Prefix: "Bearer "}
	if m := y.PassThroughMatcher; m != nil {
		if !headerNameRE.MatchString(m.Header) {
			return Profile{}, fmt.Errorf("pass_through_matcher.header %q must be a valid HTTP header name", m.Header)
		}
		if m.Prefix == "" {
			return Profile{}, fmt.Errorf("pass_through_matcher.prefix is required")
		}
		p.PassThrough = PassThroughMatcher{Header: strings.ToLower(m.Header), Prefix: m.Prefix}
	}
	return p, nil
}

func parseEndpoint(y endpointYAML) (Endpoint, error) {
	if !clusterNameRE.MatchString(y.Cluster) {
		return Endpoint{}, fmt.Errorf("cluster %q is required and may only contain letters, digits, '_', '.' and '-'", y.Cluster)
	}
	host, port, err := parseHTTPSURI(y.URI)
	if err != nil {
		return Endpoint{}, fmt.Errorf("uri: %w", err)
	}
	e := Endpoint{Cluster: y.Cluster, URI: y.URI, Host: host, Port: port, Timeout: DefaultTimeout}
	if y.Timeout != "" {
		if e.Timeout, err = parsePositiveDuration(y.Timeout); err != nil {
			return Endpoint{}, fmt.Errorf("timeout: %w", err)
		}
	}
	return e, nil
}

func parseSecret(field string, y *secretYAML) (Secret, error) {
	if y == nil {
		return Secret{}, fmt.Errorf("%s is required ({name, sds_path})", field)
	}
	if strings.TrimSpace(y.Name) == "" {
		return Secret{}, fmt.Errorf("%s.name is required", field)
	}
	if !filepath.IsAbs(y.SDSPath) {
		return Secret{}, fmt.Errorf("%s.sds_path %q must be an absolute path (inside the Envoy container)", field, y.SDSPath)
	}
	return Secret{Name: strings.TrimSpace(y.Name), SDSPath: filepath.Clean(y.SDSPath)}, nil
}

// parseClientSecret decodes the optional credentials.client_secret
// reference. Only an SDS file reference is accepted: any other shape (a
// plain string, null, or extra keys such as secret/value) is rejected so
// secret material can never be inlined in the profile file.
func parseClientSecret(n *yaml.Node) (Secret, error) {
	const field = "credentials.client_secret"
	const noInline = "inline secrets are not supported; put the secret in an SDS file inside the Envoy container and reference it as {name, sds_path}"
	if n.Kind == 0 {
		return Secret{}, nil
	}
	if n.Kind != yaml.MappingNode {
		return Secret{}, fmt.Errorf("%s must be a mapping {name, sds_path}: %s", field, noInline)
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if k := n.Content[i].Value; k != "name" && k != "sds_path" {
			return Secret{}, fmt.Errorf("%s: unknown key %q (only name and sds_path are allowed): %s", field, k, noInline)
		}
	}
	var y secretYAML
	if err := n.Decode(&y); err != nil {
		return Secret{}, fmt.Errorf("%s: %w", field, err)
	}
	return parseSecret(field, &y)
}

func parsePositiveDuration(v string) (time.Duration, error) {
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid duration %q (must be a positive Go duration such as 5s)", v)
	}
	return d, nil
}

// parseHTTPSURI requires an absolute https URI with a host and no userinfo,
// returning the host and the effective port (default 443).
func parseHTTPSURI(raw string) (string, uint32, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", 0, fmt.Errorf("%q is not a valid URL: %v", raw, err)
	}
	if u.Scheme != "https" {
		return "", 0, fmt.Errorf("%q must be an absolute https:// URL", raw)
	}
	if u.Hostname() == "" {
		return "", 0, fmt.Errorf("%q has no host", raw)
	}
	if u.User != nil {
		return "", 0, fmt.Errorf("%q must not contain credentials", raw)
	}
	port := uint64(443)
	if ps := u.Port(); ps != "" {
		port, err = strconv.ParseUint(ps, 10, 16)
		if err != nil || port == 0 {
			return "", 0, fmt.Errorf("%q has an invalid port", raw)
		}
	}
	return u.Hostname(), uint32(port), nil
}

func validateHostPort(v string) error {
	const want = "must be a bare host name (optionally :port), without scheme or path"
	if strings.ContainsAny(v, "/?#@ ") {
		return errors.New(want)
	}
	host := v
	if h, ps, err := net.SplitHostPort(v); err == nil {
		host = h
		if n, err := strconv.ParseUint(ps, 10, 16); err != nil || n == 0 {
			return fmt.Errorf("invalid port %q", ps)
		}
	}
	if !hostnameRE.MatchString(host) {
		return errors.New(want)
	}
	return nil
}

// validateCrossProfile checks constraints spanning profiles. Profiles are
// visited in sorted order and the later conflicting profile is invalidated,
// so the outcome is deterministic.
func validateCrossProfile(cfg *Config) {
	clusterOwner := map[string]Profile{}
	clusterAuthority := map[string]string{}
	secretPath := map[string]string{}
	secretOwner := map[string]string{}
	callbackOwner := map[string]string{}
	for _, name := range sortedKeys(cfg.Profiles) {
		p := cfg.Profiles[name]
		var conflict error
		for _, e := range []Endpoint{p.TokenEndpoint, p.JWKS} {
			if auth, ok := clusterAuthority[e.Cluster]; ok && auth != e.Authority() {
				conflict = fmt.Errorf("cluster %q points at %s but profile %q already uses it for %s; use a distinct cluster name", e.Cluster, e.Authority(), clusterOwner[e.Cluster].Name, auth)
				break
			}
		}
		for _, s := range p.secrets() {
			if conflict != nil {
				break
			}
			if path, ok := secretPath[s.Name]; ok && path != s.SDSPath {
				conflict = fmt.Errorf("secret %q uses sds_path %s but profile %q already maps it to %s", s.Name, s.SDSPath, secretOwner[s.Name], path)
			}
		}
		host := strings.ToLower(p.RedirectHostname())
		for _, path := range []string{p.RedirectPath, p.SignoutPath} {
			if conflict != nil {
				break
			}
			if owner, ok := callbackOwner[host+path]; ok {
				conflict = fmt.Errorf("callback/signout path %s%s is already used by profile %q; profiles sharing a redirect_uri_host need distinct redirect_path and signout_path", host, path, owner)
			}
		}
		if conflict != nil {
			cfg.Invalid[name] = conflict
			delete(cfg.Profiles, name)
			continue
		}
		for _, e := range []Endpoint{p.TokenEndpoint, p.JWKS} {
			clusterAuthority[e.Cluster] = e.Authority()
			clusterOwner[e.Cluster] = p
		}
		for _, s := range p.secrets() {
			secretPath[s.Name] = s.SDSPath
			secretOwner[s.Name] = name
		}
		callbackOwner[host+p.RedirectPath] = name
		callbackOwner[host+p.SignoutPath] = name
	}
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Loader re-reads SSO_CONFIG_PATH on demand so profile edits are picked up
// without a restart. Current is called once per snapshot build (every docker
// event and every RESYNC_INTERVAL); the file is re-parsed and the outcome
// logged only when its contents (or the read error) change.
type Loader struct {
	path   string
	logger *slog.Logger

	lastData []byte
	lastErr  string
	cfg      *Config
}

// NewLoader returns a Loader for path. An empty path yields a Loader whose
// Current is always nil (SSO disabled).
func NewLoader(path string, logger *slog.Logger) *Loader {
	if logger == nil {
		logger = slog.Default()
	}
	return &Loader{path: path, logger: logger}
}

// Current returns the latest SSO config (nil when SSO is disabled). It is
// not safe for concurrent use.
func (l *Loader) Current() *Config {
	if l == nil || l.path == "" {
		return nil
	}
	data, err := os.ReadFile(l.path)
	if err != nil {
		msg := err.Error()
		if l.cfg == nil || l.lastErr != msg {
			l.logger.Error("SSO config unreadable; every sso-labeled router will be rejected", "path", l.path, "error", err)
		}
		l.lastErr, l.lastData = msg, nil
		l.cfg = &Config{Path: l.path, LoadErr: fmt.Errorf("reading SSO config %s: %w", l.path, err)}
		return l.cfg
	}
	if l.cfg != nil && l.lastErr == "" && bytes.Equal(data, l.lastData) {
		return l.cfg
	}
	l.lastErr, l.lastData = "", data
	l.cfg = Parse(l.path, data)
	if l.cfg.LoadErr != nil {
		l.logger.Error("SSO config failed to parse; every sso-labeled router will be rejected", "path", l.path, "error", l.cfg.LoadErr)
		return l.cfg
	}
	for _, name := range sortedKeys(l.cfg.Invalid) {
		l.logger.Warn("discarding invalid SSO profile; routers referencing it will be rejected", "profile", name, "error", l.cfg.Invalid[name])
	}
	l.logger.Info("loaded SSO profiles", "path", l.path, "valid", strings.Join(l.cfg.SortedProfileNames(), ","), "invalid", len(l.cfg.Invalid))
	return l.cfg
}
