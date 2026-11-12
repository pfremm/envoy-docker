package xds

import (
	"log/slog"
	"strings"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	jwtauthnv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	oauth2v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/oauth2/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	matcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
	"github.com/bryanpfremm/envoy-control-plane/internal/sso"
)

// SSO filter names. Envoy has one oauth2 filter config per filter instance,
// so each profile used on a listener gets its own oauth2 filter
// (oauth2FilterPrefix + profile); a single jwt_authn filter carries one
// provider and one requirement per profile.
const (
	oauth2FilterPrefix = "envoy.filters.http.oauth2."
	jwtAuthnFilterName = "envoy.filters.http.jwt_authn"

	// ssoCallbackVHPrefix names the virtual host synthesized for a
	// redirect_uri_host no router serves.
	ssoCallbackVHPrefix = "sso_callback__"
)

func oauth2FilterName(profile string) string { return oauth2FilterPrefix + profile }

// applyHSTS enables HSTS on an HTTPS route configuration. It is only ever
// applied to the TLS listeners' RDS configs; the plain-HTTP redirect
// listener's inline route config never gets it (HSTS over plain HTTP is
// ignored by browsers and would be misleading).
func applyHSTS(rc *routev3.RouteConfiguration) {
	// ADD_IF_ABSENT: an upstream that sets its own policy keeps it.
	rc.ResponseHeadersToAdd = append(rc.ResponseHeadersToAdd, &corev3.HeaderValueOption{
		Header:       &corev3.HeaderValue{Key: "Strict-Transport-Security", Value: "max-age=31536000; includeSubDomains"},
		AppendAction: corev3.HeaderValueOption_ADD_IF_ABSENT,
	})
}

// filterSSORoutes rejects (only) the routers whose .sso label cannot be
// honored: SSO_CONFIG_PATH unset, the file failed to load, or the profile is
// unknown or invalid. A rejected router is dropped entirely rather than
// served without SSO, so a misconfiguration fails closed.
//
// SSO also requires a TLS router; every HTTP entrypoint this control plane
// generates terminates TLS (see LABELS.md "HTTP entrypoints"), so any router
// that reaches this point qualifies. If a plain-HTTP entrypoint is ever
// added, sso routers on it must be rejected here.
func filterSSORoutes(routes map[string]model.Route, cfg Config, logger *slog.Logger) map[string]model.Route {
	out := make(map[string]model.Route, len(routes))
	for _, key := range sortedSubdomains(routes) {
		route := routes[key]
		if route.SSOProfile != "" {
			if _, err := cfg.SSO.Lookup(route.SSOProfile); err != nil {
				if logger != nil {
					logger.Warn("skipping router: sso profile cannot be applied",
						"router", route.RouterName, "subdomain", route.Subdomain, "origin", route.Origin,
						"sso", route.SSOProfile, "error", err)
				}
				continue
			}
		}
		out[key] = route
	}
	return out
}

// ssoPlan is the snapshot-wide SSO configuration: which profiles each HTTPS
// route configuration (and therefore its listener) uses, and the IdP
// clusters to emit.
type ssoPlan struct {
	byRouteConfig map[string][]sso.Profile
	clusters      []*clusterv3.Cluster
}

// planSSO assigns profiles to virtual hosts, writes the per-route oauth2 /
// jwt_authn overrides, and adds callback routes, mutating the route configs
// in place. It must run after per-route middleware compilation and before
// applySecurityDefaultsToAll (so synthesized callback routes also receive
// the ext_authz disabled default). Route configs with no opted-in router
// are left untouched.
//
// Clusters are emitted only for profiles used by at least one published
// router: an unused profile costs nothing at runtime (no DNS resolution of
// the IdP, no TLS handshakes) and keeps the output of SSO-free deployments
// identical to before.
func planSSO(rcs []*routev3.RouteConfiguration, published map[string]model.Route, cfg Config, logger *slog.Logger) *ssoPlan {
	plan := &ssoPlan{byRouteConfig: map[string][]sso.Profile{}}
	if cfg.SSO == nil {
		return plan
	}
	profileByRoute := map[string]string{}
	for _, route := range published {
		if route.SSOProfile != "" {
			profileByRoute[routeResourceName(route)] = route.SSOProfile
		}
	}
	if len(profileByRoute) == 0 {
		return plan
	}
	usedAnywhere := map[string]sso.Profile{}
	for _, rc := range rcs {
		profiles := applySSOToRouteConfig(rc, profileByRoute, cfg.SSO, logger)
		if len(profiles) == 0 {
			continue
		}
		plan.byRouteConfig[rc.Name] = profiles
		for _, p := range profiles {
			usedAnywhere[p.Name] = p
		}
	}
	plan.clusters = ssoClusters(usedAnywhere)
	return plan
}

// applySSOToRouteConfig applies SSO to one route configuration and returns
// the profiles it uses (sorted by name).
//
// SSO is whole-virtual-host: if any router on a virtual host opts in, every
// route on that host is protected, so a public router sharing a host with an
// SSO router cannot silently expose part of the subdomain. Should two
// routers on one host name different profiles, each keeps its own and the
// host's unlabeled routes take the alphabetically first one (logged).
func applySSOToRouteConfig(rc *routev3.RouteConfiguration, profileByRoute map[string]string, cfg *sso.Config, logger *slog.Logger) []sso.Profile {
	assigned := map[*routev3.Route]string{}
	used := map[string]bool{}
	for _, vh := range rc.VirtualHosts {
		if vh.Name == catchAllVHName {
			// The catch-all copies of legacy routes are constrained to their
			// own host; protect each by its own router's label.
			for _, er := range vh.Routes {
				if p := profileByRoute[er.Name]; p != "" {
					assigned[er] = p
					used[p] = true
				}
			}
			continue
		}
		hostProfiles := map[string]bool{}
		for _, er := range vh.Routes {
			if p := profileByRoute[er.Name]; p != "" {
				hostProfiles[p] = true
			}
		}
		if len(hostProfiles) == 0 {
			continue
		}
		names := sortedStringKeys(hostProfiles)
		if len(names) > 1 && logger != nil {
			logger.Warn("virtual host has routers with different sso profiles; unlabeled routes use the first",
				"virtual_host", vh.Name, "profiles", strings.Join(names, ","), "default", names[0])
		}
		for _, er := range vh.Routes {
			p := profileByRoute[er.Name]
			if p == "" {
				p = names[0]
			}
			assigned[er] = p
			used[p] = true
		}
	}
	if len(used) == 0 {
		return nil
	}

	profiles := make([]sso.Profile, 0, len(used))
	for _, name := range sortedStringKeys(used) {
		p, err := cfg.Lookup(name)
		if err != nil {
			// filterSSORoutes already rejected routers with unusable
			// profiles; this is unreachable.
			continue
		}
		profiles = append(profiles, p)
	}

	callbacks := addSSOCallbackRoutes(rc, profiles)

	for _, vh := range rc.VirtualHosts {
		for _, er := range vh.Routes {
			enabled := assigned[er]
			if cb, ok := callbacks[er]; ok {
				enabled = cb
			}
			if er.TypedPerFilterConfig == nil {
				er.TypedPerFilterConfig = map[string]*anypb.Any{}
			}
			for _, p := range profiles {
				if p.Name != enabled {
					er.TypedPerFilterConfig[oauth2FilterName(p.Name)] = mustAny(&routev3.FilterConfig{Disabled: true})
				}
			}
			if _, isCallback := callbacks[er]; enabled != "" && !isCallback {
				er.TypedPerFilterConfig[jwtAuthnFilterName] = mustAny(&jwtauthnv3.PerRouteConfig{
					RequirementSpecifier: &jwtauthnv3.PerRouteConfig_RequirementName{RequirementName: enabled},
				})
			} else {
				er.TypedPerFilterConfig[jwtAuthnFilterName] = mustAny(&jwtauthnv3.PerRouteConfig{
					RequirementSpecifier: &jwtauthnv3.PerRouteConfig_Disabled{Disabled: true},
				})
			}
		}
	}
	return profiles
}

// addSSOCallbackRoutes makes each profile's redirect_path and signout_path
// reachable on its redirect_uri_host. When a virtual host already serves
// that host, two exact-path routes are prepended to it; otherwise a minimal
// virtual host is synthesized whose only other route is a catch-all 404.
// On these routes only the owning profile's oauth2 filter is enabled (it
// intercepts the request, so the 404 direct response is never reached for
// the callback/signout paths) and jwt_authn is disabled. It returns the
// callback routes mapped to their profile.
//
// TLS: the HTTPS listeners present a single SDS certificate
// (CERT_SECRET_NAME, normally a wildcard), so a synthesized host needs no
// extra certificate wiring; it must simply be covered by that certificate.
func addSSOCallbackRoutes(rc *routev3.RouteConfiguration, profiles []sso.Profile) map[*routev3.Route]string {
	callbacks := map[*routev3.Route]string{}
	byHost := map[string][]sso.Profile{}
	for _, p := range profiles {
		host := strings.ToLower(p.RedirectHostname())
		byHost[host] = append(byHost[host], p)
	}
	hosts := sortedStringKeys(byHost)
	for _, host := range hosts {
		var cbRoutes []*routev3.Route
		for _, p := range byHost[host] {
			for _, path := range []string{p.RedirectPath, p.SignoutPath} {
				er := &routev3.Route{
					Match: &routev3.RouteMatch{PathSpecifier: &routev3.RouteMatch_Path{Path: path}},
					Action: &routev3.Route_DirectResponse{DirectResponse: &routev3.DirectResponseAction{
						Status: 404,
					}},
				}
				callbacks[er] = p.Name
				cbRoutes = append(cbRoutes, er)
			}
		}
		var existing *routev3.VirtualHost
		for _, vh := range rc.VirtualHosts {
			for _, d := range vh.Domains {
				if strings.EqualFold(d, host) {
					existing = vh
				}
			}
		}
		if existing != nil {
			existing.Routes = append(cbRoutes, existing.Routes...)
			continue
		}
		rc.VirtualHosts = append(rc.VirtualHosts, &routev3.VirtualHost{
			Name:    ssoCallbackVHPrefix + host,
			Domains: []string{host},
			Routes: append(cbRoutes, &routev3.Route{
				Match:  &routev3.RouteMatch{PathSpecifier: &routev3.RouteMatch_Prefix{Prefix: "/"}},
				Action: &routev3.Route_DirectResponse{DirectResponse: &routev3.DirectResponseAction{Status: 404}},
			}),
		})
	}
	return callbacks
}

// ssoHTTPFilters returns the oauth2 filters (one per profile, sorted) and
// the jwt_authn filter for a listener, or nil when the listener has no
// opted-in router.
func ssoHTTPFilters(profiles []sso.Profile) []*hcmv3.HttpFilter {
	if len(profiles) == 0 {
		return nil
	}
	filters := make([]*hcmv3.HttpFilter, 0, len(profiles)+1)
	jwt := &jwtauthnv3.JwtAuthentication{
		Providers:      map[string]*jwtauthnv3.JwtProvider{},
		RequirementMap: map[string]*jwtauthnv3.JwtRequirement{},
	}
	for _, p := range profiles {
		filters = append(filters, &hcmv3.HttpFilter{
			Name:       oauth2FilterName(p.Name),
			ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: mustAny(oauth2Config(p))},
		})
		jwt.Providers[p.Name] = &jwtauthnv3.JwtProvider{
			Issuer: p.Issuer,
			JwksSourceSpecifier: &jwtauthnv3.JwtProvider_RemoteJwks{RemoteJwks: &jwtauthnv3.RemoteJwks{
				HttpUri:       ssoHTTPURI(p.JWKS),
				CacheDuration: durationpb.New(p.JWKSCacheDuration),
			}},
			Forward:     true,
			FromHeaders: []*jwtauthnv3.JwtHeader{{Name: "Authorization", ValuePrefix: "Bearer "}},
		}
		jwt.RequirementMap[p.Name] = &jwtauthnv3.JwtRequirement{
			RequiresType: &jwtauthnv3.JwtRequirement_ProviderName{ProviderName: p.Name},
		}
	}
	filters = append(filters, &hcmv3.HttpFilter{
		Name:       jwtAuthnFilterName,
		ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: mustAny(jwt)},
	})
	return filters
}

// oauth2Config builds the oauth2 filter config for a profile. Envoy v1.37
// always uses PKCE (code_verifier cookie) for the authorization code flow,
// so public clients work without a client secret; the token_secret SDS file
// then only needs to hold a dummy generic secret, because OAuth2Credentials
// requires the field.
func oauth2Config(p sso.Profile) *oauth2v3.OAuth2 {
	suffix := "-" + p.Name
	return &oauth2v3.OAuth2{Config: &oauth2v3.OAuth2Config{
		TokenEndpoint:         ssoHTTPURI(p.TokenEndpoint),
		AuthorizationEndpoint: p.AuthorizationEndpoint,
		Credentials: &oauth2v3.OAuth2Credentials{
			ClientId:       p.ClientID,
			TokenSecret:    sdsFileSecret(p.TokenSecret),
			TokenFormation: &oauth2v3.OAuth2Credentials_HmacSecret{HmacSecret: sdsFileSecret(p.HMACSecret)},
			CookieDomain:   p.CookieDomain,
			// Per-profile cookie names: several profiles may share one
			// cookie_domain, and a cookie minted for one profile must not
			// be presented to (and fail HMAC validation in) another.
			CookieNames: &oauth2v3.OAuth2Credentials_CookieNames{
				BearerToken:  "BearerToken" + suffix,
				OauthHmac:    "OauthHMAC" + suffix,
				OauthExpires: "OauthExpires" + suffix,
				IdToken:      "IdToken" + suffix,
				RefreshToken: "RefreshToken" + suffix,
				OauthNonce:   "OauthNonce" + suffix,
				CodeVerifier: "CodeVerifier" + suffix,
			},
		},
		RedirectUri: p.RedirectURI(),
		RedirectPathMatcher: &matcherv3.PathMatcher{Rule: &matcherv3.PathMatcher_Path{Path: &matcherv3.StringMatcher{
			MatchPattern: &matcherv3.StringMatcher_Exact{Exact: p.RedirectPath},
		}}},
		SignoutPath: &matcherv3.PathMatcher{Rule: &matcherv3.PathMatcher_Path{Path: &matcherv3.StringMatcher{
			MatchPattern: &matcherv3.StringMatcher_Exact{Exact: p.SignoutPath},
		}}},
		// The access token is forwarded as Authorization: Bearer so the
		// following jwt_authn filter validates it on every request.
		ForwardBearerToken: true,
		PassThroughMatcher: []*routev3.HeaderMatcher{{
			Name: p.PassThrough.Header,
			HeaderMatchSpecifier: &routev3.HeaderMatcher_StringMatch{StringMatch: &matcherv3.StringMatcher{
				MatchPattern: &matcherv3.StringMatcher_Prefix{Prefix: p.PassThrough.Prefix},
			}},
		}},
		AuthScopes: append([]string(nil), p.AuthScopes...),
		StatPrefix: "sso_" + p.Name,
	}}
}

func ssoHTTPURI(e sso.Endpoint) *corev3.HttpUri {
	return &corev3.HttpUri{
		Uri:              e.URI,
		HttpUpstreamType: &corev3.HttpUri_Cluster{Cluster: e.Cluster},
		Timeout:          durationpb.New(e.Timeout),
	}
}

// sdsFileSecret references a secret Envoy reads from a local file (mounted
// into the Envoy container). The control plane never reads the file.
func sdsFileSecret(s sso.Secret) *tlsv3.SdsSecretConfig {
	return &tlsv3.SdsSecretConfig{
		Name: s.Name,
		SdsConfig: &corev3.ConfigSource{
			ResourceApiVersion: corev3.ApiVersion_V3,
			ConfigSourceSpecifier: &corev3.ConfigSource_PathConfigSource{
				PathConfigSource: &corev3.PathConfigSource{Path: s.SDSPath},
			},
		},
	}
}

// ssoClusters builds one upstream cluster per distinct IdP cluster name
// (sorted). sso.Parse already guarantees profiles sharing a cluster name
// agree on its https host:port. Each is STRICT_DNS (STATIC for a literal IP)
// with upstream TLS, SNI and SAN validation against the URI host.
func ssoClusters(profiles map[string]sso.Profile) []*clusterv3.Cluster {
	byName := map[string]sso.Endpoint{}
	for _, name := range sortedStringKeys(profiles) {
		p := profiles[name]
		for _, e := range []sso.Endpoint{p.TokenEndpoint, p.JWKS} {
			if _, seen := byName[e.Cluster]; !seen {
				byName[e.Cluster] = e
			}
		}
	}
	names := sortedStringKeys(byName)
	out := make([]*clusterv3.Cluster, 0, len(names))
	for _, name := range names {
		e := byName[name]
		out = append(out, buildAuthCluster(name, &authService{
			address:    e.Authority(),
			serverName: e.Host,
			useTLS:     true,
		}))
	}
	return out
}
