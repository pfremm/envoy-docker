# Envoy label reference

This control plane reads routing intent from two places: Docker container
labels and an optional static YAML file. This document is the reference for
both.

## Docker labels

A container is only considered for routing when it opts in:

| Label | Required | Meaning |
| --- | --- | --- |
| `envoy.enable` | yes | Set to `"true"` to include the container. Any other value (or absence) means the container is ignored entirely. |

Each router is a group of labels sharing the prefix
`envoy.http.routers.<name>.`, where `<name>` is an arbitrary router
identifier (e.g. `web`, `admin`, `api`). A single container may define any
number of routers.

### Per-router fields

| Label | Required | Meaning |
| --- | --- | --- |
| `envoy.http.routers.<name>.subdomain` | yes | The subdomain this router serves. The legacy (no-rule) virtual host is named `<subdomain>.<baseDomain>`. |
| `envoy.http.routers.<name>.port` | legacy only | Compatibility shorthand for an implicit per-router service with one backend port (`1-65535`). Required when `service` is omitted. |
| `envoy.http.routers.<name>.service` | named service only | Selects `envoy.http.services.<service>`. Service references are resolved after every label has been parsed, so definition order does not matter. |
| `envoy.http.routers.<name>.network` | no | The Docker network to resolve the container's IP on. When omitted, the `DOCKER_NETWORK` environment variable is used. Named service definitions use the network of a referencing router on that container, falling back to `DOCKER_NETWORK`. |
| `envoy.http.routers.<name>.rule` | no | A routing rule in the rule DSL (below). When absent the router is a legacy catch-all for its subdomain. |
| `envoy.http.routers.<name>.priority` | no | An explicit integer priority that overrides rule-specificity ordering. See [Precedence](#precedence). |
| `envoy.http.routers.<name>.middlewares` | no | Ordered comma/escape list of named HTTP middleware. See [HTTP middleware](#http-middleware). |
| `envoy.http.routers.<name>.timeout` | no | Total upstream request timeout as a Go duration (`30s`, `500ms`). `0s` disables Envoy's route timeout. |
| `envoy.http.routers.<name>.idletimeout` | no | Per-route stream idle timeout as a Go duration. `0s` disables it. Unset uses Envoy's 5m default; see [Protocol support](#protocol-support-http2-http3-websockets) for long-lived streams. |
| `envoy.http.routers.<name>.websocket` | no | `true`\|`false`. WebSocket upgrades are proxied by default; `false` makes Envoy reject `Upgrade: websocket` requests to this router with 403 (ordinary requests are unaffected). See [Protocol support](#protocol-support-http2-http3-websockets). |
| `envoy.http.routers.<name>.retries.attempts` | no | Positive total attempt count, including the initial request. Envoy receives `attempts-1` retries; `1` means no retry. |
| `envoy.http.routers.<name>.retries.pertrytimeout` | no | Positive timeout for each try. |
| `envoy.http.routers.<name>.retries.retryon` | no | Envoy retry conditions, for example `5xx,reset,connect-failure`. |
| `envoy.http.routers.<name>.entrypoints` | no | Comma/escape list of HTTP entrypoint names (daemon-configured, see [HTTP entrypoints](#http-entrypoints)). Omitted means the default HTTP/HTTPS entrypoints (legacy behavior). |
| `envoy.http.routers.<name>.accesslog` | no | `true`\|`false`. See [Observability hooks](#observability-hooks). |
| `envoy.http.routers.<name>.tracing` | no | `true`\|`false`. See [Observability hooks](#observability-hooks). |
| `envoy.http.routers.<name>.tracing.operationname` | no | Per-route span name. See [Observability hooks](#observability-hooks). |
| `envoy.http.routers.<name>.sso` | no | Name of an operator SSO profile (`SSO_CONFIG_PATH`). Puts the router's whole virtual host behind OAuth SSO. See [SSO](#sso-oauth2--jwt). |

Any other `envoy.http.routers.<name>.*` field is ignored.

### Validation and failure isolation

Validation happens per router, so one broken router never takes down the
rest of a container's routers:

- A router with an invalid `port` (non-integer or out of range) or an
  invalid `priority` (non-integer) is rejected **on its own**, with an
  actionable warning naming the field and the offending value. Sibling
  routers are unaffected.
- A router missing its `subdomain` or `port` is rejected on its own.
- A label that cannot be attributed to a single router (e.g. an empty
  router name) is a structural error and causes the whole container to be
  skipped.

### Example

```yaml
labels:
  envoy.enable: "true"
  # Legacy router: serves myapp.example.com, catch-all prefix.
  envoy.http.routers.web.subdomain: myapp
  envoy.http.routers.web.port: "8080"
  # Rule-based router on the same container, higher priority.
  envoy.http.routers.api.subdomain: myapp
  envoy.http.routers.api.port: "8081"
  envoy.http.routers.api.rule: "Host(myapp.example.com) && PathPrefix(/api) && Method(GET)"
  envoy.http.routers.api.priority: "10"
```

### Named HTTP services

Named services are modeled independently from routers. A router selects one
with `envoy.http.routers.<router>.service=<service>`. Definitions may appear on
a different container and are resolved only after all enabled containers have
been parsed. An unknown, invalid, or cyclic service rejects only routers that
reference it; sibling routers continue to be published.

A direct load-balancer service defines one or more indexed ports. Each port
creates an endpoint at the defining container's IP, and scaled containers with
the same compatible service definition contribute additional endpoints:

```yaml
labels:
  envoy.enable: "true"
  envoy.http.routers.web.subdomain: myapp
  envoy.http.routers.web.service: app-backend
  envoy.http.services.app-backend.loadbalancer.servers.0.port: "8080"
  envoy.http.services.app-backend.loadbalancer.servers.1.port: "8081"
```

`envoy.http.services.<service>.loadbalancer.port` is accepted as single-port
service sugar. The older router-level `.port` remains the compatibility path
for an implicit service when the router omits `.service`.

#### Active health checks, passive outliers, and protocol

| Label suffix after `envoy.http.services.<service>.` | Meaning |
| --- | --- |
| `loadbalancer.healthcheck.path` | HTTP health-check path; must begin with `/`. |
| `loadbalancer.healthcheck.interval` | Check interval (default `10s`). |
| `loadbalancer.healthcheck.timeout` | Check timeout (default `2s`). |
| `loadbalancer.healthcheck.unhealthythreshold` | Consecutive failures (default `3`). |
| `loadbalancer.healthcheck.healthythreshold` | Consecutive successes (default `1`). |
| `loadbalancer.outlier.consecutive5xx` | Consecutive 5xx responses before passive ejection. |
| `loadbalancer.outlier.interval` | Ejection analysis interval. |
| `loadbalancer.outlier.baseejectiontime` | Base ejection duration. |
| `loadbalancer.outlier.maxejectionpercent` | Maximum percentage ejected (`0-100`). |
| `loadbalancer.protocol` | `http1` (default), `http2`, `grpc`, or `https`. `grpc` enables HTTP/2; `https` enables upstream TLS with system-CA verification and automatic SNI/SAN validation against the request authority. |

Durations use Go syntax such as `250ms`, `10s`, or `2m`. Unknown policy
fields and malformed values invalidate only that named service. A service
cannot contain both direct servers and weighted children.

#### Sticky cookie

`loadbalancer.sticky.cookie.name` enables ring-hash affinity. Optional fields
are `secure`, `httponly`, `samesite` (`lax`, `strict`, or `none`), and `ttl`.
`SameSite=None` requires `secure=true`. Sticky cookies are rejected for `grpc`
services, where cookie affinity is not meaningful.

#### Weighted services

A weighted service composes direct services by index:

```yaml
labels:
  envoy.http.services.rollout.weighted.services.0.name: stable
  envoy.http.services.rollout.weighted.services.0.weight: "90"
  envoy.http.services.rollout.weighted.services.1.name: canary
  envoy.http.services.rollout.weighted.services.1.weight: "10"
```

Every indexed entry requires both `.name` and a positive `.weight`. Nested
weighted services are flattened deterministically; duplicate leaf weights are
combined. Weighted services cannot define leaf-only protocol, health, outlier,
or sticky policy, and cannot include a sticky child. Unknown children,
overflow, and direct or indirect cycles invalidate the referencing weighted
service and only its routers.

### HTTP middleware

A router references a named, ordered chain with:

```yaml
envoy.http.routers.web.middlewares: strip-api,internal-prefix,security-headers,cors
```

Definitions use `envoy.http.middlewares.<name>.<type>.*`. A name must define
exactly one type. References are resolved after every enabled container has
been parsed, so definitions may be on another container and label order does
not matter. Unknown, invalid, conflicting, or multi-type definitions reject
only routers that reference them. Middleware execution follows the router
list from left to right; definitions and emitted header keys are sorted where
map iteration would otherwise make xDS nondeterministic. A chain can contain
at most one redirect, and it must be last because redirect is a terminal route
action. `replacepathregex` is compiled through Envoy's native RE2 rewrite; to
avoid silently changing regex semantics, a chain containing it cannot contain
another path rewrite or redirect (headers and CORS may still accompany it).
When CORS is composed with other middleware it must be last: request filters
run in listed order and response filters unwind in reverse order, matching a
standard middleware stack. Unsupported orderings reject only that router.

| Type | Fields |
| --- | --- |
| `redirectscheme` | `scheme` (required), `port` (`1-65535`, optional), `permanent` (default `false`; 302 when false, 301 when true) |
| `redirectregex` | `regex`, `replacement` (required), `permanent` (default `false`) |
| `stripprefix` | `prefixes` (required list) |
| `addprefix` | `prefix` (required path beginning with `/`) |
| `replacepath` | `path` (required path beginning with `/`) |
| `replacepathregex` | `regex`, `replacement` (required) |
| `headers` | `request.<header>`, `response.<header>`, `removerequest`, `removeresponse` |
| `cors` | `alloworigins` (required list), `allowmethods`, `allowheaders`, `exposeheaders`, `maxage`, `allowcredentials` |
| `basicauth` | `users` (required `user:htpasswd-hash` list), `realm`, `headerfield`, `removeheader` |
| `forwardauth` | `address` (required HTTP(S) URL or host/port), `trustforwardheader`, `authrequestheaders`, `authresponseheaders`, `authresponseheaderregex`, `tls.insecure`, `tls.servername` |
| `ipallowlist` | `sourcerange` (required CIDR/IP list), `ipstrategy.depth`, `ipstrategy.excludedips` |
| `ipdenylist` | `sourcerange` (required CIDR/IP list), `ipstrategy.depth`, `ipstrategy.excludedips` |
| `ratelimit` | `average`, `burst`, `period` (all required; `period` must be at least `50ms`) |
| `compress` | `minresponsebytes`, `contenttypes` (list), `excludedcontenttypes` (list), `disableonetagheader` |
| `retry` | `attempts` (required positive integer), `pertrytimeout` (required duration), `retryon` (required Envoy retry conditions) |
| `circuitbreaker` | `maxconnections`, `maxpendingrequests`, `maxrequests`, `maxretries` (at least one required) |
| `buffering` | `maxrequestbytes`, `maxresponsebytes` (at least one required); `retryexpression` is not supported |
| `errors` | `status` (required list of codes/ranges like `404,500-599`), `service` (required), `query` (path, optional) |
| `grpcweb` | `enabled` (must be `true`; omit the middleware if you don't want gRPC-Web) |

#### Resilience and protocol middleware

**Compression** installs Envoy's native compressor filter listener-wide when
at least one route references a `compress` middleware: gzip is always
installed, and brotli is installed alongside it when
`COMPRESSION_BROTLI_ENABLED` is not explicitly set to false (default true;
the go-control-plane API this control plane is built against always carries
the brotli compressor proto, but the actual deployed Envoy binary must also
have been built with the brotli extension — the standard `envoyproxy/envoy`
image does, minimal/alpine variants may not, hence the override). Because
Envoy's compressor filter is listener-scoped, every route referencing
`compress` must configure identical settings; conflicting definitions are
rejected rather than one silently winning. `minresponsebytes`,
`contenttypes`, and `disableonetagheader` are wired to the filter's
response-direction config. `excludedcontenttypes` has no Envoy equivalent
(the compressor filter only exposes an allow-list) and is rejected at model
validation.

**gRPC-Web** installs Envoy's native `grpc_web` filter listener-wide when at
least one route references a `grpcweb` middleware, positioned before CORS in
the filter chain (gRPC-Web must translate the browser request before CORS
preflight logic runs). A route with `grpcweb` must select a named HTTP
service configured with `loadbalancer.protocol=grpc` or `http2`; a legacy
port-only route or an http1/https-protocol service is rejected, since the
grpc_web filter's framing translation only round-trips over an HTTP/2
upstream.

**Circuit breakers** are cluster-scoped in Envoy but this middleware is
per-route, so the xDS layer derives deterministic cluster variants when
routes sharing one base cluster (a legacy route's own cluster, or a single
non-weighted named service) request different policies, and deduplicates
identical policies onto one shared variant. When every route sharing a base
cluster requests the identical policy, it is applied directly to the base
cluster with no variant. Variant cluster names are a deterministic
`<base>~cb-c<maxconnections>-p<maxpending>-r<maxrequests>-t<maxretries>`
suffix, so identical policies always produce identical cluster names.
`circuitbreaker` middleware cannot be combined with a route selecting a
weighted service, since a weighted service has no single base cluster to
vary; this is rejected at snapshot build time.

**Error pages** install Envoy's native `custom_response` filter
listener-wide when at least one route references an `errors` middleware,
with the actual matching/redirect behavior entirely in a per-route override:
a matcher over the configured status codes/ranges (using Envoy's status
class matcher for a `NxxN` pattern spanning a full class, exact-code
matchers otherwise) redirects internally (via `redirect_policy`) to a
synthetic virtual host for the named `errors.service`. `errors.service` must
resolve to a named HTTP service (`envoy.http.services.<name>.*`); a service
that is itself served by a route carrying its own `errors` middleware is
rejected outright (no recursive error handling).

**Retry** policies are per-route and fully implemented via
`RouteAction.RetryPolicy`. `attempts` is the total number of tries, so Envoy's
`num_retries` is `attempts-1`; middleware retry overrides router-level retry
defaults when present.

**Buffering** is per-route and implemented for `maxrequestbytes` only; Envoy's
buffer filter does not expose `maxresponsebytes`, `memrequestbytes`,
`memresponsebytes`, or retry-expression at the per-route level. Unsupported
settings are rejected at model validation rather than silently ignored.

Regexes are validated when labels are parsed. Invalid expressions never reach
xDS. Replacements accept Go/Traefik capture references (`$1` or `${1}`), which
are translated to Envoy's RE2 substitution form; `$$` emits a literal dollar.
In Docker Compose YAML, double the dollar again (`$$1` in the Compose source)
so interpolation delivers `$1` to the container label. Header names are
case-insensitive and canonicalized to lowercase.
Pseudo-headers such as `:authority`, and syntactically invalid HTTP field
names, are rejected rather than mutated.

#### List syntax

List-valued fields and the router `middlewares` chain accept comma-separated
values. A literal comma is written `\,`; a literal backslash is written `\\`.
Whitespace surrounding each item is trimmed. Empty items, unsupported escapes,
and a dangling backslash are errors. For example:

```yaml
envoy.http.middlewares.strip.stripprefix.prefixes: '/api\,/literal,/v1'
```

is the two-item list `/api,/literal` and `/v1`.

As an alternative, middleware list fields accept numeric indexed labels. The
indices are sorted numerically and need not be contiguous:

```yaml
envoy.http.middlewares.site-cors.cors.alloworigins.2: https://app.example.com
envoy.http.middlewares.site-cors.cors.alloworigins.10: https://admin.example.com
envoy.http.middlewares.site-cors.cors.allowmethods: GET,POST,OPTIONS
```

Do not combine a base list label and indexed labels for the same field.
Indexed syntax is accepted for every list field, including `prefixes`,
header/CORS lists, `users`, auth header lists, `sourcerange`, and
`ipstrategy.excludedips`. Docker
label maps cannot repeat an identical key, so indexing is the repeated-value
form.

#### Security middleware

Basic auth credentials are emitted only into Envoy's sensitive xDS data source
and are redacted from control-plane diagnostics. The pinned Envoy native
`basic_auth` filter currently accepts only Apache htpasswd `{SHA}` entries, so
other algorithms are rejected during model validation before xDS publication.
In Compose interpolation, any literal dollar in a future/alternate Envoy build's
supported hash must be doubled (`$2y$...` becomes `$$2y$$...` in YAML). `headerfield`
forwards the authenticated username to that upstream header. `removeheader`
removes `Authorization` only after authentication succeeds. A custom `realm`
is applied to 401 responses by a pre-auth response-only Lua filter.

Forward auth is fail-closed: an auth-server denial, error, or timeout does not
reach the upstream. Checks have a fixed two-second upper bound and use an
explicit static auth cluster. `authresponseheaders` and its regex variant copy
successful auth response headers into the upstream request. Enabling
`trustforwardheader` deliberately forwards existing `X-Forwarded-*` identity
headers to the auth service; only do this behind a proxy that overwrites or
sanitizes those headers. An `http://` address selects plaintext. HTTPS verifies
the system CA and upstream identity by default; `tls.insecure=true` keeps TLS
but disables certificate verification and must not be used across an untrusted
network. `tls.servername` overrides the TLS SNI name. A path in the auth
address is emitted as Envoy's authorization path prefix; query strings and
fragments are rejected because Envoy HTTP ext_authz cannot represent them
without silently changing the request. Envoy's native `basic_auth` cannot be
disabled per route, so when BasicAuth is used every published route must opt
into it. ForwardAuth can be selective: routes without it receive an explicit
disabled override rather than inheriting the listener's default auth service.
Mixed BasicAuth coverage is rejected rather than accidentally changing access.

IP allow/deny rules use only Envoy's direct downstream peer by default, so a
client-supplied `X-Forwarded-For` cannot bypass them. `ipstrategy.depth=N`
explicitly trusts N right-most proxy hops. `ipstrategy.excludedips` instead
configures those CIDRs as trusted proxy hops; depth and excluded IPs are
mutually exclusive. Both modes trust forwarding metadata and are spoofable if
the direct peer is not a controlled proxy. Because original-IP detection is an
HTTP-listener property, routes that opt into XFF must agree on one strategy;
conflicting strategies reject the snapshot rather than silently weakening it.

Rate limiting uses Envoy's native local token bucket. `burst` is the bucket
capacity; `average` tokens are refilled each `period`. Buckets are per route
and local to one Envoy proxy process. They are not distributed/global limits,
so N replicas permit roughly N times the configured aggregate rate.

Security filters have unavoidable Envoy filter-phase ordering: local rate
limit, realm response hook (when needed), basic auth, and IP RBAC run first;
request mutation follows, then forward auth sees the final path and headers,
BasicAuth credential removal runs after all auth checks, and CORS/routing
finish the chain. Order is preserved within the mutation family and response
mutations unwind in reverse. Security types cannot be arbitrarily interleaved
per route because Envoy installs HTTP filter implementations listener-wide;
the fixed phase order is deterministic and documented rather than inferred
from map iteration.

#### Complete mutation example

```yaml
labels:
  envoy.enable: "true"
  envoy.http.routers.web.subdomain: myapp
  envoy.http.routers.web.port: "8080"
  envoy.http.routers.web.middlewares: strip-api,add-internal,response-headers,site-cors
  envoy.http.middlewares.strip-api.stripprefix.prefixes: /api,/v1
  envoy.http.middlewares.add-internal.addprefix.prefix: /internal
  envoy.http.middlewares.response-headers.headers.request.X-Forwarded-App: myapp
  envoy.http.middlewares.response-headers.headers.response.X-Content-Type-Options: nosniff
  envoy.http.middlewares.response-headers.headers.removeresponse: Server,X-Powered-By
  envoy.http.middlewares.site-cors.cors.alloworigins.0: https://app.example.com
  envoy.http.middlewares.site-cors.cors.allowmethods: GET,POST,OPTIONS
  envoy.http.middlewares.site-cors.cors.allowheaders: Content-Type,Authorization
  envoy.http.middlewares.site-cors.cors.exposeheaders: X-Request-ID
  envoy.http.middlewares.site-cors.cors.maxage: "600"
  envoy.http.middlewares.site-cors.cors.allowcredentials: "true"
```

Routers without a `middlewares` label retain their existing route action and
request/response behavior.

## The rule DSL

A rule is a boolean expression over matcher atoms.

### Grammar

```
expr    := term ( '||' term )*
term    := factor ( '&&' factor )*
factor  := '!' factor | '(' expr ')' | matcher
matcher := Host | Path | PathPrefix | Headers | Method | Query | ClientIP
```

- `&&` binds tighter than `||`.
- `!` is unary negation.
- Parentheses group sub-expressions.
- Multiple values inside a single matcher are ORed together.

### Matchers

| Matcher | Form | Meaning |
| --- | --- | --- |
| `Host` | `Host(a.com, b.com)` | The request `Host` header equals one of the listed hosts. |
| `Path` | `Path(/api, /v1)` | The request path equals one of the listed paths. |
| `PathPrefix` | `PathPrefix(/api, /admin)` | The request path starts with one of the listed prefixes. |
| `Headers` | `Headers(name, value, ...)` | Pairs of header name/value; each listed pair must match. |
| `Method` | `Method(GET, POST)` | The HTTP method equals one of the listed methods. |
| `Query` | `Query(name)` or `Query(name, value)` | Presence of a query parameter, or exact match of a parameter value. |
| `ClientIP` | `ClientIP(10.0.0.0/8, 192.168.1.1)` | The client source IP is in one of the listed CIDRs. |

### Translatability

`ClientIP` and negation on non-header matchers cannot be expressed as an
Envoy route match. When a rule uses them, that specific route is **skipped
with an actionable warning** (naming the matcher and the rule); the rest of
the host's routes are unaffected.

## Precedence

Within one virtual host, Envoy evaluates routes top-to-bottom and the first
match wins. The control plane orders routes with a deterministic precedence
(`model.SortByPrecedence`):

1. **Explicit priority** — a router with a `priority` label sorts before
   one without, and a higher value sorts before a lower one.
2. **Rule specificity** — a longer (more specific) rule expression sorts
   before a shorter one, so a narrow rule is not shadowed by a broad
   `PathPrefix(/)`.
3. **Router name** — a stable alphabetical tie-breaker.

### Several routers on one subdomain

Distinct routers (different router label names) may share one subdomain.
Every one of them is preserved through discovery and reaches the precedence
evaluation above — the control plane never discards a router before its rule
has been considered. They are emitted into a **single** virtual host for that
host (one domain must be claimed by exactly one virtual host; Envoy rejects a
route configuration with duplicate domains), ordered by the precedence rules,
so a narrow `PathPrefix(/admin)` router is evaluated before a broad
`Host(...)` router on the same subdomain and neither shadows the other.

Each such router gets its own Envoy cluster and endpoint assignment, so it
keeps its own backend: the subdomain's highest-precedence router keeps the
legacy cluster name (the subdomain itself) and every other router sharing
that subdomain gets `<subdomain>#<router>`. Single-router subdomains — the
common case — are completely unchanged.

Two containers advertising the **same router name** on the same subdomain are
still replicas of one router and merge into a multi-endpoint route (round
robin), matching Traefik's behavior for a scaled compose service. Only a
genuinely incompatible redefinition of that one router (same name, different
rule/service/policy) resolves by precedence, since there is no second router
to preserve.

A rule-based route is served by the virtual host of its rule's first
`Host(...)` atom. A legacy (no-rule) route keeps its own
`<subdomain>.<baseDomain>` virtual host **in every configuration**, so legacy
subdomains stay isolated from each other even when rule-based routes exist.
When any rule-based route exists, legacy routes are additionally carried in a
catch-all virtual host with domain `*`; each catch-all copy is constrained to
its own `<subdomain>.<baseDomain>` authority, so a request that matches no
rule-based host still reaches *its own* legacy route, while a request for an
entirely unknown host matches nothing (404) instead of being routed to an
arbitrary legacy backend. A legacy route whose host is also claimed by a
rule-based virtual host joins that virtual host and is ordered by the shared
precedence rules above. With no rule-based routes at all, the configuration
is exactly the legacy shape (one virtual host per subdomain, no catch-all).

## Static YAML config

For non-Docker backends, routes can be declared in a YAML file (path from
the `STATIC_CONFIG` environment variable; empty means none). On a
subdomain collision, a static route wins over a Docker-discovered one.

```yaml
routers:
  - subdomain: external
    port: 443
    addresses:
      - 203.0.113.10
      - 203.0.113.11
```

Each entry requires a `subdomain`, a `port`, and at least one `addresses`
entry. Duplicate subdomains within the file are an error.

## HTTP entrypoints

`envoy.http.routers.<name>.entrypoints` accepts a comma/escape-separated list
of HTTP entrypoint names. Like TCP entrypoints, an HTTP entrypoint's name and
port are pure daemon/operator configuration (`HTTP_ENTRYPOINTS=name=port,...`
and, optionally, `HTTP_DEFAULT_ENTRYPOINT=name` in the control plane's own
environment) — a container label can only *select* among entrypoints the
operator already configured, never bind a new host socket of its own. This is
the same trust boundary as TCP: untrusted container labels never get to open
a listener that wasn't already provisioned by whoever runs the control plane.

A router with no `.entrypoints` label is served on the ordered list in
`HTTP_DEFAULT_ENTRYPOINTS` when set (comma-separated, for example
`public,internal`), or the compatibility alias `HTTP_DEFAULT_ENTRYPOINT`,
 or otherwise on the always-present legacy default entrypoint. Every name in
that list must already exist in `HTTP_ENTRYPOINTS`; labels cannot create
listeners. The list is intentional: an omitted router entrypoint is published
on every configured default, not just the first one.
That default entrypoint keeps the legacy resource names (`http_listener`,
`https_listener`, `https_routes`) so upgrading the control plane binary never
renames or disrupts a router that never asked for a named entrypoint. Each
extra configured entrypoint gets its own TLS listener (`https_listener__<ep>`)
on its configured port, serving its own RDS route configuration
(`https_routes__<ep>`); a router naming multiple entrypoints is published,
unmodified, on every one of them. A router naming an entrypoint the daemon
did not configure is skipped on that entrypoint with a warning naming the
valid entrypoints (it still publishes on any valid entrypoints it also
names), exactly like the TCP case: labels are untrusted input, so one bad
`.entrypoints` value never blocks config updates for other containers. The
default `https_routes` route configuration is always published — even with
zero routes — because the default `https_listener` always references it.

Unlike TCP entrypoints (which carry either a raw or TLS-passthrough chain and
never terminate TLS), every HTTP entrypoint listener — default or named — is
a TLS-terminating listener sharing the same certificate/SDS configuration;
there is currently no way to publish a router on a plain-HTTP-only named
entrypoint (the always-present `HTTP_PORT` listener still exists solely to
redirect to HTTPS, exactly as before).

```yaml
labels:
  envoy.enable: "true"
  # Legacy router: served on the default HTTP/HTTPS entrypoints, unchanged.
  envoy.http.routers.web.subdomain: myapp
  envoy.http.routers.web.port: "8080"

  # Served only on a dedicated "admin" entrypoint, e.g. bound to a private
  # network interface by the operator's HTTP_ENTRYPOINTS configuration.
  envoy.http.routers.admin.subdomain: admin
  envoy.http.routers.admin.port: "9090"
  envoy.http.routers.admin.entrypoints: admin
```

With `HTTP_ENTRYPOINTS=admin=8444` in the control plane's environment: `web`
keeps serving `myapp.example.com` on the default `HTTP_PORT`/`HTTPS_PORT`
pair exactly as it always did, and `admin` additionally gets its own TLS
listener on `8444` serving only `admin.example.com`.

## SSO (OAuth2 + JWT)

Routers can opt in to single sign-on with
`envoy.http.routers.<name>.sso: <profile>`. Profiles are **operator**
configuration in the YAML file named by the `SSO_CONFIG_PATH` environment
variable (unset = SSO disabled); a label can only select a profile, never
define one. Unlabeled routers stay fully public.

```yaml
# /etc/envoy-control-plane/sso.yaml
sso_profiles:
  nas:
    redirect_uri_host: sso.nas2.pfrem.me      # callback = https://<host><redirect_path>
    redirect_path: /oauth2/callback           # optional (default shown)
    signout_path: /oauth2/signout             # optional (default shown)
    cookie_domain: nas2.pfrem.me              # must contain redirect_uri_host
    issuer: https://auth.example.com/application/o/nas/
    authorization_endpoint: https://auth.example.com/application/o/authorize/
    token_endpoint: {cluster: sso_idp, uri: https://auth.example.com/application/o/token/, timeout: 5s}
    jwks: {cluster: sso_idp, uri: https://auth.example.com/application/o/nas/jwks/}  # cache_duration default 300s
    credentials:
      client_id: envoy-nas
    hmac_secret:  {name: sso-nas-hmac,  sds_path: /etc/envoy/secrets/sso-nas-hmac.yaml}
    token_secret: {name: sso-nas-token, sds_path: /etc/envoy/secrets/sso-nas-token.yaml}
    auth_scopes: [openid, email]              # optional (default shown)
    pass_through_matcher: {header: authorization, prefix: "Bearer "}  # optional (default shown)
```

- **Envoy filters.** Each HTTPS listener serving at least one opted-in
  router gets one `envoy.filters.http.oauth2.<profile>` filter per profile
  it uses, then one `envoy.filters.http.jwt_authn` filter, at the front of
  its filter chain. Every route on that listener carries explicit per-route
  overrides: the oauth2 filters of other profiles are disabled, and
  jwt_authn either requires the route's profile or is disabled. Listeners
  without opted-in routers are unchanged. The oauth2 filter forwards the
  access token as `Authorization: Bearer`, which jwt_authn validates against
  the profile's issuer/JWKS, so the IdP must issue **JWT** access tokens.
  Requests already carrying a matching `pass_through_matcher` header (by
  default a Bearer token, i.e. machine clients) skip the browser login and
  are validated by jwt_authn directly.
- **Whole virtual host.** If any router on a virtual host opts in, every
  route on that host is protected (a public router cannot expose part of an
  SSO subdomain). There is no per-path SSO.
- **Callback host.** `redirect_path` and `signout_path` are made reachable on
  `redirect_uri_host` (a minimal virtual host returning 404 for anything
  else is synthesized if no router serves that host). The host must be
  covered by the listener certificate (`CERT_SECRET_NAME`, normally a
  wildcard) and must reach an entrypoint that serves at least one router of
  the profile. `signout_path` also works on every host protected by the
  profile; Envoy then redirects to that host's `/` (on the synthesized
  callback host that lands on its 404), so link sign-out from the
  protected hosts.
- **Secrets** are file-based SDS: the control plane only references
  `sds_path` (an absolute path **inside the Envoy container**) and never reads
  it. `token_secret` holds the client secret for a confidential client;
  Envoy requires it even for a public (PKCE) client, in which case its file
  may contain a dummy generic secret. `hmac_secret` signs the session cookies.
- **IdP clusters.** The `cluster` names in `token_endpoint`/`jwks` are
  generated by the control plane (STRICT_DNS to the URI host, port default
  443, upstream TLS with SNI and certificate validation) for each profile
  used by at least one accepted router. Profiles may share a cluster name
  only if they point at the same host:port; a name that collides with any
  other generated cluster fails the snapshot like other cluster collisions.
- **Failure isolation.** Each profile is validated on its own (absolute
  `https://` URLs, absolute `sds_path`, durations, required fields, unknown
  keys rejected); an invalid profile only rejects the routers referencing
  it. A router naming an unknown or invalid profile, or any profile while
  `SSO_CONFIG_PATH` is unset or unparseable, is skipped with a warning (it is
  not served unprotected). The file is re-read on every snapshot build
  (docker events and every `RESYNC_INTERVAL`), so edits apply without a
  restart.

All generated HTTPS route configurations also add
`Strict-Transport-Security: max-age=31536000; includeSubDomains` to responses
that do not already carry the header (never on the plain-HTTP redirect
listener). Listeners with SSO add it through a leading `header_mutation`
filter as well, because the oauth2 filter's own redirects and errors bypass
the route configuration's response headers.

### Profile field reference

The file has exactly one top-level key, `sso_profiles`, mapping profile names
to profiles. An unknown top-level key or a file that is not valid YAML is a
file-level error: every sso-labeled router is then rejected. Profile names
are 1-63 characters of letters, digits, `-` or `_`, starting with a letter or
digit. Unknown keys inside a profile (including an inline `client_secret`,
which is deliberately unsupported) invalidate that profile only.

| Field | Required | Default | Meaning |
| --- | --- | --- | --- |
| `redirect_uri_host` | yes | | Fixed callback host, optionally with `:port` (HTTPS on a non-standard port). A bare host name: no scheme, path, query or userinfo. |
| `redirect_path` | no | `/oauth2/callback` | Callback path. Absolute (starts with `/`), no `?`, `#` or whitespace. Must differ from `signout_path`. |
| `signout_path` | no | `/oauth2/signout` | Sign-out path, same constraints as `redirect_path`. |
| `cookie_domain` | yes | | Session cookie domain. A leading `.` is stripped. `redirect_uri_host` (ignoring its port) must equal it or be a subdomain of it. |
| `issuer` | yes | | Must equal the `iss` claim of the IdP's tokens exactly. Compared as an opaque string, so a trailing `/` matters. |
| `authorization_endpoint` | yes | | Absolute `https://` URL with no userinfo. The browser is redirected here. |
| `token_endpoint` | yes | | `{cluster, uri, timeout}`. Envoy calls this to exchange the authorization code. `cache_duration` is rejected here. |
| `token_endpoint.cluster` | yes | | Name of the generated IdP cluster: 1-128 characters of letters, digits, `_`, `.` or `-`, starting with a letter or digit. |
| `token_endpoint.uri` | yes | | Absolute `https://` URL, no userinfo. Port defaults to 443. |
| `token_endpoint.timeout` | no | `5s` | Positive Go duration. |
| `jwks` | yes | | `{cluster, uri, timeout, cache_duration}`. Where jwt_authn fetches the signing keys. `cluster`, `uri` and `timeout` follow the same rules as in `token_endpoint`. `token_endpoint` and `jwks` may share a cluster name only if both URIs have the same host:port. |
| `jwks.cache_duration` | no | `300s` | Positive Go duration: how long the fetched JWKS is cached. |
| `credentials.client_id` | yes | | OAuth client ID. |
| `hmac_secret.name` | yes | | SDS secret name. Must match the `name` inside the secret file and differ from `token_secret.name`. |
| `hmac_secret.sds_path` | yes | | Absolute path of the SDS file **inside the Envoy container**. |
| `token_secret.name` | yes | | SDS secret name of the client secret (or a dummy value for a public client). |
| `token_secret.sds_path` | yes | | Absolute path, as for `hmac_secret.sds_path`. |
| `auth_scopes` | no | `[openid, email]` | Requested scopes. If present it must be non-empty, and no entry may be empty or contain whitespace. |
| `pass_through_matcher.header` | if block present | `authorization` | Header whose presence (with `prefix`) skips the browser flow. Must be a valid HTTP header name. Matched case-insensitively. |
| `pass_through_matcher.prefix` | if block present | `Bearer ` | Required, non-empty value prefix. |

Profiles are also checked against each other, in sorted name order. When two
profiles conflict, the later one is invalidated. A cluster name must point at
one host:port across all profiles. A secret name must map to one `sds_path`.
Profiles sharing a `redirect_uri_host` need distinct `redirect_path` and
`signout_path` values.

### Machine clients (Bearer pass-through)

A request that matches the profile's `pass_through_matcher` (by default any
`Authorization` header starting with `Bearer `) skips the oauth2 filter's
browser redirect and goes straight to jwt_authn. jwt_authn then validates the
token against the profile:

- the signature must verify against the keys from the profile's `jwks`;
- `iss` must equal `issuer`;
- `exp`/`nbf` are enforced (Envoy's jwt_authn default).

**`aud` is not checked.** The generated provider configures no
`audiences`, so any unexpired JWT signed by the IdP's JWKS with a matching
`iss` is accepted, whichever client it was issued to. If your IdP shares one
issuer across applications, give each protected app its own issuer (for
example Authentik's per-application issuer URLs), or check the audience in the
backend. The validated token is forwarded upstream unchanged.

A missing, malformed, expired or wrongly signed token is answered by jwt_authn
with **401** (no redirect to the IdP). Tokens must be JWTs from the same
issuer. Opaque access tokens cannot be validated.

jwt_authn only reads the token from `Authorization: Bearer <jwt>`. If you
change `pass_through_matcher` to a different header, matching requests still
skip the browser flow, but they get a 401 unless they also carry an
`Authorization: Bearer` JWT.

```sh
# Obtain an access token from the IdP however your client does (e.g. client
# credentials), then:
TOKEN=$(curl -s https://auth.example.com/application/o/token/ \
  -d grant_type=client_credentials -d client_id=my-script -d client_secret=... \
  | jq -r .access_token)
curl -H "Authorization: Bearer $TOKEN" https://files.nas2.pfrem.me/api/status
# no token / bad token -> 401 from Envoy, never a 302 to the IdP
```

### Callback host pattern

Use one dedicated callback host per profile (or shared by profiles), for
example `sso.<BASE_DOMAIN>`, rather than one of the protected hosts:

1. Set `redirect_uri_host: sso.<BASE_DOMAIN>` (add `:port` if the HTTPS
   entrypoint is not on 443).
2. Register exactly `https://<redirect_uri_host><redirect_path>` (with the
   defaults, `https://sso.<BASE_DOMAIN>/oauth2/callback`) as the redirect URI
   at the IdP. Envoy sends this fixed URI for every protected host, so only
   one redirect URI is needed however many hosts use the profile.
3. Set `cookie_domain` to a parent domain covering both the callback host and
   every protected host, typically `<BASE_DOMAIN>`. The session cookies are
   set while serving the callback host, and browsers must send them to the
   protected hosts. A `redirect_uri_host` outside `cookie_domain` invalidates
   the profile. A protected host outside it gets stuck in a login loop.
4. Make sure the listener certificate (`CERT_SECRET_NAME`) covers the callback
   host. A `*.<BASE_DOMAIN>` wildcard covers `sso.<BASE_DOMAIN>`.
5. No container needs to serve the callback host. If no router does, the
   control plane synthesizes a virtual host (`sso_callback__<host>`) holding
   only the callback/sign-out routes plus a catch-all 404. It is added to
   every listener that serves a router of the profile. If a router does serve
   that host, the two exact-path routes are prepended to its virtual host.

### SDS secret files

`hmac_secret` and `token_secret` point at Envoy file-based SDS files that
must be mounted into the **Envoy** container (the control plane never reads
them). Each file holds one `Secret` resource whose `name` matches the
profile's secret `name`:

```yaml
# /etc/envoy/secrets/sso-nas-hmac.yaml
resources:
  - "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret
    name: sso-nas-hmac
    generic_secret:
      secret:
        inline_string: "REPLACE_WITH_openssl_rand_-base64_32"
```

```yaml
# /etc/envoy/secrets/sso-nas-token.yaml
resources:
  - "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret
    name: sso-nas-token
    generic_secret:
      secret:
        inline_string: "the-client-secret-from-the-idp"
```

- The HMAC secret signs the session cookies. Make it random and keep it
  private, e.g. `openssl rand -base64 32`. Changing it invalidates existing
  sessions.
- For a **public** (PKCE-only) client, `token_secret` is still required by
  Envoy's oauth2 filter. Put any dummy string in its file.
- The IdP must issue **JWT** access tokens (jwt_authn validates the forwarded
  access token, not the ID token). Opaque access tokens fail with 401 after
  login.
- The files must be readable by the Envoy process. Envoy watches the path;
  replace the file atomically (write a temp file, then `mv`) when rotating.

## Protocol support (HTTP/2, HTTP/3, WebSockets)

What the generated listeners speak today, from `buildHTTPSListener` and
`buildHTTPListener` (`internal/xds/snapshot.go`):

| Protocol | Status |
| --- | --- |
| Downstream HTTP/1.1 | Supported. Used by clients that do not offer `h2`, and for every WebSocket handshake. |
| Downstream HTTP/2 | **Supported.** The HTTPS listeners' TLS context advertises ALPN `h2,http/1.1`, so browsers and other clients that offer `h2` get HTTP/2, and the rest get HTTP/1.1. This is safe with HTTP/2 connection coalescing: each HTTPS listener has one filter chain and one connection manager, and routes every request by `:authority` through one route config. A connection a browser reuses for another host on the certificate still reaches that host's routes, SSO and middleware. Native gRPC from outside works for routers whose service uses `loadbalancer.protocol: grpc` (or `http2`); verified with a grpc-go client on Envoy 1.37. The upstream protocol is set per service, independent of the client's. |
| Upstream HTTP/2 / gRPC | Supported per named service with `envoy.http.services.<svc>.loadbalancer.protocol: http2` or `grpc`, which enables HTTP/2 on that service's cluster. Legacy port-only routers always use HTTP/1.1 upstream. This is independent of the downstream protocol. |
| HTTP/3 / QUIC | **Not supported.** No UDP/QUIC listeners are generated and no `alt-svc` header is sent, so clients never attempt HTTP/3. |
| WebSockets | **Supported, on by default** (as in Traefik). Every routed HTTPS connection manager (the default entrypoint and each named entrypoint) sets `upgrade_configs: [{upgrade_type: websocket}]`, so an HTTP/1.1 `Upgrade: websocket` request gets the upstream's `101 Switching Protocols` and frames flow both ways. The plain-HTTP listener only redirects to HTTPS and does not proxy upgrades. Opt a router out with `envoy.http.routers.<r>.websocket: "false"`: its routes set a route-level `upgrade_configs: [{upgrade_type: websocket, enabled: false}]` and Envoy answers upgrades with **403**. Once upgraded, the route `timeout` (default 15s) no longer applies, but the stream idle timeout does (see below). WebSockets over HTTP/2 (RFC 8441 extended CONNECT) are not enabled. Envoy does not advertise `SETTINGS_ENABLE_CONNECT_PROTOCOL`, so browsers open a separate HTTP/1.1 connection for each WebSocket even when the page itself loaded over HTTP/2. See the notes below for SSO and middleware. |

**Long-lived streams and `idletimeout`.** The connection managers do not set
`stream_idle_timeout`, so Envoy's default of **5 minutes** applies: a stream
with no request or response activity for 5 minutes is closed (408 if no
response headers were sent yet, otherwise a reset). For routers serving
long-lived, mostly quiet responses (Server-Sent Events, long polling, large
slow downloads, and WebSockets), set
`envoy.http.routers.<r>.idletimeout: "0s"` to disable the route's idle timeout,
or set a value longer than the longest expected silence. The route `timeout`
(Envoy default 15s) is a separate limit: it runs from the end of the request
until the response is complete, so a streaming response that lasts longer is
cut off unless `envoy.http.routers.<r>.timeout: "0s"` (or a large value) is
also set.

**WebSocket sessions and timeouts.** The route `timeout` stops applying once
the upgrade completes: with default labels a session stays up well past 15s
(verified on Envoy 1.37 with 30s sessions, including a single 21s gap with no
frames). The idle timeout still applies to the upgraded stream: frames in either direction
reset it, and a session silent for longer than the idle timeout (5m by
default) is closed. Either have the application send pings more often than
the idle timeout (most WebSocket libraries can), or set
`envoy.http.routers.<r>.idletimeout` to a longer value (or `"0s"` to disable it).

**WebSockets and SSO.** The oauth2 filter handles the upgrade request like
any other request:

- Browsers send cookies on a same-origin WebSocket handshake, so a page
  loaded after SSO login can open a WebSocket to the same host and the
  oauth2 session cookie authenticates it.
- An unauthenticated upgrade gets the oauth2 filter's `302` to the IdP, not
  a `101`. A WebSocket client cannot follow that redirect; the browser just
  reports a failed connection. Load a page on the host first so the login
  happens there.
- Browsers cannot set an `Authorization` header on a WebSocket, so the
  Bearer/`jwt_authn` path only helps non-browser clients. Those can send
  `Authorization: Bearer <JWT>` on the handshake. An invalid token gets
  `401` from `jwt_authn`.

**WebSockets and middleware.** Header, path, CORS, auth, IP and rate-limit
middlewares act on the handshake request only. The `compress` filters leave
the `101` response and the frames alone (verified). The `buffering`
middleware does not work with upgrades: Envoy's buffer filter waits for the
end of the request body, which never comes on an upgrade, so the handshake
hangs. Set `websocket: "false"` on buffered routers, or do not combine
buffering with WebSocket routes.

## Observability hooks

Three router labels give per-route control over Envoy's tracing and
access-logging behavior, implemented with the route decorator/metadata and
per-route tracing-override semantics the pinned Envoy API exposes:

| Label | Meaning |
| --- | --- |
| `envoy.http.routers.<name>.tracing` | `true` forces 100% trace sampling for this route's traffic; `false` disables tracing for it (0% sampling), overriding whatever the listener/HCM default would otherwise select. Omitted leaves the route at the listener default. |
| `envoy.http.routers.<name>.tracing.operationname` | Sets the route's per-route span name (`Route.Tracing.Operation`), which takes precedence over the HCM's default operation name. Can be set with or without `.tracing`; setting it alone does not change the sampling decision. |
| `envoy.http.routers.<name>.accesslog` | `true`\|`false`. Recorded as route metadata (see below) under the `envoy-control-plane.observability` filter-metadata namespace, alongside the router's name and subdomain, so a log-processing or metrics pipeline consuming that metadata can distinguish routers that opted in from ones that didn't. |

`.tracing`/`.tracing.operationname` are true per-route Envoy semantics
(`Route.Tracing.overall_sampling` and `Route.Tracing.operation`) and directly
change whether/how a request is traced. `.accesslog` is different: **Envoy's
pinned access-log configuration is listener-scoped, not per-route** — there
is no field on `Route` that turns access logging on or off for just that
route in the API version this control plane targets. Setting
`.accesslog=true|false` therefore does not itself enable or suppress a log
line; it is a declarative carrier of the operator's intent, recorded as route
metadata that an access-log format string (or an external log-processing
pipeline reading Envoy's metadata field) can key off. See
[Limitations](#observability-limitations) for the precise implication.

None of these hooks ever place a secret or raw `Authorization`/credential
header into generated metadata, tracing spans, or (by extension) whatever
access-log format an operator layers on top: the emitted metadata carries
only the boolean flag, the router name, and the subdomain — never request
headers, path query strings, or middleware-scrubbed credentials. Combine this
with the BasicAuth/ForwardAuth credential-redaction behavior described above
if request headers themselves ever need to reach a log or trace pipeline.

### Observability limitations {#observability-limitations}

- `.accesslog` does not, by itself, install or configure an access-log sink
  (Envoy's `stdout`/`file`/gRPC access loggers) or filter which requests are
  written to one — that remains an operator concern (the Envoy bootstrap
  template's listener `access_log` stanza), independent of this control
  plane's generated resources, because access logging is listener-scoped in
  the pinned API and this milestone's per-route hook cannot select a
  listener-level sink per route. `.accesslog=false` is therefore *not* a
  guarantee that a route's requests are absent from whatever sink the
  listener does have configured; it only stops that route from carrying the
  observability metadata an access-log format or downstream consumer would
  otherwise use to flag it as "opted in".
- `.tracing`/`.tracing.operationname` require the listener to actually have
  tracing configured (an HCM `tracing` provider) to have any effect; on a
  listener with tracing disabled entirely, a per-route override has nothing
  to override.

## TCP routers, raw TCP, and TLS passthrough

TCP routing is a separate label namespace (`envoy.tcp.*`) from HTTP. It
never attaches an HTTP connection manager: a TCP filter chain always carries
exactly a `tcp_proxy` network filter, optionally gated by Envoy's TLS
inspector for passthrough. No TCP middlewares are supported in this
milestone.

### Per-router fields

Each router is a group of labels sharing the prefix
`envoy.tcp.routers.<name>.`, mirroring the HTTP router shape:

| Label | Required | Meaning |
| --- | --- | --- |
| `envoy.tcp.routers.<name>.rule` | yes | A `HostSNI(...)` rule (below). |
| `envoy.tcp.routers.<name>.service` | yes | Selects `envoy.tcp.services.<service>`. |
| `envoy.tcp.routers.<name>.entrypoints` | see below | Comma/escape list of TCP entrypoint names (daemon-configured, see [TCP entrypoints](#tcp-entrypoints)). |
| `envoy.tcp.routers.<name>.priority` | no | Explicit integer priority; higher wins on overlapping SNI. See [Precedence and conflicts](#tcp-precedence-and-conflicts). |
| `envoy.tcp.routers.<name>.tls.passthrough` | no (default `false`) | `true` selects TLS passthrough; `false` (default) selects raw TCP. |
| `envoy.tcp.routers.<name>.network` | no | Docker network override, same semantics as the HTTP router field. |

### The SNI rule DSL

```
expr    := term ( '||' term )*
term    := factor ( '&&' factor )*
factor  := '!' factor | '(' expr ')' | matcher
matcher := HostSNI
```

`HostSNI(value, ...)` is the only matcher; multiple values are ORed. The
grammar accepts `&&`, `||`, `!`, and parentheses like the HTTP rule DSL, but
only a rule that reduces to a pure disjunction of (non-negated) `HostSNI`
atoms is actually usable — Envoy's filter-chain `server_names` matching has
no negation and no cross-dimension conjunction, so:

- `!HostSNI(...)` (negation anywhere in the rule) is rejected.
- Any matcher other than `HostSNI` (there are none defined for TCP, but the
  grammar would otherwise accept it) is rejected.
- `HostSNI(a) && HostSNI(b)` for distinct `a`/`b` is a contradiction (no
  request can present two different SNI values at once) and is rejected as
  unsatisfiable, the same way the HTTP DNF expander rejects
  `Path(/a) && Path(/b)`.

`HostSNI(*)` is the catch-all: it matches any SNI value, including a
connection with no SNI at all when used as a passthrough router, or matches
every connection outright when used as a raw router (see below).

### Raw TCP vs. TLS passthrough

- **TLS passthrough** (`tls.passthrough=true`) forwards the encrypted TLS
  bytes untouched: Envoy never terminates TLS on this chain (no downstream
  `TransportSocket`). The generated filter chain matches
  `transport_protocol=tls` plus, for a non-catch-all rule, `server_names`
  from the rule's `HostSNI(...)` values. This requires the listener's TLS
  inspector (added automatically whenever any passthrough router exists on
  that entrypoint) to have peeked the ClientHello's SNI first.
- **Raw TCP** (`tls.passthrough=false`, the default) has no TLS
  inspection requirement and matches `transport_protocol=raw_buffer`.
  Because there is no ClientHello to inspect, a raw router's rule **must**
  be exactly `HostSNI(*)` (the catch-all) — matching on a concrete SNI value
  is only meaningful once the bytes have been proven to be a TLS
  ClientHello, which raw TCP explicitly does not require. A raw router with
  a concrete `HostSNI(...)` value is rejected at validation with an
  actionable error.

### TCP entrypoints

`.entrypoints` only ever *selects among* entrypoints the daemon operator
already configured (via `TCP_ENTRYPOINTS=name=port,name2=port2` and,
optionally, `TCP_DEFAULT_ENTRYPOINT=name` in the control plane's own
environment); a container label can never bind a new host socket of its
own. A router with no `.entrypoints` label uses `TCP_DEFAULT_ENTRYPOINT`
when set; otherwise it is skipped with a warning (an explicit entrypoint is
required). A router naming an entrypoint that was not configured is skipped
with a warning naming the list of valid entrypoints; labels are untrusted
input, so a bad selection never blocks config updates for other containers.
Comma-separated multiple entrypoints publish the same
router's filter chain on every named listener. Existing HTTP/HTTPS
entrypoints (`HTTP_PORT`/`HTTPS_PORT`) are untouched by any of this and
keep serving legacy HTTP routers exactly as before.

### TCP named services

```yaml
labels:
  envoy.enable: "true"
  envoy.tcp.routers.postgres.rule: "HostSNI(*)"
  envoy.tcp.routers.postgres.service: db
  envoy.tcp.services.db.loadbalancer.servers.0.port: "5432"
  envoy.tcp.services.db.loadbalancer.servers.1.port: "5433"
```

A plain named multi-endpoint service (indexed `loadbalancer.servers.<n>.port`)
is the mandatory form; replica containers with the same compatible service
definition contribute additional endpoints exactly like HTTP named
services. Weighted TCP services mirror the HTTP naming:

```yaml
envoy.tcp.services.rollout.weighted.services.0.name: blue
envoy.tcp.services.rollout.weighted.services.0.weight: "90"
envoy.tcp.services.rollout.weighted.services.1.name: canary
envoy.tcp.services.rollout.weighted.services.1.weight: "10"
```

A service cannot combine direct servers and weighted children in the same
definition; unknown, invalid, or cyclic services invalidate only the
routers that reference them.

### TCP precedence and conflicts

Within one entrypoint, TCP routers use the identical three-tier precedence
as HTTP routers (`model.TCPPrecedence`): explicit `.priority` (descending)
first, then rule specificity (the length of the rule expression,
descending), then router name (ascending) as the final tie-breaker.

Because Envoy's `FilterChainMatch` has no priority concept of its own — it
picks the single best-matching chain **structurally**, and two chains with
identical or overlapping matches are duplicates Envoy rejects with an LDS
NACK (refusing the entire listener update) — this control plane resolves
overlaps deterministically at build time rather than letting a bad label
NACK the dataplane:

- Two routers on the same entrypoint, same TLS mode (raw vs. passthrough),
  whose `HostSNI(...)` sets overlap (either both are the catch-all, or they
  share a concrete SNI value) cannot coexist as Envoy filter chains,
  **regardless of `.priority`** — priority orders chains but cannot
  disambiguate structural duplicate matches. The highest-precedence router
  of the overlapping set is kept and the rest are skipped with a warning
  naming both routers and the overlapping values.
- A concrete SNI match and the catch-all on the same entrypoint/TLS-mode
  are **not** a conflict: Envoy's filter-chain matching always prefers the
  more specific (concrete `server_names`) chain over the fallback, so no
  priority is needed to arbitrate that case.
- Raw and passthrough chains on the same entrypoint never conflict with
  each other: they match mutually exclusive `transport_protocol` values
  (`raw_buffer` vs. `tls`) at the Envoy filter-chain level.

### Example

```yaml
labels:
  envoy.enable: "true"
  envoy.tcp.routers.secure.rule: "HostSNI(mail.example.com)"
  envoy.tcp.routers.secure.service: mailserver
  envoy.tcp.routers.secure.tls.passthrough: "true"
  envoy.tcp.routers.secure.entrypoints: websecure
  envoy.tcp.services.mailserver.loadbalancer.servers.0.port: "993"

  envoy.tcp.routers.catchall.rule: "HostSNI(*)"
  envoy.tcp.routers.catchall.service: fallback
  envoy.tcp.routers.catchall.tls.passthrough: "true"
  envoy.tcp.routers.catchall.entrypoints: websecure
  envoy.tcp.services.fallback.loadbalancer.servers.0.port: "443"

  envoy.tcp.routers.raw.rule: "HostSNI(*)"
  envoy.tcp.routers.raw.service: db
  envoy.tcp.routers.raw.entrypoints: db
  envoy.tcp.services.db.loadbalancer.servers.0.port: "5432"
```

With `TCP_ENTRYPOINTS=websecure=8443,db=5432` in the control plane's
environment: `secure` and `catchall` share the `websecure` listener (the
concrete `mail.example.com` match takes precedence over the catch-all
automatically; no `.priority` label is needed), and `raw` gets its own `db`
listener with no TLS inspection since it is not TLS passthrough.

### Limitations

- No TCP middlewares in this milestone (no rate limiting, IP filtering,
  etc. on TCP routers).
- A raw TCP router's rule must be exactly `HostSNI(*)`; concrete SNI
  matching requires TLS passthrough (or termination, which is out of scope
  here).
- `HostSNI` is the only TCP matcher; there is no TCP equivalent of
  `Path`/`Headers`/`Method`/etc., since those are HTTP-layer concepts.

## Migration from legacy `subdomain` labels and Traefik

### From this control plane's own legacy labels

The very first form this control plane supported was a legacy, no-rule
router: `envoy.http.routers.<name>.subdomain` plus `.port` (or `.service`),
with no `.rule`. Every feature added since is additive — a legacy router
keeps working unmodified, with no relabeling required, forever:

```yaml
# Original legacy router. Still valid on the latest version, unchanged.
envoy.enable: "true"
envoy.http.routers.web.subdomain: myapp
envoy.http.routers.web.port: "8080"
```

To opt an existing legacy router into a feature added later, add only the
label(s) for that feature; nothing about `subdomain`/`port` changes:

```yaml
envoy.enable: "true"
envoy.http.routers.web.subdomain: myapp
envoy.http.routers.web.port: "8080"
# Opt into an operator-configured named entrypoint...
envoy.http.routers.web.entrypoints: admin
# ...and observability hooks, without touching the router's core shape.
envoy.http.routers.web.accesslog: "true"
envoy.http.routers.web.tracing: "true"
```

A legacy router that never sets `.rule` continues to behave as a
`PathPrefix(/)` catch-all for its subdomain; there is no need to write an
equivalent `.rule` label to preserve behavior.

### Traefik-to-envoy label mapping

This control plane's label grammar deliberately echoes Traefik's Docker
provider so migrating a compose file is mostly a `traefik.` -> `envoy.`
prefix swap plus the differences below. It is **not** a drop-in replacement
of Traefik's label surface — only the mappings in this table (and the
features documented elsewhere in this file) are supported.

| Traefik label | This control plane | Notes |
| --- | --- | --- |
| `traefik.enable=true` | `envoy.enable=true` | Same semantics: opt-in per container. |
| `traefik.http.routers.<r>.rule=Host(\`app.example.com\`)` | `envoy.http.routers.<r>.rule=Host(app.example.com)` | No backticks around the value; this grammar's `Host(...)` takes a bare hostname, and a backticked value is rejected with an actionable error (never silently accepted) so a pasted Traefik rule cannot silently blackhole a router. Traefik's `Host()`/`Headers()`/etc. all lower/uppercase quoting rules do not apply here — see [Matchers](#matchers). |
| `traefik.http.routers.<r>.rule=PathPrefix(\`/api\`)` | `envoy.http.routers.<r>.rule=PathPrefix(/api)` | Same idea; combine with `Host(...)` via `&&` as shown throughout this doc. |
| `traefik.http.routers.<r>.priority=10` | `envoy.http.routers.<r>.priority=10` | Same integer-priority override semantics; both fall back to rule-specificity ordering when unset. |
| `traefik.http.routers.<r>.entrypoints=websecure` | `envoy.http.routers.<r>.entrypoints=websecure` | Same idea (comma-separated selection among *daemon-configured* entrypoints), but Traefik entrypoints are typically declared in its static config file, while here they come from `HTTP_ENTRYPOINTS`/`TCP_ENTRYPOINTS` environment variables. See [HTTP entrypoints](#http-entrypoints) / [TCP entrypoints](#tcp-entrypoints). |
| `traefik.http.routers.<r>.middlewares=strip@docker,cors@docker` | `envoy.http.routers.<r>.middlewares=strip,cors` | No `@docker`/`@file` provider suffix; every middleware referenced by a router must be defined by another label on some container in the same discovery pass. |
| `traefik.http.routers.<r>.tls=true` (+ `certresolver`) | *(implicit)* | TLS termination and ACME are handled entirely by the separate `envoy-acme` control plane via SDS; there is no per-router TLS/certresolver label here. Every router on a TLS-terminating entrypoint gets the one wildcard cert configured for the whole control plane (`CERT_SECRET_NAME`). |
| `traefik.http.middlewares.<m>.stripprefix.prefixes=/api` | `envoy.http.middlewares.<m>.stripprefix.prefixes=/api` | Same list syntax (comma-separated, or indexed — see [List syntax](#list-syntax)). |
| `traefik.http.middlewares.<m>.redirectscheme.scheme=https` | `envoy.http.middlewares.<m>.redirectscheme.scheme=https` | Same fields (`scheme`, `port`, `permanent`). |
| `traefik.http.middlewares.<m>.basicauth.users=user:hash` | `envoy.http.middlewares.<m>.basicauth.users=user:{SHA}hash` | Envoy's native `basic_auth` filter only accepts Apache htpasswd `{SHA}` entries in this milestone; Traefik's bcrypt (`$apr1$`/`$2y$`) hashes are **not** accepted and must be regenerated. See [Security middleware](#security-middleware). |
| `traefik.http.middlewares.<m>.forwardauth.address=...` | `envoy.http.middlewares.<m>.forwardauth.address=...` | Same idea (fail-closed external auth check); field names differ slightly (`trustforwardheader`, `authresponseheaders`, etc.) — see [Security middleware](#security-middleware) for the full set. |
| `traefik.http.middlewares.<m>.ratelimit.average=10` | `envoy.http.middlewares.<m>.ratelimit.average=10` | Same `average`/`burst`/`period` shape, but this is a **local, per-Envoy-process** token bucket, not Traefik's (also local-by-default) limiter — see the rate-limiting note under [Security middleware](#security-middleware) for the N-replica caveat. There is no global/distributed rate limiter in this milestone. |
| `traefik.http.services.<s>.loadbalancer.server.port=8080` | `envoy.http.services.<s>.loadbalancer.servers.0.port=8080` | Named services here always use the indexed `servers.<n>.port` form (supporting multiple backends/replicas per service), where Traefik's Docker provider infers one port automatically per container. |
| `traefik.tcp.routers.<r>.rule=HostSNI(\`db.example.com\`)` | `envoy.tcp.routers.<r>.rule=HostSNI(db.example.com)` | Same idea, no backticks. See [TCP routers](#tcp-routers-raw-tcp-and-tls-passthrough). |
| `traefik.tcp.routers.<r>.tls.passthrough=true` | `envoy.tcp.routers.<r>.tls.passthrough=true` | Same semantics. |

Traefik features with **no equivalent** in this control plane (do not expect
these labels to do anything if carried over verbatim): dynamic file/etcd/consul
providers, the dashboard/API, `traefik.http.routers.<r>.tls.domains.*` (SAN
management — handled entirely by the external `envoy-acme` service here),
per-router TLS options (`tls.options`), Traefik plugins, and any middleware
family not listed in [HTTP middleware](#http-middleware) (e.g. Traefik's
`chain`, `plugin`, `digestauth`, or `inflightreq` have no port here).
