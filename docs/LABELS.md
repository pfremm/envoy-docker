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
| `envoy.http.routers.<name>.idletimeout` | no | Per-route stream idle timeout as a Go duration. `0s` disables it. |
| `envoy.http.routers.<name>.retries.attempts` | no | Positive retry count. |
| `envoy.http.routers.<name>.retries.pertrytimeout` | no | Positive timeout for each try. |
| `envoy.http.routers.<name>.retries.retryon` | no | Envoy retry conditions, for example `5xx,reset,connect-failure`. |

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

A rule-based route is served by the virtual host of its rule's first
`Host(...)` atom. A legacy (no-rule) route keeps its own
`<subdomain>.<baseDomain>` virtual host. When any rule-based route exists,
legacy routes are additionally carried in a catch-all virtual host with
domain `*` so a request that matches no rule-based host still reaches them.
With no rule-based routes at all, the configuration is exactly the legacy
shape (one virtual host per subdomain, no catch-all).

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
