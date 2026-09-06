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
