# Traefik parity capability matrix

This control plane deliberately keeps the `envoy.*` label namespace. The
entries below describe behavior rather than claiming wire-compatible
`traefik.*` labels.

| Capability | Status | Notes |
| --- | --- | --- |
| HTTP named entrypoints | Supported | Operator-configured via `HTTP_ENTRYPOINTS`; labels only select existing listeners. |
| HTTP default entrypoint list | Supported | `HTTP_DEFAULT_ENTRYPOINTS` publishes omitted routers on every listed entrypoint; singular `HTTP_DEFAULT_ENTRYPOINT` is a compatibility alias. |
| HTTP/TCP listener collision validation | Supported | Shared ports, including default HTTP/HTTPS ports, are rejected during startup. |
| HTTP router priority/conflicts | Supported | Conflicts are non-fatal; the deterministic explicit-priority, specificity, then router-name order selects a winner. |
| TCP HostSNI exact/catch-all | Supported | Exact SNI and `*`, raw TCP, TLS passthrough, and explicit conflict validation are covered by tests. |
| Retry attempts | Supported | `attempts` counts the initial request; Envoy receives `attempts-1` retries. Values are positive and incomplete policies are rejected. |
| Per-router tracing | Supported | Route-level sampling and operation-name overrides are emitted when configured. |
| Per-router access logging | Partial | `.accesslog` is metadata intent only because the pinned Envoy API makes access logs listener-scoped. It does not install or suppress a sink. |
| Docker service/network replicas | Supported | Compatible definitions merge endpoints deterministically; conflicting service shape/network definitions are rejected without dropping unrelated routers. |
| Docker weighted services | Supported | Indexed definitions are sorted and validated; cycles and malformed children are isolated to referencing routers. |
| Plain named HTTP entrypoints | Not supported | Named HTTP listeners terminate TLS; the legacy HTTP port remains redirect-only. |
| Native `traefik.*` labels | Not supported | Use the documented `envoy.*` namespace. |
