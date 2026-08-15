# Rate Limiter — `dev.mcpg.rate-limit`

> class `tool_gate` · `native` · package `mcpg-plugin-reliability-rate-limit` · artifact `libmcpg_plugin_reliability_rate_limit.so` · Apache-2.0

Token-bucket rate limiter for MCPG tool calls. Each request draws one token from
a bucket chosen by the matching rule's scope — the calling principal, the tool,
the principal-and-tool pair, the MCP session, or a single global bucket — and a
drained bucket answers HTTP 429 with a `retry_after_secs` hint instead of
reaching the backend. Reach for it to cap spend on expensive tools, to keep one
noisy caller from starving the rest, or to put a hard ceiling on a shared
downstream quota.

## What it does
- Gates pre-dispatch only. Post-dispatch always allows, so a rate-limited tool
  never pays twice for one call.
- Applies the first `rules[]` entry whose glob patterns match the tool name;
  tools that match nothing fall back to the plugin-wide defaults under
  `per_principal` scope.
- Refills each bucket continuously at `limit / window_ms` tokens per
  millisecond, capped at `burst` when set and at `limit` otherwise. A fresh
  bucket starts full.
- Returns `remaining` and `limit` as decision metadata on allow.
- Denies an exhausted bucket with HTTP 429, JSON-RPC code `-32029`, and
  `error_data` carrying `retry_after_secs`, `limit`, `window_ms`, and
  `remaining`. The hint travels in the JSON-RPC error payload, not in an HTTP
  `Retry-After` header.
- Sweeps idle buckets opportunistically so the key space cannot grow without
  bound, with no background task and no timer thread.
- Emits a per-decision host-observability triad — span, latency histogram,
  decision counter — plus an audit event on rejection only.
- Declares no host capabilities and opens no sockets.

## Configuration
Loaded from the flat top-level `plugins:` list. Every entry of class `tool_gate`
joins the gate chain that runs on each tool call; a `Deny` from an enforcing gate
ends the chain immediately.

```yaml
plugins:
  - id: dev.mcpg.rate-limit
    class: tool_gate
    source: { path: ./plugins/libmcpg_plugin_reliability_rate_limit.so }
    # or, platform-agnostic — the gateway resolves the artifact for its own
    # os/arch/libc at boot:
    # source: { oci: ghcr.io/mcpg-dev/source-code/plugins/rate-limit:protocol-1 }
    config:
      default_limit: 100              # tokens per window for unmatched tools
      default_window_ms: 60000
      default_burst: 150              # optional headroom above the steady rate
      cleanup_interval_ms: 300000     # idle threshold for bucket eviction
      rules:
        - tools: ["expensive.*", "admin.*"]   # glob patterns, first match wins
          scope: per_principal
          limit: 10
          window_ms: 60000
          burst: 20
```

| Field | Type | Default | Description |
|---|---|---|---|
| `default_limit` | integer | `100` | Tokens per window for tools no rule matches. |
| `default_window_ms` | integer | `60000` | Window length in milliseconds for the defaults. |
| `default_burst` | integer | unset | Bucket capacity for the defaults; unset means capacity equals `default_limit`. |
| `rules` | object[] | `[]` | Per-tool rules, evaluated in order — see below. |
| `cleanup_interval_ms` | integer | `300000` | A bucket untouched for longer than this becomes evictable; `0` disables eviction. |

Each `rules[]` entry:

| Field | Type | Default | Description |
|---|---|---|---|
| `tools` | string[] | required | Glob patterns matched against the tool name. `*` matches any run of characters, `?` exactly one. |
| `scope` | enum | `per_principal` | Bucket key strategy: `per_principal`, `per_tool`, `per_principal_tool`, `per_session`, or `global`. |
| `limit` | integer | required | Tokens per window. |
| `window_ms` | integer | `60000` | Window length in milliseconds. |
| `burst` | integer | unset | Bucket capacity; unset means capacity equals `limit`. |

Unknown fields are rejected, at the top level and inside `rules[]` entries. An
absent or empty `config:` block yields the defaults above; a present-but-malformed
block refuses the plugin at boot rather than quietly degrading to permissive
defaults, so a typo in a limit cannot silently open the gate.

## Operations
**Bucket keys.** `per_principal` keys on the caller's subject id, falling back to
the MCP session id and then to a shared `_anon` bucket for callers with neither —
so unauthenticated traffic shares one bucket unless sessions are in play.
`per_session` keys on the session id with a shared `_no_session` fallback.
`per_principal_tool` combines subject and tool. `per_tool` ignores the caller
entirely, and `global` puts every caller and tool in one bucket.

**Capacity versus rate.** Capacity is `burst` when set, `limit` otherwise, and it
is what a cold bucket starts with — a rule of `limit: 10, burst: 20` admits 20
calls immediately, then settles to 10 per window.

**State is per process.** Buckets live in the plugin instance, so a fleet of N
gateway replicas admits up to N times the configured rate for a given key. Set
limits against per-replica traffic, or terminate rate limiting in front of the
fleet.

**Eviction.** Every 256 newly-created buckets the plugin sweeps entries idle for
longer than `cleanup_interval_ms`. A quiet gateway therefore keeps its buckets
until new keys arrive, which is harmless — an idle bucket is a few bytes and
refills to full anyway.

**Surfaces.** The gate chain is also evaluated on prompt, resource, and
completion requests, where the name matched against `tools` and used for
`per_tool` bucketing is the prompt name, resource URI, or completion reference.
Write patterns accordingly if you intend a rule to cover only `tools/call`.

## Observability
Internal metrics, always emitted:

- `mcpg_rate_limit_decisions_total{tool,decision}` — per-tool allow/deny counts.
- `mcpg_rate_limit_evaluate_ms` — pre-dispatch evaluation latency.

When the gateway installs its host-services handle, each evaluation additionally
opens a `rate_limit.check` span (tagged with tool, scope, limit, window, and
request id) and reports `mcpg_rate_limit_decision_seconds{outcome}` and
`mcpg_rate_limit_decisions_total{outcome}` through the central sink, with
`outcome` bounded to `allow`, `deny_rate_limited`, or `error`. Bucket keys stay
out of metric labels — they would be unbounded cardinality — and appear only in
the audit trail.

Rejections emit a `dev.mcpg.rate_limit.rejected` audit event whose details carry
the bucket key, scope, limit, window, remaining tokens, retry-after, and subject.
Allowed calls emit no audit traffic.

## Build
The `cdylib-export` feature gates the `mcpg_plugin_register` export. It is on by
default for a standalone build and switched off when the crate is linked as a
path dependency alongside other plugins, since several `mcpg_plugin_register`
symbols collide at link time:

```bash
cargo build -p mcpg-plugin-reliability-rate-limit --features cdylib-export --release   # → target/release/libmcpg_plugin_reliability_rate_limit.so
```

## Testing
```bash
cargo test -p mcpg-plugin-reliability-rate-limit
```

Beyond the unit tests, an integration suite drives a `HostServices` test double
through the plugin and asserts the full per-decision triad: span open/close
ordering, the bounded `outcome` label set, and that only rejections produce audit
events. It relies on the SDK's `static-firstparty` feature, which exposes
`HostHandle::from_services` so a host handle can be built in-process without the
FFI boundary; the cdylib build is unaffected.

## Sign & load (production)
Sign the artifact, pin/verify via the entry's `signature:` block, and honour
revocations. See <https://mcpg.dev/docs/security/plugin-security>.

## See also
- Plugin classes, loading, and the ABI: <https://mcpg.dev/docs/plugins/plugins-and-protocol>
- Full gateway config schema: <https://mcpg.dev/docs/reference/configuration>
- Sibling reliability gates: `libs/plugins/reliability/circuit-breaker`,
  `libs/plugins/reliability/response-cache`
