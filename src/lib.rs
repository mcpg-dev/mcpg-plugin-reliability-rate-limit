//! Rate-limiting ToolGate plugin for MCPG.
//!
//! Provides per-identity, per-tool, per-session, and global rate
//! limiting using token-bucket algorithms with interior-mutable
//! state. Distributed as a `native-cdylib-v1` plugin.

mod limiter;

use mcpg_plugin_protocol::audit::{AuditEvent, AuditOutcome};
use mcpg_plugin_protocol::types::PluginIdentity;
use mcpg_plugin_protocol::{GateDecision, PluginClass, PluginContext, PluginManifest};
use mcpg_plugin_sdk::HostHandle;
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncToolGate;
use serde::Deserialize;
use std::sync::{Arc, OnceLock};

const PLUGIN_ID: &str = "dev.mcpg.rate-limit";

pub use limiter::{RateLimitState, TokenBucket};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Default requests per window for unmatched tools.
    #[serde(default = "default_limit")]
    pub default_limit: u64,
    /// Default window in milliseconds.
    #[serde(default = "default_window_ms")]
    pub default_window_ms: u64,
    /// Default burst allowance (extra tokens above steady rate).
    #[serde(default)]
    pub default_burst: Option<u64>,
    /// Per-tool rules (evaluated in order, first match wins).
    #[serde(default)]
    pub rules: Vec<RateLimitRuleConfig>,
    /// Cleanup interval for expired entries (milliseconds).
    #[serde(default = "default_cleanup_interval_ms")]
    pub cleanup_interval_ms: u64,
}

fn default_limit() -> u64 {
    100
}
fn default_window_ms() -> u64 {
    60000
}
fn default_cleanup_interval_ms() -> u64 {
    300000
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            default_limit: default_limit(),
            default_window_ms: default_window_ms(),
            default_burst: None,
            rules: Vec::new(),
            cleanup_interval_ms: default_cleanup_interval_ms(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitRuleConfig {
    /// Glob patterns for tool names (e.g. `["expensive.*", "admin.*"]`).
    pub tools: Vec<String>,
    /// Key strategy for bucketing.
    #[serde(default)]
    pub scope: RateLimitScope,
    /// Max requests per window.
    pub limit: u64,
    /// Window in milliseconds.
    #[serde(default = "default_window_ms")]
    pub window_ms: u64,
    /// Burst allowance above steady rate.
    #[serde(default)]
    pub burst: Option<u64>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitScope {
    /// Key = principal_id (unauthenticated uses session_id fallback).
    #[default]
    PerPrincipal,
    /// Key = tool_name.
    PerTool,
    /// Key = principal_id:tool_name.
    PerPrincipalTool,
    /// Key = session_id.
    PerSession,
    /// Single global bucket (no per-user split).
    Global,
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

pub struct RateLimitPlugin {
    manifest: PluginManifest,
    config: RateLimitConfig,
    compiled_rules: Vec<CompiledRule>,
    state: Arc<RateLimitState>,
    /// Unified host-observability handle.
    /// `OnceLock` because the factory closure installs it exactly
    /// once at boot via `set_host_handle`, after the plugin is
    /// constructed but before any traffic reaches `evaluate_pre`.
    /// Test paths that construct the plugin without the macro
    /// factory leave the slot empty; `host_handle()` returns
    /// `None` and the per-decision observability triad short-circuits
    /// to a no-op. The internal `tracing::*` + `metrics::*` calls
    /// remain wired in both modes (coexisting with the host triad
    /// is intentional).
    host_handle: OnceLock<HostHandle>,
}

struct CompiledRule {
    tool_patterns: Vec<String>,
    scope: RateLimitScope,
    limit: u64,
    window_ms: u64,
    burst: Option<u64>,
}

impl RateLimitPlugin {
    pub fn new(config: RateLimitConfig) -> Self {
        let compiled_rules = config
            .rules
            .iter()
            .map(|r| CompiledRule {
                tool_patterns: r.tools.clone(),
                scope: r.scope,
                limit: r.limit,
                window_ms: r.window_ms,
                burst: r.burst,
            })
            .collect();

        // Wire opportunistic bucket eviction from the advertised
        // `cleanup_interval_ms` knob (captured before `config` is moved
        // into the struct below). Buckets idle longer than one cleanup
        // interval are swept opportunistically as new buckets are created.
        let max_idle_ms = config.cleanup_interval_ms;

        Self {
            manifest: PluginManifest {
                id: PLUGIN_ID.into(),
                version: env!("CARGO_PKG_VERSION").into(),
                name: "Rate Limiter".into(),
                plugin_class: PluginClass::ToolGate,
                protocol_version: "1.0".into(),
                license: None,
                required_capabilities: Vec::new(),
                tags: Vec::new(),
                provides: Vec::new(),
                provides_schemes: Vec::new(),
                module_path_prefix: ::std::module_path!()
                    .split("::")
                    .next()
                    .unwrap_or("")
                    .to_owned(),
                backend_profile: None,
            },
            config,
            compiled_rules,
            state: Arc::new(RateLimitState::with_eviction(max_idle_ms)),
            host_handle: OnceLock::new(),
        }
    }

    /// Install the unified [`HostHandle`] surface for
    /// per-call observability. The SDK factory closure installs
    /// this exactly once at boot, after constructing the plugin but
    /// before any `evaluate_pre()` traffic is dispatched, threading
    /// a handle built from the late-bound `HostServices`.
    ///
    /// Idempotent — a second call returns `false` so reload paths
    /// that re-enter the install site don't panic. The returned
    /// `bool` indicates whether the handle was installed (`true`)
    /// or the slot was already occupied (`false`).
    pub fn set_host_handle(&self, host: HostHandle) -> bool {
        self.host_handle.set(host).is_ok()
    }

    /// Borrow the installed unified host surface, if any.
    /// Returns `None` in test harnesses that constructed the plugin
    /// without calling [`RateLimitPlugin::set_host_handle`]. Callers
    /// MUST treat `None` as "skip the host observability triad" — the
    /// plugin's internal `tracing::*` + `metrics::*` calls remain
    /// wired and carry the load through their own sinks.
    fn host_handle(&self) -> Option<&HostHandle> {
        self.host_handle.get()
    }

    pub fn from_config(config_value: &serde_json::Value) -> Result<Self, String> {
        let config: RateLimitConfig =
            serde_json::from_value(config_value.clone()).map_err(|e| format!("{e}"))?;
        Ok(Self::new(config))
    }

    /// SDK macro factory. Fails CLOSED on a malformed operator
    /// `config:` block (see [`mcpg_plugin_sdk::config`]): a
    /// present-but-unparseable config panics rather than silently
    /// degrading to permissive defaults, which the FFI `make` slot
    /// turns into a boot rejection. An empty / absent block (`""`,
    /// `"{}"`, `"null"`) still yields [`RateLimitConfig::default`].
    pub fn from_config_json(config_json: &str) -> Self {
        let config: RateLimitConfig =
            mcpg_plugin_sdk::fail_closed_config!(config_json, RateLimitConfig);
        Self::new(config)
    }

    /// Get or create a token bucket for the given key.
    fn check_limit(
        &self,
        key: &str,
        limit: u64,
        window_ms: u64,
        burst: Option<u64>,
    ) -> LimitResult {
        let capacity = burst.unwrap_or(limit);
        // tokens per MILLISECOND — window_ms is milliseconds, and refill()
        // accrues `elapsed_ms * refill_rate`. (Previously labeled "per second"
        // and accrued against elapsed *seconds*, a 1000x error that refilled
        // the bucket 1000x too slowly = silently far more restrictive than
        // the configured `limit` per `window_ms`.)
        let refill_rate = limit as f64 / window_ms as f64;
        self.state.check(key, capacity, refill_rate, window_ms)
    }

    fn resolve_key(&self, ctx: &PluginContext, scope: RateLimitScope) -> String {
        match scope {
            RateLimitScope::PerPrincipal => ctx
                .identity
                .subject_id
                .clone()
                .or_else(|| ctx.session_id.clone())
                .unwrap_or_else(|| "_anon".into()),
            RateLimitScope::PerTool => ctx.tool_name.clone(),
            RateLimitScope::PerPrincipalTool => {
                let principal = ctx
                    .identity
                    .subject_id
                    .as_deref()
                    .or(ctx.session_id.as_deref())
                    .unwrap_or("_anon");
                format!("{}:{}", principal, ctx.tool_name)
            }
            RateLimitScope::PerSession => ctx
                .session_id
                .clone()
                .unwrap_or_else(|| "_no_session".into()),
            RateLimitScope::Global => "_global".into(),
        }
    }

    fn find_matching_rule(&self, tool_name: &str) -> Option<&CompiledRule> {
        self.compiled_rules.iter().find(|rule| {
            rule.tool_patterns
                .iter()
                .any(|pattern| glob_match(pattern, tool_name))
        })
    }
}

pub(crate) struct LimitResult {
    allowed: bool,
    remaining: u64,
    limit: u64,
    retry_after_secs: f64,
}

impl SyncToolGate for RateLimitPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn evaluate_pre(
        &self,
        ctx: &PluginContext,
        _arguments: &serde_json::Value,
        _meta: Option<&serde_json::Value>,
        _config: &serde_json::Value,
    ) -> GateDecision {
        // Plugin-scoped span so traces from rate-limit gate
        // attribute back to dev.mcpg.rate-limit. Retained alongside
        // the host-attributed span below; the two coexist
        // intentionally.
        let _span = tracing::info_span!(
            "rate_limit_evaluate_pre",
            plugin_id = PLUGIN_ID,
            tool = %ctx.tool_name,
        )
        .entered();

        // Open a host-attributed span ALONGSIDE the
        // internal `info_span!` above. The internal span flows
        // through the local `tracing` subscriber; the host span
        // routes to the central observability sink with the plugin
        // alias as a resource attribute.
        //
        // Cardinality note: we put `tool_name` + `scope` in span
        // attrs (operators can inspect them on a single span), but
        // NOT in the metric labels — tools/buckets can be very
        // numerous in real deployments. Per-bucket-key would be
        // worst (one principal per series). The bucket key itself
        // goes only in audit details (forensic drill-down on a
        // reject).
        let (eff_limit, eff_window_ms, eff_burst, eff_scope) = self.effective_rule(&ctx.tool_name);
        let host_span = self.host_handle().map(|h| {
            h.span(
                "rate_limit.check",
                serde_json::json!({
                    "tool": ctx.tool_name,
                    "scope": scope_label(eff_scope),
                    "limit": eff_limit,
                    "window_ms": eff_window_ms,
                    "request_id": ctx.request_id,
                }),
            )
        });

        let started = std::time::Instant::now();
        let (decision, outcome_label, audit_payload) =
            self.check_rate_limit_with_outcome(ctx, eff_limit, eff_window_ms, eff_burst, eff_scope);
        let elapsed = started.elapsed();
        metrics::histogram!("mcpg_rate_limit_evaluate_ms").record(elapsed.as_millis() as f64);

        // Unified host-observability triad. Runs
        // ALONGSIDE the metrics::* calls inside `check_rate_limit_*`;
        // the two coexist intentionally until the host sinks subsume
        // the internal calls.
        self.emit_host_observability(ctx, outcome_label, elapsed, audit_payload);

        // Explicitly drop the host span here so its Drop-driven
        // `span_end` fires AFTER the metric + audit emission above.
        drop(host_span);

        decision
    }

    fn evaluate_post(
        &self,
        _ctx: &PluginContext,
        _arguments: &serde_json::Value,
        _result: &serde_json::Value,
        _duration_ms: u64,
        _config: &serde_json::Value,
    ) -> GateDecision {
        // Rate limit is a pre-dispatch gate only.
        GateDecision::allow()
    }
}

impl RateLimitPlugin {
    /// Resolve the effective bucket parameters for a tool: either the
    /// first matching per-tool rule, or the plugin-wide defaults.
    /// Pulled out so the host-span attrs and the check path read
    /// the same rule.
    fn effective_rule(&self, tool_name: &str) -> (u64, u64, Option<u64>, RateLimitScope) {
        if let Some(rule) = self.find_matching_rule(tool_name) {
            (rule.limit, rule.window_ms, rule.burst, rule.scope)
        } else {
            (
                self.config.default_limit,
                self.config.default_window_ms,
                self.config.default_burst,
                RateLimitScope::PerPrincipal,
            )
        }
    }

    /// Run the bucket check and return the gate decision plus the
    /// pre-bound outcome label (for the host metric pair) and a
    /// JSON payload of bucket details (for the reject audit event).
    /// The audit payload is only consumed on reject.
    fn check_rate_limit_with_outcome(
        &self,
        ctx: &PluginContext,
        limit: u64,
        window_ms: u64,
        burst: Option<u64>,
        scope: RateLimitScope,
    ) -> (GateDecision, &'static str, serde_json::Value) {
        let key = self.resolve_key(ctx, scope);
        let result = self.check_limit(&key, limit, window_ms, burst);

        // Internal counter — keep cardinality identical to the
        // original (tool + decision) so any existing operator
        // dashboards continue to render. The host counter uses a
        // bounded outcome-only label set.
        metrics::counter!("mcpg_rate_limit_decisions_total",
            "tool" => ctx.tool_name.clone(),
            "decision" => if result.allowed { "allow" } else { "deny" },
        )
        .increment(1);

        // Bucket-key + tool + scope go in audit details — fine in
        // forensic, drill-down audit traffic; would be lethal in
        // metric labels.
        let audit_details = serde_json::json!({
            "tool": ctx.tool_name,
            "scope": scope_label(scope),
            "bucket_key": key,
            "limit": result.limit,
            "window_ms": window_ms,
            "remaining": result.remaining,
            "retry_after_secs": result.retry_after_secs,
            "subject": ctx.identity.subject_id.clone().unwrap_or_default(),
        });

        if result.allowed {
            (
                GateDecision::Allow {
                    modified_arguments: None,
                    modified_result: None,
                    metadata: Some(serde_json::json!({
                        "remaining": result.remaining,
                        "limit": result.limit,
                    })),
                },
                "allow",
                audit_details,
            )
        } else {
            tracing::info!(
                tool = %ctx.tool_name,
                principal = ?ctx.identity.subject_id,
                key = %key,
                limit = result.limit,
                "Rate limit exceeded"
            );
            (
                GateDecision::Deny {
                    http_status: 429,
                    code: -32029,
                    message: "Rate limit exceeded".into(),
                    error_data: Some(serde_json::json!({
                        "retry_after_secs": result.retry_after_secs,
                        "limit": result.limit,
                        "window_ms": window_ms,
                        "remaining": result.remaining,
                    })),
                },
                "deny_rate_limited",
                audit_details,
            )
        }
    }

    /// Emit the per-evaluation host-observability triad:
    /// latency histogram + decisions counter + reject audit event,
    /// through the installed [`HostHandle`]. Short-circuits to a
    /// no-op when no handle is installed (test paths). Never
    /// audit-emits on `allow` — that's normal traffic.
    ///
    /// Cardinality budget: outcome ∈ {allow, deny_rate_limited,
    /// error}. The `error` arm is reserved for engine-internal
    /// failures; the token-bucket implementation cannot fail today,
    /// so it never fires on the happy path. The label is declared
    /// to keep the surface symmetrical with the other policy and
    /// reliability plugins (operator dashboards expect the same
    /// outcome enum across plugins).
    ///
    /// Audit emission is gated to reject paths:
    ///
    /// - `dev.mcpg.rate_limit.rejected` on bucket-exhaustion Deny.
    /// - `dev.mcpg.rate_limit.error` on engine failure (reserved).
    ///
    /// `SyncToolGate::evaluate_pre` is called directly from inside
    /// a tokio worker (the `SyncToolGateAdapter`'s async wrapper
    /// dispatches `inner.evaluate_pre()` without `spawn_blocking`),
    /// so calling `HostHandle::audit_event` here would panic on
    /// `Cannot start a runtime from within a runtime`. We move the
    /// call onto a blocking worker via `spawn_blocking` and detach
    /// — audit emission is best-effort, and joining the handle
    /// from a sync method isn't possible without re-entering the
    /// runtime.
    fn emit_host_observability(
        &self,
        ctx: &PluginContext,
        outcome_label: &'static str,
        duration: std::time::Duration,
        audit_payload: serde_json::Value,
    ) {
        let Some(host) = self.host_handle() else {
            return;
        };
        let elapsed_secs = duration.as_secs_f64();
        host.histogram(
            "mcpg_rate_limit_decision_seconds",
            elapsed_secs,
            &[("outcome", outcome_label)],
        );
        host.counter(
            "mcpg_rate_limit_decisions_total",
            1,
            &[("outcome", outcome_label)],
        );

        // Audit ONLY on reject paths. Allow is normal traffic and
        // would flood the audit sink at rate-limited traffic rates.
        let action: Option<&'static str> = match outcome_label {
            "deny_rate_limited" => Some("dev.mcpg.rate_limit.rejected"),
            "error" => Some("dev.mcpg.rate_limit.error"),
            _ => None,
        };
        let Some(action) = action else {
            return;
        };

        let audit_outcome = match outcome_label {
            "error" => AuditOutcome::Failure,
            _ => AuditOutcome::Denied,
        };

        let actor = if ctx.identity.kind.is_empty() {
            synthetic_system_identity()
        } else {
            ctx.identity.clone()
        };
        let resource_uri = format!("tool://{}", ctx.tool_name);
        let mut details = audit_payload;
        details
            .as_object_mut()
            .unwrap()
            .insert("alias".into(), serde_json::Value::String(host.alias()));
        details.as_object_mut().unwrap().insert(
            "duration_ms".into(),
            serde_json::json!(duration.as_millis() as u64),
        );

        let event = AuditEvent {
            event_id: format!("rate-limit-{}-{}", ctx.request_id, duration.as_nanos()),
            occurred_at: rfc3339_now(),
            actor,
            action: action.to_owned(),
            resource: Some(resource_uri),
            outcome: audit_outcome,
            request_id: Some(ctx.request_id.clone()),
            node_id: None,
            details,
            prev_event_hash: None,
        };

        // SyncToolGate's `evaluate_pre` is invoked directly from a
        // tokio worker via the async `SyncToolGateAdapter` (no
        // `spawn_blocking` between the runtime and us). Calling
        // `HostHandle::audit_event` directly here would re-enter
        // `Handle::block_on` from inside the runtime and panic.
        // Move the call onto a blocking worker and detach — audit
        // emission is best-effort. A planned SDK `_async`
        // variant will retire this detour.
        let host_for_audit = host.clone();
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn_blocking(move || {
                if let Err(err) = host_for_audit.audit_event(event) {
                    tracing::debug!(
                        target: "mcpg::rate_limit::host_handle",
                        error = %err,
                        "host_handle.audit_event emission failed"
                    );
                }
            });
        } else {
            // Non-runtime path (e.g. direct unit-test invocation
            // outside of `#[tokio::test]`). Call the bridge
            // directly — `block_on` will spin up a transient
            // runtime via the host services.
            if let Err(err) = host_for_audit.audit_event(event) {
                tracing::debug!(
                    target: "mcpg::rate_limit::host_handle",
                    error = %err,
                    "host_handle.audit_event emission failed (no runtime)"
                );
            }
        }
    }
}

/// Bounded label for the `scope` attr on the host span. The
/// scope enum is closed and small (5 variants) so it's safe as a
/// span attr — high-cardinality concerns apply only to metric
/// labels.
fn scope_label(scope: RateLimitScope) -> &'static str {
    match scope {
        RateLimitScope::PerPrincipal => "per_principal",
        RateLimitScope::PerTool => "per_tool",
        RateLimitScope::PerPrincipalTool => "per_principal_tool",
        RateLimitScope::PerSession => "per_session",
        RateLimitScope::Global => "global",
    }
}

/// RFC 3339 timestamp for audit events. Mirrors the helper in the
/// policy plugins so cross-plugin audit lines sort identically.
/// Naïve UTC; no leap-second handling.
fn rfc3339_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() as i64;
    let millis = now.subsec_millis();
    let (year, month, day, hour, min, sec) = epoch_to_ymdhms(secs);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.{millis:03}Z")
}

fn epoch_to_ymdhms(secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    let days_since_epoch = secs.div_euclid(86_400);
    let secs_today = secs.rem_euclid(86_400) as u32;
    let hour = secs_today / 3600;
    let min = (secs_today % 3600) / 60;
    let sec = secs_today % 60;
    let z = days_since_epoch + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i32 + era as i32 * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d, hour, min, sec)
}

/// Synthetic identity for audit events on inbound traffic with no
/// caller attribution (system-initiated paths). Mirrors the policy
/// plugins so cross-plugin audit search treats system traffic
/// uniformly.
fn synthetic_system_identity() -> PluginIdentity {
    PluginIdentity {
        kind: "system".into(),
        trust_level: "verified".into(),
        subject_id: Some(PLUGIN_ID.into()),
        auth_provider: None,
        issuer: None,
        roles: vec![],
        groups: vec![],
        scopes: vec![],
        attributes: Default::default(),
    }
}

declare_plugin! {
    plugin_id: PLUGIN_ID,
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[],
    entities: [
        tool_gate as gate {
            inner_name: "",
            plugin_type: RateLimitPlugin,
            // Install the unified `HostHandle` on the
            // plugin so per-evaluation observability (span + latency
            // histogram + decisions counter + reject audit event)
            // routes through the gateway's central host-services
            // sink. Idempotent — a second install returns false and
            // the slot remains untouched.
            factory: |cfg: &str, host: ::mcpg_plugin_sdk::HostHandle| -> RateLimitPlugin {
                let plugin = RateLimitPlugin::from_config_json(cfg);
                let _installed = plugin.set_host_handle(host);
                plugin
            },
        }
    ],
}

// ---------------------------------------------------------------------------
// Glob matching — delegated to mcpg-glob
// ---------------------------------------------------------------------------

use mcpg_glob::glob_match;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn test_ctx(tool: &str, principal: Option<&str>, session: Option<&str>) -> PluginContext {
        PluginContext {
            surface: "tool".to_owned(),
            request_id: "req-1".into(),
            session_id: session.map(str::to_owned),
            tool_name: tool.into(),
            identity: mcpg_plugin_protocol::PluginIdentity {
                kind: if principal.is_some() {
                    "verified"
                } else {
                    "anonymous"
                }
                .into(),
                trust_level: if principal.is_some() {
                    "verified"
                } else {
                    "unauthenticated"
                }
                .into(),
                subject_id: principal.map(str::to_owned),
                auth_provider: None,
                issuer: None,
                roles: Vec::new(),
                groups: Vec::new(),
                scopes: Vec::new(),
                attributes: BTreeMap::new(),
            },
            transport: "http".into(),
        }
    }

    #[test]
    fn allows_within_limit() {
        let plugin = RateLimitPlugin::from_config(&serde_json::json!({
            "default_limit": 5,
            "default_window_ms": 60
        }))
        .unwrap();

        let ctx = test_ctx("my_tool", Some("user-1"), None);
        for _ in 0..5 {
            let decision =
                plugin.evaluate_pre(&ctx, &serde_json::json!({}), None, &serde_json::json!({}));
            assert!(decision.is_allow(), "should allow within limit");
        }
    }

    #[test]
    fn denies_when_limit_exceeded() {
        let plugin = RateLimitPlugin::from_config(&serde_json::json!({
            "default_limit": 3,
            "default_window_ms": 60
        }))
        .unwrap();

        let ctx = test_ctx("my_tool", Some("user-1"), None);
        // Consume all tokens
        for _ in 0..3 {
            plugin.evaluate_pre(&ctx, &serde_json::json!({}), None, &serde_json::json!({}));
        }
        // 4th should be denied
        let decision =
            plugin.evaluate_pre(&ctx, &serde_json::json!({}), None, &serde_json::json!({}));
        match decision {
            GateDecision::Deny {
                http_status, code, ..
            } => {
                assert_eq!(http_status, 429);
                assert_eq!(code, -32029);
            }
            _ => panic!("expected deny"),
        }
    }

    #[test]
    fn per_principal_isolation() {
        let plugin = RateLimitPlugin::from_config(&serde_json::json!({
            "default_limit": 2,
            "default_window_ms": 60
        }))
        .unwrap();

        let ctx_a = test_ctx("tool", Some("user-a"), None);
        let ctx_b = test_ctx("tool", Some("user-b"), None);

        // Exhaust user-a
        for _ in 0..2 {
            plugin.evaluate_pre(&ctx_a, &serde_json::json!({}), None, &serde_json::json!({}));
        }
        let denied =
            plugin.evaluate_pre(&ctx_a, &serde_json::json!({}), None, &serde_json::json!({}));
        assert!(!denied.is_allow());

        // user-b should still be allowed
        let allowed =
            plugin.evaluate_pre(&ctx_b, &serde_json::json!({}), None, &serde_json::json!({}));
        assert!(allowed.is_allow());
    }

    #[test]
    fn per_tool_rule_overrides_default() {
        let plugin = RateLimitPlugin::from_config(&serde_json::json!({
            "default_limit": 100,
            "default_window_ms": 60,
            "rules": [{
                "tools": ["expensive.*"],
                "scope": "per_principal",
                "limit": 2,
                "window_ms": 60
            }]
        }))
        .unwrap();

        let ctx_expensive = test_ctx("expensive.compute", Some("user-1"), None);
        let ctx_normal = test_ctx("normal.tool", Some("user-2"), None);

        // Expensive tool: limit 2
        for _ in 0..2 {
            let d = plugin.evaluate_pre(
                &ctx_expensive,
                &serde_json::json!({}),
                None,
                &serde_json::json!({}),
            );
            assert!(d.is_allow());
        }
        let denied = plugin.evaluate_pre(
            &ctx_expensive,
            &serde_json::json!({}),
            None,
            &serde_json::json!({}),
        );
        assert!(!denied.is_allow());

        // Normal tool: default limit 100, should still be allowed
        let allowed = plugin.evaluate_pre(
            &ctx_normal,
            &serde_json::json!({}),
            None,
            &serde_json::json!({}),
        );
        assert!(allowed.is_allow());
    }

    #[test]
    fn global_scope_shares_bucket() {
        let plugin = RateLimitPlugin::from_config(&serde_json::json!({
            "default_limit": 100,
            "rules": [{
                "tools": ["shared.*"],
                "scope": "global",
                "limit": 3,
                "window_ms": 60
            }]
        }))
        .unwrap();

        let ctx_a = test_ctx("shared.resource", Some("user-a"), None);
        let ctx_b = test_ctx("shared.resource", Some("user-b"), None);

        // 3 calls total regardless of user
        plugin.evaluate_pre(&ctx_a, &serde_json::json!({}), None, &serde_json::json!({}));
        plugin.evaluate_pre(&ctx_b, &serde_json::json!({}), None, &serde_json::json!({}));
        plugin.evaluate_pre(&ctx_a, &serde_json::json!({}), None, &serde_json::json!({}));

        let denied =
            plugin.evaluate_pre(&ctx_b, &serde_json::json!({}), None, &serde_json::json!({}));
        assert!(!denied.is_allow(), "shared global limit should be exceeded");
    }

    #[test]
    fn session_scope_keys_by_session() {
        let plugin = RateLimitPlugin::from_config(&serde_json::json!({
            "rules": [{
                "tools": ["*"],
                "scope": "per_session",
                "limit": 2,
                "window_ms": 60
            }]
        }))
        .unwrap();

        let ctx_s1 = test_ctx("tool", Some("user-1"), Some("session-1"));
        let ctx_s2 = test_ctx("tool", Some("user-1"), Some("session-2"));

        // Exhaust session-1
        for _ in 0..2 {
            plugin.evaluate_pre(
                &ctx_s1,
                &serde_json::json!({}),
                None,
                &serde_json::json!({}),
            );
        }
        let denied = plugin.evaluate_pre(
            &ctx_s1,
            &serde_json::json!({}),
            None,
            &serde_json::json!({}),
        );
        assert!(!denied.is_allow());

        // session-2 should be fine
        let allowed = plugin.evaluate_pre(
            &ctx_s2,
            &serde_json::json!({}),
            None,
            &serde_json::json!({}),
        );
        assert!(allowed.is_allow());
    }

    #[test]
    fn burst_allows_extra_tokens() {
        let plugin = RateLimitPlugin::from_config(&serde_json::json!({
            "default_limit": 2,
            "default_window_ms": 60,
            "default_burst": 5
        }))
        .unwrap();

        let ctx = test_ctx("tool", Some("user-1"), None);
        // Burst capacity = 5, so 5 requests should pass initially
        for i in 0..5 {
            let d = plugin.evaluate_pre(&ctx, &serde_json::json!({}), None, &serde_json::json!({}));
            assert!(d.is_allow(), "request {i} should be allowed within burst");
        }
        // 6th should be denied
        let denied =
            plugin.evaluate_pre(&ctx, &serde_json::json!({}), None, &serde_json::json!({}));
        assert!(!denied.is_allow());
    }

    #[test]
    fn anonymous_uses_session_fallback() {
        let plugin = RateLimitPlugin::from_config(&serde_json::json!({
            "default_limit": 2,
            "default_window_ms": 60
        }))
        .unwrap();

        let ctx = test_ctx("tool", None, Some("session-anon"));

        for _ in 0..2 {
            let d = plugin.evaluate_pre(&ctx, &serde_json::json!({}), None, &serde_json::json!({}));
            assert!(d.is_allow());
        }
        let denied =
            plugin.evaluate_pre(&ctx, &serde_json::json!({}), None, &serde_json::json!({}));
        assert!(!denied.is_allow());
    }

    #[test]
    fn glob_match_patterns() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("admin.*", "admin.delete"));
        assert!(glob_match("admin.*", "admin."));
        assert!(!glob_match("admin.*", "user.delete"));
        assert!(glob_match("*.info", "system.info"));
        assert!(!glob_match("*.info", "system.stats"));
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "other"));
    }

    #[test]
    fn empty_config_json_uses_defaults() {
        // An empty / absent operator `config:` block opts out of
        // tuning and must yield Default (not a parse error).
        let plugin = RateLimitPlugin::from_config_json("{}");
        assert_eq!(plugin.config.default_limit, default_limit());
        assert_eq!(plugin.config.default_window_ms, default_window_ms());
        assert_eq!(
            plugin.config.cleanup_interval_ms,
            default_cleanup_interval_ms()
        );
        assert!(plugin.config.rules.is_empty());
    }

    #[test]
    #[should_panic(expected = "failing closed")]
    fn malformed_config_json_fails_closed() {
        // A present-but-unparseable config must refuse the plugin
        // (fail closed) rather than silently degrade to permissive
        // defaults.
        let _ = RateLimitPlugin::from_config_json("not json");
    }

    #[test]
    fn unknown_top_level_key_is_rejected() {
        // A stray / renamed / typo'd config key must become a parse
        // error (fail-closed via `deny_unknown_fields`) rather than
        // being silently ignored — a typo in a reliability-critical
        // knob should refuse the plugin, not degrade quietly.
        let err = RateLimitPlugin::from_config(&serde_json::json!({
            "default_limit": 5,
            "default_window_ms": 60,
            // typo'd: the real field is `cleanup_interval_ms`
            "cleanup_intervall_ms": 1000
        }));
        assert!(
            err.is_err(),
            "unknown top-level config key must be rejected"
        );
    }

    #[test]
    fn unknown_rule_key_is_rejected() {
        // Same fail-closed contract for the nested per-tool rule struct.
        let err = RateLimitPlugin::from_config(&serde_json::json!({
            "rules": [{
                "tools": ["*"],
                "limit": 5,
                // typo'd: the real field is `window_ms`
                "windows_ms": 60
            }]
        }));
        assert!(
            err.is_err(),
            "unknown nested rule config key must be rejected"
        );
    }

    #[test]
    fn config_deserialization() {
        let config: RateLimitConfig = serde_json::from_value(serde_json::json!({
            "default_limit": 50,
            "default_window_ms": 120,
            "rules": [{
                "tools": ["admin.*"],
                "scope": "per_principal_tool",
                "limit": 5,
                "window_ms": 60,
                "burst": 10
            }]
        }))
        .unwrap();

        assert_eq!(config.default_limit, 50);
        assert_eq!(config.default_window_ms, 120);
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].scope, RateLimitScope::PerPrincipalTool);
        assert_eq!(config.rules[0].burst, Some(10));
    }
}
