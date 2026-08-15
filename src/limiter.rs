//! Token bucket rate limiter with DashMap-backed state.

use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// How many newly-created buckets trigger one opportunistic sweep. A
/// fixed cadence bounds the worst-case overshoot to this many idle
/// buckets between sweeps, independent of config.
const EVICT_CHECK_INTERVAL: u64 = 256;

/// Thread-safe rate limit state backed by DashMap.
#[derive(Default)]
pub struct RateLimitState {
    buckets: DashMap<String, TokenBucket>,
    /// New-bucket counter for opportunistic eviction. Every
    /// [`EVICT_CHECK_INTERVAL`] insertions we sweep buckets idle longer
    /// than [`Self::max_idle_ms`], so the advertised `cleanup_interval_ms`
    /// knob has effect WITHOUT a background task (the FFI surface is sync
    /// and the plugin owns no runtime) — mirroring the response-cache
    /// opportunistic-eviction pattern.
    inserts_since_sweep: AtomicU64,
    /// Buckets untouched for longer than this are evictable. `0` disables
    /// auto-eviction (the default-constructed state used by tests, which
    /// drive `cleanup()` directly).
    max_idle_ms: u64,
}

impl RateLimitState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct with opportunistic eviction wired from operator config.
    /// `max_idle_ms` is the idle threshold (the plugin passes
    /// `cleanup_interval_ms`); `0` disables auto-eviction.
    pub fn with_eviction(max_idle_ms: u64) -> Self {
        Self {
            buckets: DashMap::new(),
            inserts_since_sweep: AtomicU64::new(0),
            max_idle_ms,
        }
    }

    /// Check (and consume one token from) the bucket for `key`.
    /// Creates a new bucket if none exists, then opportunistically sweeps
    /// idle buckets so the map can't grow unbounded.
    pub(crate) fn check(
        &self,
        key: &str,
        capacity: u64,
        refill_rate: f64,
        window_ms: u64,
    ) -> super::LimitResult {
        use dashmap::mapref::entry::Entry;
        // Compute the result inside a scope so the per-shard entry guard
        // is dropped BEFORE any `cleanup()` sweep — `DashMap::retain`
        // locks every shard and would deadlock against a held guard.
        let (result, inserted) = match self.buckets.entry(key.to_owned()) {
            Entry::Occupied(mut e) => (e.get_mut().try_consume(capacity, refill_rate), false),
            Entry::Vacant(v) => {
                let mut bucket = TokenBucket::new(capacity, refill_rate, window_ms);
                let r = bucket.try_consume(capacity, refill_rate);
                v.insert(bucket);
                (r, true)
            }
        };
        if inserted {
            self.maybe_evict();
        }
        result
    }

    /// Opportunistic eviction tick: bump the insert counter and, every
    /// [`EVICT_CHECK_INTERVAL`] new buckets, sweep idle entries. No-op
    /// when auto-eviction is disabled (`max_idle_ms == 0`).
    fn maybe_evict(&self) {
        if self.max_idle_ms == 0 {
            return;
        }
        let n = self.inserts_since_sweep.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= EVICT_CHECK_INTERVAL {
            // Approximate cadence — Relaxed is fine. The thread that
            // resets the counter performs the (single) sweep.
            self.inserts_since_sweep.store(0, Ordering::Relaxed);
            self.cleanup(self.max_idle_ms);
        }
    }

    /// Remove expired entries. Call periodically to prevent unbounded growth.
    /// `max_idle_ms` is milliseconds (matches the config's `_ms` fields) — the
    /// idle duration is compared in milliseconds, not seconds.
    pub fn cleanup(&self, max_idle_ms: u64) {
        let now = Instant::now();
        self.buckets.retain(|_, bucket| {
            (now.duration_since(bucket.last_access).as_millis() as u64) < max_idle_ms
        });
    }

    /// Number of tracked keys (for testing/metrics).
    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    /// True when no buckets have been created. Provided so clippy's
    /// `len_without_is_empty` lint is satisfied — the metric is the
    /// main use.
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }
}

/// Token bucket algorithm.
///
/// Tokens refill at a constant rate. Each request consumes one token.
/// When tokens reach zero, requests are denied until enough refill.
#[derive(Debug)]
pub struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    last_access: Instant,
    window_ms: u64,
}

impl TokenBucket {
    fn new(capacity: u64, _refill_rate: f64, window_ms: u64) -> Self {
        Self {
            tokens: capacity as f64,
            last_refill: Instant::now(),
            last_access: Instant::now(),
            window_ms,
        }
    }

    fn try_consume(&mut self, capacity: u64, refill_rate: f64) -> super::LimitResult {
        self.last_access = Instant::now();
        self.refill(capacity, refill_rate);

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            super::LimitResult {
                allowed: true,
                remaining: self.tokens.floor() as u64,
                limit: capacity,
                retry_after_secs: 0.0,
            }
        } else {
            // Calculate when the next token will be available. refill_rate is
            // tokens/ms, so deficit/refill_rate is milliseconds → /1000 for the
            // seconds field. (window_ms is likewise ms → seconds.)
            let deficit = 1.0 - self.tokens;
            let retry_after = if refill_rate > 0.0 {
                (deficit / refill_rate) / 1000.0
            } else {
                self.window_ms as f64 / 1000.0
            };
            super::LimitResult {
                allowed: false,
                remaining: 0,
                limit: capacity,
                retry_after_secs: retry_after,
            }
        }
    }

    fn refill(&mut self, capacity: u64, refill_rate: f64) {
        let now = Instant::now();
        // refill_rate is tokens-per-MILLISECOND, so accrue against elapsed
        // milliseconds (not seconds — that was the 1000x under-refill bug).
        let elapsed_ms = now.duration_since(self.last_refill).as_secs_f64() * 1000.0;
        if elapsed_ms > 0.0 {
            self.tokens = (self.tokens + elapsed_ms * refill_rate).min(capacity as f64);
            self.last_refill = now;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_bucket_starts_full() {
        let state = RateLimitState::new();
        let result = state.check("key1", 10, 1.0, 60);
        assert!(result.allowed);
        assert_eq!(result.remaining, 9);
    }

    #[test]
    fn exhaustion_denies() {
        let state = RateLimitState::new();
        for _ in 0..5 {
            let r = state.check("key1", 5, 1.0, 60);
            assert!(r.allowed);
        }
        let r = state.check("key1", 5, 1.0, 60);
        assert!(!r.allowed);
        assert!(r.retry_after_secs > 0.0);
    }

    #[test]
    fn different_keys_are_isolated() {
        let state = RateLimitState::new();
        for _ in 0..3 {
            state.check("a", 3, 1.0, 60);
        }
        assert!(!state.check("a", 3, 1.0, 60).allowed);
        assert!(state.check("b", 3, 1.0, 60).allowed);
    }

    #[test]
    fn cleanup_removes_idle_entries() {
        let state = RateLimitState::new();
        state.check("active", 10, 1.0, 60);
        assert_eq!(state.len(), 1);
        // With max_idle_ms=0, everything is "idle"
        state.cleanup(0);
        assert_eq!(state.len(), 0);
    }

    #[test]
    fn opportunistic_eviction_sweeps_idle_buckets() {
        // 1ms idle threshold so the early buckets are evictable after a
        // short sleep.
        let state = RateLimitState::with_eviction(1);
        // Fill to just below the sweep threshold — no sweep fires yet.
        for i in 0..(EVICT_CHECK_INTERVAL - 1) {
            state.check(&format!("k{i}"), 10, 1.0, 60);
        }
        assert_eq!(state.len() as u64, EVICT_CHECK_INTERVAL - 1);
        // Let those buckets go idle past the threshold.
        std::thread::sleep(std::time::Duration::from_millis(5));
        // The next new bucket crosses EVICT_CHECK_INTERVAL and triggers a
        // sweep; every idle bucket is evicted, only the just-created one
        // (last_access ≈ now) survives.
        state.check("trigger", 10, 1.0, 60);
        assert_eq!(
            state.len(),
            1,
            "idle buckets must be swept on the eviction tick"
        );
    }

    #[test]
    fn auto_eviction_disabled_without_config() {
        // `new()` / `default()` leave max_idle_ms = 0 → no auto-eviction;
        // the map grows past the sweep threshold (tests drive cleanup()
        // directly). Guards against the eviction tick nuking a default state.
        let state = RateLimitState::new();
        for i in 0..(EVICT_CHECK_INTERVAL + 10) {
            state.check(&format!("k{i}"), 10, 1.0, 60);
        }
        assert_eq!(state.len() as u64, EVICT_CHECK_INTERVAL + 10);
    }

    // Regression: refill accrues tokens PER MILLISECOND. `check_limit` passes
    // refill_rate = limit/window_ms; here 1000/1000 = 1 token/ms. Drain the
    // single-token bucket, then after a 5ms sleep it must allow again (≈5
    // tokens refilled). Under the previous per-SECOND refill this accrued only
    // ~0.005 tokens and stayed denied — a 1000x under-refill.
    #[test]
    fn refill_accrues_tokens_per_millisecond() {
        let state = RateLimitState::new();
        let refill_rate = 1000.0 / 1000.0; // tokens/ms, as check_limit computes
        assert!(state.check("k", 1, refill_rate, 1000).allowed);
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(
            state.check("k", 1, refill_rate, 1000).allowed,
            "refill must accrue tokens per millisecond, not per second"
        );
    }
}
