//! Rate limiting: in-memory (single replica) and Redis-backed (shared across replicas).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;

use crate::error::BrokerError;

/// Per-tenant request limiter.
#[async_trait]
pub trait RateLimiter: Send + Sync {
    /// Returns `false` when the caller should be throttled.
    async fn allow_per_minute(&self, key: &str, per_minute: u32) -> bool;

    /// Whether this limiter is shared across replicas.
    fn distributed(&self) -> bool {
        false
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── In-memory token bucket ──────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    last_ms: u64,
}

/// Local token-bucket limiter. Bounds memory by resetting when too many keys accrue.
pub struct MemoryRateLimiter {
    buckets: Mutex<HashMap<String, Bucket>>,
    max_keys: usize,
}

const DEFAULT_MAX_KEYS: usize = 50_000;
/// Buckets untouched for this long are evicted first when the limiter is at capacity.
const IDLE_MS: u64 = 120_000;

impl Default for MemoryRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryRateLimiter {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_KEYS)
    }

    pub fn with_capacity(max_keys: usize) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            max_keys: max_keys.max(1),
        }
    }

    /// Evict stale buckets when at capacity: idle keys first (a mass clear would reset the
    /// limits of every caller, including the attacker), then the least-recently-used.
    fn evict(buckets: &mut HashMap<String, Bucket>, now_ms: u64, max_keys: usize) {
        let idle_cutoff = now_ms.saturating_sub(IDLE_MS);
        buckets.retain(|_, bucket| bucket.last_ms > idle_cutoff);
        while buckets.len() >= max_keys {
            let Some(oldest) = buckets
                .iter()
                .min_by_key(|(_, bucket)| bucket.last_ms)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            buckets.remove(&oldest);
        }
    }

    fn allow(&self, key: &str, capacity: f64, refill_per_sec: f64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let Ok(mut buckets) = self.buckets.lock() else {
            return true; // fail open on poison
        };
        if buckets.len() >= self.max_keys {
            Self::evict(&mut buckets, now, self.max_keys);
        }
        let bucket = buckets.entry(key.to_string()).or_insert(Bucket {
            tokens: capacity,
            last_ms: now,
        });
        let elapsed = now.saturating_sub(bucket.last_ms) as f64 / 1000.0;
        bucket.tokens = (bucket.tokens + elapsed * refill_per_sec).min(capacity);
        bucket.last_ms = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[async_trait]
impl RateLimiter for MemoryRateLimiter {
    async fn allow_per_minute(&self, key: &str, per_minute: u32) -> bool {
        let cap = per_minute as f64;
        self.allow(key, cap, cap / 60.0)
    }
}

// ── Redis fixed-window limiter ──────────────────────────────────────────────

/// Shared fixed-window limiter (`INCR` + `EXPIRE` per tenant per minute).
pub struct RedisRateLimiter {
    manager: redis::aio::ConnectionManager,
}

impl RedisRateLimiter {
    pub async fn connect(url: &str) -> Result<Self, BrokerError> {
        let client = redis::Client::open(url)
            .map_err(|e| BrokerError::Internal(format!("redis client: {e}")))?;
        let manager = redis::aio::ConnectionManager::new(client)
            .await
            .map_err(|e| BrokerError::Internal(format!("redis connect: {e}")))?;
        Ok(Self { manager })
    }
}

#[async_trait]
impl RateLimiter for RedisRateLimiter {
    async fn allow_per_minute(&self, key: &str, per_minute: u32) -> bool {
        use redis::AsyncCommands;
        let window = now_secs() / 60;
        let redis_key = format!("tessera:rl:{key}:{window}");
        let mut conn = self.manager.clone();

        let count: i64 = match conn.incr(&redis_key, 1i64).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("redis rate-limit error, failing open: {e}");
                return true;
            }
        };
        if count == 1 {
            let _: Result<bool, _> = conn.expire(&redis_key, 60i64).await;
        }
        count <= per_minute as i64
    }

    fn distributed(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn allows_up_to_capacity_then_throttles() {
        let limiter = MemoryRateLimiter::new();
        assert!(limiter.allow_per_minute("acme", 2).await);
        assert!(limiter.allow_per_minute("acme", 2).await);
        assert!(!limiter.allow_per_minute("acme", 2).await);
    }

    #[tokio::test]
    async fn keys_are_isolated() {
        let limiter = MemoryRateLimiter::new();
        assert!(limiter.allow_per_minute("a", 1).await);
        assert!(!limiter.allow_per_minute("a", 1).await);
        assert!(limiter.allow_per_minute("b", 1).await);
    }

    #[test]
    fn capacity_eviction_keeps_recent_keys_and_resets_nothing_massively() {
        let limiter = MemoryRateLimiter::with_capacity(3);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        {
            let mut buckets = limiter.buckets.lock().unwrap();
            // Two hot (recent) buckets, one exhausted; two stale buckets past the idle window.
            buckets.insert(
                "hot:exhausted".into(),
                Bucket {
                    tokens: 0.0,
                    last_ms: now,
                },
            );
            buckets.insert(
                "hot:full".into(),
                Bucket {
                    tokens: 5.0,
                    last_ms: now - 1_000,
                },
            );
            buckets.insert(
                "idle:1".into(),
                Bucket {
                    tokens: 5.0,
                    last_ms: now - IDLE_MS - 1,
                },
            );
            buckets.insert(
                "idle:2".into(),
                Bucket {
                    tokens: 5.0,
                    last_ms: now - IDLE_MS - 60_000,
                },
            );
        }

        assert!(limiter.allow("new", 10.0, 1.0));

        let buckets = limiter.buckets.lock().unwrap();
        assert!(!buckets.contains_key("idle:1") && !buckets.contains_key("idle:2"));
        assert!(buckets.contains_key("hot:exhausted"));
        assert!(buckets.contains_key("hot:full"));
        assert!(buckets.contains_key("new"));
        drop(buckets);

        // The exhausted hot bucket was not reset to full by eviction.
        assert!(!limiter.allow("hot:exhausted", 1.0, 0.0));
    }

    #[tokio::test]
    async fn refills_over_time() {
        let limiter = MemoryRateLimiter::new();
        assert!(limiter.allow("k", 1.0, 1000.0));
        assert!(!limiter.allow("k", 1.0, 1000.0));
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(limiter.allow("k", 1.0, 1000.0));
    }
}
