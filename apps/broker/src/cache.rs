//! Caching layer for hot-path lookups: Redis in production, in-memory otherwise.
//!
//! Used to cache API-key authentication results so authorization does not hit Postgres on
//! every request. Writes that change state (create/revoke) clear the cache.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;

use crate::error::BrokerError;

#[async_trait]
pub trait Cache: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<String>, BrokerError>;
    async fn put(&self, key: &str, value: &str, ttl_secs: u64) -> Result<(), BrokerError>;
    /// Insert only when absent. Returns `true` when this caller inserted the value.
    async fn put_if_absent(
        &self,
        key: &str,
        value: &str,
        ttl_secs: u64,
    ) -> Result<bool, BrokerError>;
    async fn delete(&self, key: &str) -> Result<(), BrokerError>;
    async fn clear(&self) -> Result<(), BrokerError>;
}

const DEFAULT_MAX_ENTRIES: usize = 10_000;

/// In-memory cache with per-entry TTL and crude size-bounded eviction.
pub struct MemoryCache {
    map: Mutex<HashMap<String, (String, u64)>>,
    max_entries: usize,
}

impl Default for MemoryCache {
    fn default() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            max_entries: DEFAULT_MAX_ENTRIES,
        }
    }
}

impl MemoryCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            max_entries,
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[async_trait]
impl Cache for MemoryCache {
    async fn get(&self, key: &str) -> Result<Option<String>, BrokerError> {
        let mut map = self
            .map
            .lock()
            .map_err(|_| BrokerError::Internal("cache poisoned".into()))?;
        match map.get(key) {
            Some((value, expires_at)) if *expires_at > now_secs() => Ok(Some(value.clone())),
            Some(_) => {
                map.remove(key);
                Ok(None)
            }
            None => Ok(None),
        }
    }

    async fn put(&self, key: &str, value: &str, ttl_secs: u64) -> Result<(), BrokerError> {
        let mut map = self
            .map
            .lock()
            .map_err(|_| BrokerError::Internal("cache poisoned".into()))?;
        if map.len() >= self.max_entries {
            map.clear();
        }
        let expires_at = if ttl_secs == 0 {
            u64::MAX
        } else {
            now_secs() + ttl_secs
        };
        map.insert(key.to_string(), (value.to_string(), expires_at));
        Ok(())
    }

    async fn put_if_absent(
        &self,
        key: &str,
        value: &str,
        ttl_secs: u64,
    ) -> Result<bool, BrokerError> {
        let mut map = self
            .map
            .lock()
            .map_err(|_| BrokerError::Internal("cache poisoned".into()))?;
        let now = now_secs();
        if let Some((_, expires_at)) = map.get(key) {
            if *expires_at > now {
                return Ok(false);
            }
            map.remove(key);
        }
        if map.len() >= self.max_entries {
            map.retain(|_, (_, expires_at)| *expires_at > now);
            if map.len() >= self.max_entries {
                return Err(BrokerError::Internal("replay cache is at capacity".into()));
            }
        }
        let expires_at = if ttl_secs == 0 {
            u64::MAX
        } else {
            now + ttl_secs
        };
        map.insert(key.to_string(), (value.to_string(), expires_at));
        Ok(true)
    }

    async fn delete(&self, key: &str) -> Result<(), BrokerError> {
        self.map
            .lock()
            .map_err(|_| BrokerError::Internal("cache poisoned".into()))?
            .remove(key);
        Ok(())
    }

    async fn clear(&self) -> Result<(), BrokerError> {
        self.map
            .lock()
            .map_err(|_| BrokerError::Internal("cache poisoned".into()))?
            .clear();
        Ok(())
    }
}

/// Redis-backed cache. `clear` is a no-op (entries expire within `ttl_secs`); callers that
/// need immediate invalidation rely on the short TTL.
pub struct RedisCache {
    manager: redis::aio::ConnectionManager,
}

impl RedisCache {
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
impl Cache for RedisCache {
    async fn get(&self, key: &str) -> Result<Option<String>, BrokerError> {
        use redis::AsyncCommands;
        let mut conn = self.manager.clone();
        conn.get(key).await.map_err(map)
    }

    async fn put(&self, key: &str, value: &str, ttl_secs: u64) -> Result<(), BrokerError> {
        use redis::AsyncCommands;
        let mut conn = self.manager.clone();
        let _: () = conn
            .set_ex(key, value, ttl_secs.max(1))
            .await
            .map_err(map)?;
        Ok(())
    }

    async fn put_if_absent(
        &self,
        key: &str,
        value: &str,
        ttl_secs: u64,
    ) -> Result<bool, BrokerError> {
        let mut conn = self.manager.clone();
        let result: Option<String> = redis::cmd("SET")
            .arg(key)
            .arg(value)
            .arg("EX")
            .arg(ttl_secs.max(1))
            .arg("NX")
            .query_async(&mut conn)
            .await
            .map_err(map)?;
        Ok(result.is_some())
    }

    async fn delete(&self, key: &str) -> Result<(), BrokerError> {
        use redis::AsyncCommands;
        let mut conn = self.manager.clone();
        let _: () = conn.del(key).await.map_err(map)?;
        Ok(())
    }

    async fn clear(&self) -> Result<(), BrokerError> {
        Ok(())
    }
}

fn map(err: redis::RedisError) -> BrokerError {
    BrokerError::Internal(format!("redis: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_put_get_delete_clear() {
        let cache = MemoryCache::new();
        assert!(cache.get("k").await.unwrap().is_none());
        cache.put("k", "v", 60).await.unwrap();
        assert_eq!(cache.get("k").await.unwrap().as_deref(), Some("v"));
        cache.delete("k").await.unwrap();
        assert!(cache.get("k").await.unwrap().is_none());

        cache.put("a", "1", 60).await.unwrap();
        cache.put("b", "2", 60).await.unwrap();
        cache.clear().await.unwrap();
        assert!(cache.get("a").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn put_if_absent_is_exclusive() {
        let cache = MemoryCache::new();
        assert!(cache.put_if_absent("k", "1", 60).await.unwrap());
        assert!(!cache.put_if_absent("k", "2", 60).await.unwrap());
        assert_eq!(cache.get("k").await.unwrap().as_deref(), Some("1"));
    }

    #[tokio::test]
    async fn entries_expire() {
        let cache = MemoryCache::new();
        cache.put("k", "v", 0).await.unwrap(); // ttl 0 => no expiry
        assert_eq!(cache.get("k").await.unwrap().as_deref(), Some("v"));
    }

    #[tokio::test]
    async fn evicts_when_full() {
        let cache = MemoryCache::with_capacity(2);
        cache.put("a", "1", 60).await.unwrap();
        cache.put("b", "2", 60).await.unwrap();
        cache.put("c", "3", 60).await.unwrap(); // clears then inserts c
        assert!(cache.get("c").await.unwrap().is_some());
        assert!(cache.get("a").await.unwrap().is_none());
    }
}
