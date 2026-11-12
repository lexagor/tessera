//! Redis-backed rate limiter (skipped unless REDIS_URL is set).

use std::time::{SystemTime, UNIX_EPOCH};

use tessera_broker::cache::{Cache, RedisCache};
use tessera_broker::ratelimit::{RateLimiter, RedisRateLimiter};

fn unique_key() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("t{nanos}")
}

#[tokio::test]
async fn redis_fixed_window_limiter() {
    let Ok(url) = std::env::var("REDIS_URL") else {
        eprintln!("skipping: REDIS_URL not set");
        return;
    };
    let limiter = RedisRateLimiter::connect(&url).await.unwrap();
    assert!(limiter.distributed());

    let key = unique_key();
    assert!(limiter.allow_per_minute(&key, 2).await);
    assert!(limiter.allow_per_minute(&key, 2).await);
    assert!(
        !limiter.allow_per_minute(&key, 2).await,
        "third call throttled"
    );

    // different tenants are independent
    let other = unique_key();
    assert!(limiter.allow_per_minute(&other, 2).await);
}

#[tokio::test]
async fn redis_put_if_absent_is_exclusive() {
    let Ok(url) = std::env::var("REDIS_URL") else {
        eprintln!("skipping: REDIS_URL not set");
        return;
    };
    let cache = RedisCache::connect(&url).await.unwrap();
    let key = format!("tessera:test:replay:{}", unique_key());
    assert!(cache.put_if_absent(&key, "1", 60).await.unwrap());
    assert!(!cache.put_if_absent(&key, "2", 60).await.unwrap());
    cache.delete(&key).await.unwrap();
}
