use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    refilled: Instant,
}

/// One token bucket per caller: `allowed` actions per `period`, with a burst of the same size.
#[derive(Debug)]
pub(crate) struct RateLimiter {
    period: Duration,
    buckets: HashMap<String, Bucket>,
}

impl RateLimiter {
    pub(crate) fn per(period: Duration) -> Self {
        Self {
            period,
            buckets: HashMap::new(),
        }
    }

    pub(crate) fn allow(&mut self, caller: &str, allowed: u32, now: Instant) -> bool {
        let capacity = f64::from(allowed);
        let bucket = self.buckets.entry(caller.to_owned()).or_insert(Bucket {
            tokens: capacity,
            refilled: now,
        });
        let elapsed = now.saturating_duration_since(bucket.refilled);
        let refill = elapsed.as_secs_f64() / self.period.as_secs_f64().max(f64::EPSILON);
        bucket.tokens = (bucket.tokens + refill * capacity).min(capacity);
        bucket.refilled = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_burst_is_allowed_then_refilled_over_the_period() {
        let mut limiter = RateLimiter::per(Duration::from_secs(60));
        let start = Instant::now();
        assert!((0..6).all(|_| limiter.allow("agent", 6, start)));
        assert!(!limiter.allow("agent", 6, start));
        assert!(limiter.allow("other", 6, start));
        assert!(limiter.allow("agent", 6, start + Duration::from_secs(10)));
        assert!(!limiter.allow("agent", 6, start + Duration::from_secs(10)));
    }

    #[test]
    fn zero_allows_nothing() {
        let mut limiter = RateLimiter::per(Duration::from_secs(60));
        assert!(!limiter.allow("agent", 0, Instant::now()));
    }
}
