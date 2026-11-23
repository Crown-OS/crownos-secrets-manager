use std::collections::HashMap;
use std::time::{Duration, Instant};

/// More callers than this, and the idle ones are forgotten.
const MAX_TRACKED_CALLERS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RateDecision {
    Allowed,
    /// `first` is true for the first refusal after an allowed call, so a flood logs one line.
    Refused {
        first: bool,
    },
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    refilled: Instant,
    refusing: bool,
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

    pub(crate) fn decide(&mut self, caller: &str, allowed: u32, now: Instant) -> RateDecision {
        let capacity = f64::from(allowed);
        if !self.buckets.contains_key(caller) {
            self.forget_idle_callers(now);
        }
        let period = self.period.as_secs_f64().max(f64::EPSILON);
        let bucket = self.buckets.entry(caller.to_owned()).or_insert(Bucket {
            tokens: capacity,
            refilled: now,
            refusing: false,
        });
        let elapsed = now.saturating_duration_since(bucket.refilled).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed / period * capacity).min(capacity);
        bucket.refilled = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            bucket.refusing = false;
            RateDecision::Allowed
        } else {
            let first = !bucket.refusing;
            bucket.refusing = true;
            RateDecision::Refused { first }
        }
    }

    /// A caller idle for a full period has a full bucket again, so forgetting it changes nothing.
    /// When all are busy, the one idle longest goes.
    fn forget_idle_callers(&mut self, now: Instant) {
        if self.buckets.len() < MAX_TRACKED_CALLERS {
            return;
        }
        let period = self.period;
        self.buckets
            .retain(|_, bucket| now.saturating_duration_since(bucket.refilled) < period);
        if self.buckets.len() >= MAX_TRACKED_CALLERS
            && let Some(oldest) = self
                .buckets
                .iter()
                .min_by_key(|(_, bucket)| bucket.refilled)
                .map(|(caller, _)| caller.clone())
        {
            self.buckets.remove(&oldest);
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
        assert!((0..6).all(|_| limiter.decide("agent", 6, start) == RateDecision::Allowed));
        assert_eq!(
            limiter.decide("agent", 6, start),
            RateDecision::Refused { first: true }
        );
        assert_eq!(
            limiter.decide("agent", 6, start),
            RateDecision::Refused { first: false }
        );
        assert_eq!(limiter.decide("other", 6, start), RateDecision::Allowed);
        let later = start + Duration::from_secs(10);
        assert_eq!(limiter.decide("agent", 6, later), RateDecision::Allowed);
    }

    #[test]
    fn the_caller_map_stays_bounded() {
        let mut limiter = RateLimiter::per(Duration::from_secs(60));
        let start = Instant::now();
        for caller in 0..1000 {
            limiter.decide(&caller.to_string(), 6, start);
        }
        assert!(limiter.buckets.len() <= MAX_TRACKED_CALLERS);
    }
}
