use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since_epoch| since_epoch.as_secs())
}

pub(crate) fn unix_seconds_now_signed() -> i64 {
    i64::try_from(unix_seconds_now()).unwrap_or(i64::MAX)
}
