//! Keeps secret bytes out of swap with `mlock`.
//!
//! A lock is never released: `mlock` works on whole pages, a page can hold other heap data or a
//! second value, and one `munlock` would release the page for all of them. So the locked set only
//! grows up to the heap pages that ever held a secret. When `RLIMIT_MEMLOCK` is reached, the bytes
//! stay unlocked and the daemon logs this one time. The unit file also sets `MemorySwapMax=0`.

use std::sync::atomic::{AtomicBool, Ordering};

use secrecy::SecretSlice;

static FAILURE_REPORTED: AtomicBool = AtomicBool::new(false);

pub(crate) fn keep_in_memory(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    match region::lock(bytes.as_ptr(), bytes.len()) {
        Ok(guard) => std::mem::forget(guard),
        Err(error) => {
            if !FAILURE_REPORTED.swap(true, Ordering::Relaxed) {
                tracing::warn!(%error, "cannot lock secret memory; it can go to swap");
            }
        }
    }
}

/// A copy of `value` in its own allocation, locked in memory.
pub(crate) fn locked_secret(value: &[u8]) -> SecretSlice<u8> {
    let secret = SecretSlice::from(value.to_vec());
    keep_in_memory(secrecy::ExposeSecret::expose_secret(&secret));
    secret
}
