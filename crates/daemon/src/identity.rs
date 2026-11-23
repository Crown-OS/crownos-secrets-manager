//! Who is calling. For now the caller is the executable of the peer process. A later crownos-ipc
//! gives a pidfd from `SO_PEERPIDFD` and crownos-config an `AppKey`; only this module changes then.

use std::fmt;
use std::os::fd::OwnedFd;
use std::path::Path;

use crownos_ipc::Credentials;
use rustix::event::{PollFd, PollFlags, Timespec, poll};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    app_key: Option<String>,
}

impl Caller {
    pub fn from_executable(executable: &Path) -> Self {
        Self {
            app_key: executable.to_str().map(str::to_owned),
        }
    }

    pub const fn unidentified() -> Self {
        Self { app_key: None }
    }

    /// The key that bindings and the admin list name. `None` matches nothing.
    pub fn app_key(&self) -> Option<&str> {
        self.app_key.as_deref()
    }

    pub fn is_any_of(&self, app_keys: &[String]) -> bool {
        self.app_key()
            .is_some_and(|app_key| app_keys.iter().any(|allowed| allowed == app_key))
    }
}

impl fmt::Display for Caller {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.app_key().unwrap_or("unidentified"))
    }
}

pub trait IdentifyCaller {
    fn identify(&self, credentials: &Credentials) -> Caller;
}

/// The caller is the target of `/proc/<pid>/exe`, read while the pidfd shows that the process
/// that connected still runs. This names the program the peer runs now. It does not stop a
/// process that connects and then runs `exec`, or that hands its socket to another process. So
/// the name is a second layer: admin calls that change the vault also need the master password.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcExecutableIdentity;

impl IdentifyCaller for ProcExecutableIdentity {
    fn identify(&self, credentials: &Credentials) -> Caller {
        let Some(pidfd) = credentials.pidfd.as_ref() else {
            return Caller::unidentified();
        };
        let executable = std::fs::read_link(format!("/proc/{}/exe", credentials.pid));
        match executable {
            Ok(executable) if process_still_runs(pidfd) => Caller::from_executable(&executable),
            _ => Caller::unidentified(),
        }
    }
}

/// A pidfd becomes readable when its process exits.
fn process_still_runs(pidfd: &OwnedFd) -> bool {
    let mut descriptors = [PollFd::new(pidfd, PollFlags::IN)];
    let no_wait = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    matches!(poll(&mut descriptors, Some(&no_wait)), Ok(0))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::os::unix::net::UnixStream;

    use super::*;

    #[test]
    fn a_live_peer_is_named_by_its_executable() {
        let (ours, _theirs) = UnixStream::pair().unwrap();
        let credentials = rustix::net::sockopt::socket_peercred(&ours).unwrap();
        let credentials = Credentials {
            uid: credentials.uid.as_raw(),
            gid: credentials.gid.as_raw(),
            pid: credentials.pid.as_raw_nonzero().get(),
            pidfd: rustix::process::pidfd_open(
                credentials.pid,
                rustix::process::PidfdFlags::empty(),
            )
            .ok(),
        };
        let caller = ProcExecutableIdentity.identify(&credentials);
        let executable = std::env::current_exe().unwrap();
        assert_eq!(caller, Caller::from_executable(&executable));
    }

    #[test]
    fn an_unidentified_caller_matches_no_list() {
        assert!(!Caller::unidentified().is_any_of(&[String::new()]));
        assert_eq!(Caller::unidentified().to_string(), "unidentified");
    }
}
