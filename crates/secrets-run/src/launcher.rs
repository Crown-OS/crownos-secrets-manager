//! The sandbox runs as a transient service of the user manager, with its own memory limit and
//! run time, outside the daemon's cgroup and system call filter.

use std::path::PathBuf;
use std::process::Stdio;

use secrets_core::RunTemplate;
use tokio::process::Command;

use crate::SandboxError;

/// The programs that start a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launcher {
    pub systemd_run: PathBuf,
    pub systemctl: PathBuf,
    pub bwrap: PathBuf,
}

impl Default for Launcher {
    fn default() -> Self {
        Self {
            systemd_run: PathBuf::from("/usr/bin/systemd-run"),
            systemctl: PathBuf::from("/usr/bin/systemctl"),
            bwrap: PathBuf::from("/usr/bin/bwrap"),
        }
    }
}

/// A fresh unit name, so a stop reaches only this run.
pub(crate) fn unit_name() -> Result<String, SandboxError> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).map_err(|_| SandboxError::Random)?;
    let suffix: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!("crownos-secrets-run-{suffix}.service"))
}

/// `systemd-run` and its arguments up to the bwrap command line. No value is here: values go
/// through standard input, which `--pipe` hands to bwrap.
pub(crate) fn systemd_run_arguments(
    launcher: &Launcher,
    template: &RunTemplate,
    unit: &str,
) -> Vec<String> {
    let run_time = template.timeout_seconds.saturating_add(5);
    [
        "--user",
        "--pipe",
        "--wait",
        "--collect",
        "--quiet",
        "--service-type=exec",
    ]
    .iter()
    .map(|part| (*part).to_owned())
    .chain([
        format!("--unit={unit}"),
        format!("--property=MemoryMax={}M", template.memory_max_megabytes),
        "--property=MemorySwapMax=0".to_owned(),
        format!("--property=RuntimeMaxSec={run_time}"),
        "--property=TimeoutStopSec=2".to_owned(),
        "--property=LimitCORE=0".to_owned(),
        "--property=TasksMax=256".to_owned(),
        "--property=NoNewPrivileges=yes".to_owned(),
        "--".to_owned(),
        launcher.bwrap.to_string_lossy().into_owned(),
        "--args".to_owned(),
        "0".to_owned(),
    ])
    .collect()
}

/// The user manager is found through the real runtime directory of the user, also when the
/// daemon runs with another `XDG_RUNTIME_DIR`. Nothing else of the daemon's environment goes on.
pub(crate) fn user_manager_environment() -> [(&'static str, String); 2] {
    let runtime = format!("/run/user/{}", rustix::process::getuid().as_raw());
    [
        (
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={runtime}/bus"),
        ),
        ("XDG_RUNTIME_DIR", runtime),
    ]
}

/// Stops the unit of a run that went over a limit.
pub(crate) async fn stop(launcher: &Launcher, unit: &str) {
    let stopped = Command::new(&launcher.systemctl)
        .args(["--user", "stop", unit])
        .env_clear()
        .envs(user_manager_environment())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
    if stopped.is_err() {
        tracing::warn!(unit, "cannot stop a run unit");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_unit_has_limits_and_no_value() {
        let template = RunTemplate {
            timeout_seconds: 30,
            memory_max_megabytes: 64,
            ..RunTemplate::default()
        };
        let arguments = systemd_run_arguments(&Launcher::default(), &template, "unit-x.service");
        assert!(arguments.contains(&"--pipe".to_owned()));
        assert!(arguments.contains(&"--property=MemoryMax=64M".to_owned()));
        assert!(arguments.contains(&"--property=RuntimeMaxSec=35".to_owned()));
        assert_eq!(arguments.last().unwrap(), "0");
        let environment = user_manager_environment();
        assert!(
            environment
                .iter()
                .all(|(name, _)| name.starts_with("DBUS") || name.starts_with("XDG"))
        );
    }
}
