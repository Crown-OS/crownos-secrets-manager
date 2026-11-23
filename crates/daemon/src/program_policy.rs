//! Which programs may call a group of methods: the admin methods, where the master password is
//! the first gate and this the second, and the typing methods, which only computer-use calls.

use std::path::PathBuf;

use crownos_config::schema::AppKey;

use crate::Caller;

const INSTALLED_ADMIN_EXECUTABLES: [&str; 2] =
    ["/usr/bin/crownos-secrets", "/usr/bin/crownos-settings"];
const INSTALLED_TYPING_CALLERS: [&str; 1] = ["/usr/bin/crownos-computer-use"];

/// Debug builds also accept the paths in these variables, separated by `:`, without the
/// root-owned check.
#[cfg(debug_assertions)]
pub const DEBUG_ADMIN_EXECUTABLES_VARIABLE: &str = "CROWNOS_SECRETS_DEBUG_ADMIN_EXECUTABLES";
#[cfg(debug_assertions)]
pub const DEBUG_TYPING_CALLERS_VARIABLE: &str = "CROWNOS_SECRETS_DEBUG_TYPING_CALLERS";

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrustedProgram {
    path: PathBuf,
    /// The file and its directory must be owned by root and not writable by others, so no
    /// process of the user can put another program there.
    must_be_root_owned: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProgramPolicy {
    trusted: Vec<TrustedProgram>,
}

impl ProgramPolicy {
    /// The installed CLI and Settings app, which must be root-owned.
    pub fn installed_admins() -> Self {
        Self::installed(
            &INSTALLED_ADMIN_EXECUTABLES,
            #[cfg(debug_assertions)]
            DEBUG_ADMIN_EXECUTABLES_VARIABLE,
        )
    }

    /// The installed computer-use daemon, which must be root-owned.
    pub fn installed_typing_callers() -> Self {
        Self::installed(
            &INSTALLED_TYPING_CALLERS,
            #[cfg(debug_assertions)]
            DEBUG_TYPING_CALLERS_VARIABLE,
        )
    }

    fn installed(paths: &[&str], #[cfg(debug_assertions)] debug_variable: &str) -> Self {
        let mut trusted: Vec<TrustedProgram> = paths
            .iter()
            .map(|path| TrustedProgram {
                path: PathBuf::from(path),
                must_be_root_owned: true,
            })
            .collect();
        #[cfg(debug_assertions)]
        if let Ok(extra) = std::env::var(debug_variable) {
            trusted.extend(
                extra
                    .split(':')
                    .filter(|path| !path.is_empty())
                    .map(|path| TrustedProgram {
                        path: PathBuf::from(path),
                        must_be_root_owned: false,
                    }),
            );
        }
        Self { trusted }
    }

    /// These paths, without the root-owned check: for tests and tools.
    pub fn trusting(paths: Vec<PathBuf>) -> Self {
        Self {
            trusted: paths
                .into_iter()
                .map(|path| TrustedProgram {
                    path,
                    must_be_root_owned: false,
                })
                .collect(),
        }
    }

    pub fn allows(&self, caller: &Caller) -> bool {
        let Some(key @ AppKey::HostExecutable { path }) = caller.app_key() else {
            return false;
        };
        self.trusted.iter().any(|trusted| {
            trusted.path == *path && (!trusted.must_be_root_owned || !key.is_session_only(None))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn a_script_or_another_program_is_never_trusted() {
        let policy = ProgramPolicy::trusting(vec![PathBuf::from("/usr/bin/crownos-secrets")]);
        assert!(policy.allows(&Caller::from_executable(Path::new(
            "/usr/bin/crownos-secrets"
        ))));
        assert!(!policy.allows(&Caller::from_executable(Path::new("/usr/bin/other"))));
        let script = Caller::from_app_key(AppKey::Interpreted {
            interpreter: PathBuf::from("/usr/bin/python3"),
            script: PathBuf::from("/usr/bin/crownos-secrets"),
        });
        assert!(!policy.allows(&script));
        assert!(!policy.allows(&Caller::unidentified()));
    }

    #[test]
    fn an_installed_path_must_be_root_owned() {
        let own = std::env::current_exe().unwrap_or_default();
        let policy = ProgramPolicy {
            trusted: vec![TrustedProgram {
                path: own.clone(),
                must_be_root_owned: true,
            }],
        };
        assert!(!policy.allows(&Caller::from_executable(&own)));
    }
}
