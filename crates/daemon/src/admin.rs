//! Which programs may call the admin methods. The master password is the first gate; this is
//! the second.

use std::path::PathBuf;

use crownos_config::schema::AppKey;

use crate::Caller;

const INSTALLED_ADMIN_EXECUTABLES: [&str; 2] =
    ["/usr/bin/crownos-secrets", "/usr/bin/crownos-settings"];

/// Debug builds also accept the paths in this variable, separated by `:`, without the
/// root-owned check.
#[cfg(debug_assertions)]
pub const DEBUG_ADMIN_EXECUTABLES_VARIABLE: &str = "CROWNOS_SECRETS_DEBUG_ADMIN_EXECUTABLES";

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrustedAdmin {
    path: PathBuf,
    /// The file and its directory must be owned by root and not writable by others, so no
    /// process of the user can put another program there.
    must_be_root_owned: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdminPolicy {
    trusted: Vec<TrustedAdmin>,
}

impl AdminPolicy {
    /// The installed CLI and Settings app, which must be root-owned.
    pub fn installed() -> Self {
        let mut trusted: Vec<TrustedAdmin> = INSTALLED_ADMIN_EXECUTABLES
            .iter()
            .map(|path| TrustedAdmin {
                path: PathBuf::from(path),
                must_be_root_owned: true,
            })
            .collect();
        #[cfg(debug_assertions)]
        if let Ok(extra) = std::env::var(DEBUG_ADMIN_EXECUTABLES_VARIABLE) {
            trusted.extend(
                extra
                    .split(':')
                    .filter(|path| !path.is_empty())
                    .map(|path| TrustedAdmin {
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
                .map(|path| TrustedAdmin {
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
    fn a_script_or_another_program_is_never_admin() {
        let policy = AdminPolicy::trusting(vec![PathBuf::from("/usr/bin/crownos-secrets")]);
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
        let policy = AdminPolicy {
            trusted: vec![TrustedAdmin {
                path: own.clone(),
                must_be_root_owned: true,
            }],
        };
        assert!(!policy.allows(&Caller::from_executable(&own)));
    }
}
