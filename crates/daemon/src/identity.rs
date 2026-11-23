//! Who is calling: the `AppKey` of the program that connected, from what crownos-ipc read once
//! at accept (the executable with its device and inode, the command line and the working
//! directory). A process that turns off `PR_SET_DUMPABLE` after it connects keeps its identity;
//! one that turns it off first stays unidentified.

use std::fmt;
use std::path::Path;

use crownos_config::schema::AppKey;
use crownos_ipc::Credentials;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    app_key: Option<AppKey>,
}

impl Caller {
    pub const fn from_app_key(app_key: AppKey) -> Self {
        Self {
            app_key: Some(app_key),
        }
    }

    /// An unsandboxed native program, as `exe:<path>`.
    pub fn from_executable(executable: &Path) -> Self {
        Self::from_app_key(AppKey::HostExecutable {
            path: executable.to_owned(),
        })
    }

    pub const fn unidentified() -> Self {
        Self { app_key: None }
    }

    /// The key that bindings and approvals name. `None` matches nothing.
    pub const fn app_key(&self) -> Option<&AppKey> {
        self.app_key.as_ref()
    }

    /// The text form, `exe:<path>` and the like, that bindings store.
    pub fn app_key_text(&self) -> Option<String> {
        self.app_key.as_ref().map(AppKey::to_string)
    }

    /// The name for the user in a dialog: the app id, component, program or script.
    pub fn display_name(&self) -> String {
        self.app_key.as_ref().map_or_else(
            || "an unidentified program".to_owned(),
            AppKey::display_name,
        )
    }
}

/// Without control characters, because the key goes into audit lines and events.
impl fmt::Display for Caller {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = self
            .app_key_text()
            .unwrap_or_else(|| "unidentified".to_owned());
        text.chars()
            .filter(|character| !character.is_control())
            .try_for_each(|character| fmt::Write::write_char(formatter, character))
    }
}

pub trait IdentifyCaller {
    fn identify(&self, credentials: &Credentials) -> Caller;
}

/// The program that crownos-ipc read at accept, keyed by `AppKey::of_program`. A runtime that
/// gets no key (`python -c`, a loader) is unidentified.
#[derive(Debug, Clone, Copy, Default)]
pub struct AcceptedProgramIdentity;

impl IdentifyCaller for AcceptedProgramIdentity {
    fn identify(&self, credentials: &Credentials) -> Caller {
        credentials
            .program
            .as_ref()
            .and_then(|program| {
                AppKey::of_program(
                    &program.executable,
                    &program.arguments,
                    program.working_directory.as_deref(),
                )
            })
            .map_or_else(Caller::unidentified, Caller::from_app_key)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::os::unix::net::UnixStream;

    use super::*;

    #[test]
    fn a_live_peer_is_named_by_its_program() {
        let (ours, _theirs) = UnixStream::pair().unwrap();
        let credentials = Credentials::from_socket(&ours).unwrap();
        let caller = AcceptedProgramIdentity.identify(&credentials);
        let executable = std::env::current_exe().unwrap();
        assert_eq!(caller, Caller::from_executable(&executable));
        assert_eq!(caller.to_string(), format!("exe:{}", executable.display()));
    }

    #[test]
    fn an_unidentified_caller_has_no_key() {
        assert_eq!(Caller::unidentified().app_key(), None);
        assert_eq!(Caller::unidentified().to_string(), "unidentified");
    }
}
