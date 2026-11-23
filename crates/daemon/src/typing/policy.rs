//! Who may ask to type, and which app a window must belong to.

use std::path::PathBuf;

use crownos_config::schema::{AppKey, LauncherMap};

use crate::util::desktop_app_key::desktop_app_key;
use crate::{Caller, ProgramPolicy};

/// System directories with desktop entries. The user's own entries are not read: a program of
/// the user could name any executable there.
const SYSTEM_APPLICATION_DIRECTORIES: [&str; 3] = [
    "/usr/local/share/applications",
    "/usr/share/applications",
    "/var/lib/flatpak/exports/share/applications",
];

#[derive(Debug, Clone)]
pub struct TypingPolicy {
    callers: ProgramPolicy,
    application_directories: Vec<PathBuf>,
    launchers: LauncherMap,
}

impl TypingPolicy {
    /// The installed computer-use daemon and the system desktop entries.
    pub fn installed() -> Self {
        Self::new(
            ProgramPolicy::installed_typing_callers(),
            SYSTEM_APPLICATION_DIRECTORIES
                .iter()
                .map(PathBuf::from)
                .collect(),
        )
    }

    /// With the built-in launchers and those of a root-controlled launcher file.
    pub fn new(callers: ProgramPolicy, application_directories: Vec<PathBuf>) -> Self {
        let launchers = LauncherMap::installed().unwrap_or_else(|error| {
            tracing::warn!(%error, "the launcher file is ignored");
            LauncherMap::built_in()
        });
        Self {
            callers,
            application_directories,
            launchers,
        }
    }

    pub fn allows_caller(&self, caller: &Caller) -> bool {
        self.callers.allows(caller)
    }

    /// The key the compositor must find on the window of `app_id`.
    pub fn expected_app_key(&self, app_id: &str) -> Option<AppKey> {
        desktop_app_key(app_id, &self.application_directories, &self.launchers)
    }
}
