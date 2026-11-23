//! The app key of an installed app, from its desktop entry: what the compositor reads from the
//! process when a window of the app connects.

use std::path::{Path, PathBuf};

use crownos_config::schema::{AppKey, LauncherMap};

/// Where a relative `Exec` program is looked for. The user's `PATH` is not used.
const SYSTEM_PROGRAM_DIRECTORIES: [&str; 3] = ["/usr/local/bin", "/usr/bin", "/bin"];
/// The sandbox engine name that Flatpak gives `wp_security_context_v1`.
const FLATPAK_ENGINE: &str = "org.flatpak";
const DESKTOP_ENTRY_GROUP: &str = "[Desktop Entry]";

/// The key of the app whose desktop entry is `<app_id>.desktop` in one of `directories`,
/// first match first, with a launcher replaced by the program it starts. `None` for an unknown
/// app, or an entry whose program the user can change.
pub(crate) fn desktop_app_key(
    app_id: &str,
    directories: &[PathBuf],
    launchers: &LauncherMap,
) -> Option<AppKey> {
    if app_id.is_empty() || app_id.contains('/') || app_id.starts_with('.') {
        return None;
    }
    let entry = directories.iter().find_map(|directory| {
        std::fs::read_to_string(directory.join(format!("{app_id}.desktop"))).ok()
    })?;
    let key = entry_key(&entry, launchers)?;
    (!key.is_session_only(None)).then_some(key)
}

fn entry_key(entry: &str, launchers: &LauncherMap) -> Option<AppKey> {
    let mut in_group = false;
    let mut exec = None;
    for line in entry.lines().map(str::trim) {
        if line.starts_with('[') {
            in_group = line == DESKTOP_ENTRY_GROUP;
            continue;
        }
        if !in_group {
            continue;
        }
        if let Some(flatpak_id) = line.strip_prefix("X-Flatpak=") {
            return Some(AppKey::Sandboxed {
                engine: FLATPAK_ENGINE.to_owned(),
                app_id: flatpak_id.trim().to_owned(),
            });
        }
        if exec.is_none() {
            exec = line.strip_prefix("Exec=");
        }
    }
    let arguments: Vec<String> = exec?
        .split_whitespace()
        .filter(|argument| !argument.starts_with('%'))
        .map(|argument| argument.trim_matches('"').to_owned())
        .collect();
    let program = program_path(arguments.first()?, launchers)?;
    AppKey::of_program(&program, &arguments, None)
}

fn program_path(program: &str, launchers: &LauncherMap) -> Option<PathBuf> {
    let program = Path::new(program);
    let found = if program.is_absolute() {
        program.to_path_buf()
    } else {
        SYSTEM_PROGRAM_DIRECTORIES
            .iter()
            .map(|directory| Path::new(directory).join(program))
            .find(|candidate| candidate.is_file())?
    };
    let canonical = std::fs::canonicalize(launchers.real_program(&found)).ok()?;
    Some(launchers.real_program(&canonical).to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_gives_the_key_of_the_program_on_the_system_path() {
        let key = entry_key(
            "[Desktop Entry]\nName=True\nExec=true --flag %U\n",
            &LauncherMap::built_in(),
        );
        let program = std::fs::canonicalize("/usr/bin/true").ok();
        assert_eq!(key, program.map(|path| AppKey::HostExecutable { path }));
    }

    #[test]
    fn a_flatpak_entry_gives_the_sandbox_key() {
        let key = entry_key(
            "[Desktop Entry]\nExec=/usr/bin/flatpak run --branch=stable org.example.App\nX-Flatpak=org.example.App\n",
            &LauncherMap::built_in(),
        );
        assert_eq!(
            key,
            Some(AppKey::Sandboxed {
                engine: "org.flatpak".into(),
                app_id: "org.example.App".into()
            })
        );
    }

    #[test]
    fn only_the_desktop_entry_group_counts() {
        assert_eq!(
            entry_key(
                "[Desktop Action new]\nExec=/bin/sh\n[Desktop Entry]\nName=x\n",
                &LauncherMap::built_in()
            ),
            None
        );
    }

    #[test]
    fn app_ids_cannot_leave_the_directory() {
        let directories = [PathBuf::from("/usr/share/applications")];
        for app_id in ["", "../etc/passwd", "a/b", ".hidden"] {
            assert_eq!(
                desktop_app_key(app_id, &directories, &LauncherMap::built_in()),
                None,
                "{app_id}"
            );
        }
    }

    #[test]
    fn a_browser_launcher_gives_the_key_of_the_browser_process() {
        if !Path::new("/usr/lib/chromium/chromium").is_file() {
            return;
        }
        let key = entry_key(
            "[Desktop Entry]\nName=Chromium\nExec=/usr/bin/chromium %U\n",
            &LauncherMap::built_in(),
        );
        assert_eq!(
            key,
            Some(AppKey::HostExecutable {
                path: PathBuf::from("/usr/lib/chromium/chromium")
            })
        );
    }
}
