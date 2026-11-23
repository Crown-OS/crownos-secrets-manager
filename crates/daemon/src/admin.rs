//! The programs that may call the admin methods. The master password is the real gate; this
//! list is a second layer.

const INSTALLED_ADMIN_EXECUTABLES: [&str; 2] =
    ["/usr/bin/crownos-secrets", "/usr/bin/crownos-settings"];

/// Debug builds also accept the paths in this variable, separated by `:`.
#[cfg(debug_assertions)]
pub const DEBUG_ADMIN_EXECUTABLES_VARIABLE: &str = "CROWNOS_SECRETS_DEBUG_ADMIN_EXECUTABLES";

pub fn admin_executables() -> Vec<String> {
    let mut executables: Vec<String> = INSTALLED_ADMIN_EXECUTABLES.map(str::to_owned).to_vec();
    #[cfg(debug_assertions)]
    if let Ok(extra) = std::env::var(DEBUG_ADMIN_EXECUTABLES_VARIABLE) {
        executables.extend(
            extra
                .split(':')
                .filter(|path| !path.is_empty())
                .map(str::to_owned),
        );
    }
    executables
}
