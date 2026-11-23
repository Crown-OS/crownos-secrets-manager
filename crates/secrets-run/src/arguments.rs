//! The bwrap options, NUL-separated, for `--args <fd>`. bwrap takes the command itself only from
//! its real command line, which holds no value.

use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use secrecy::{ExposeSecret as _, SecretSlice};
use secrets_core::RunTemplate;
use zeroize::Zeroizing;

use crate::SandboxError;

/// Top-level directories that are links into `/usr` on merged-usr systems.
const USR_LINKS: [&str; 4] = ["/bin", "/sbin", "/lib", "/lib64"];

struct ArgumentList(Zeroizing<Vec<u8>>);

impl ArgumentList {
    fn push(&mut self, part: &[u8]) -> Result<(), SandboxError> {
        if part.contains(&0) {
            return Err(SandboxError::ArgumentWithNul);
        }
        self.0.extend_from_slice(part);
        self.0.push(0);
        Ok(())
    }

    fn push_all(&mut self, parts: &[&str]) -> Result<(), SandboxError> {
        parts.iter().try_for_each(|part| self.push(part.as_bytes()))
    }
}

fn is_variable_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

pub(crate) fn bwrap_options(
    template: &RunTemplate,
    cwd: Option<&Path>,
    environment: &[(String, SecretSlice<u8>)],
) -> Result<Zeroizing<Vec<u8>>, SandboxError> {
    let capacity = 1024
        + environment
            .iter()
            .map(|(name, value)| name.len() + value.expose_secret().len() + 16)
            .sum::<usize>();
    let mut list = ArgumentList(Zeroizing::new(Vec::with_capacity(capacity)));
    list.push_all(&[
        "--die-with-parent",
        "--new-session",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup-try",
    ])?;
    if template.network.is_empty() {
        list.push_all(&["--unshare-net"])?;
    }
    list.push_all(&["--ro-bind", "/usr", "/usr"])?;
    for link in USR_LINKS {
        let path = Path::new(link);
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_symlink() => {
                let target = std::fs::read_link(path)?;
                list.push(b"--symlink")?;
                list.push(target.as_os_str().as_bytes())?;
                list.push(link.as_bytes())?;
            }
            Ok(_) => list.push_all(&["--ro-bind", link, link])?,
            Err(_) => {}
        }
    }
    list.push_all(&["--ro-bind", "/etc", "/etc"])?;
    if !template.network.is_empty() {
        list.push_all(&[
            "--ro-bind-try",
            "/run/systemd/resolve",
            "/run/systemd/resolve",
        ])?;
    }
    list.push_all(&["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"])?;
    match cwd {
        Some(directory) => {
            let bind = if template.cwd_writable {
                "--bind"
            } else {
                "--ro-bind"
            };
            list.push(bind.as_bytes())?;
            list.push(directory.as_os_str().as_bytes())?;
            list.push(directory.as_os_str().as_bytes())?;
            list.push(b"--chdir")?;
            list.push(directory.as_os_str().as_bytes())?;
        }
        None => list.push_all(&["--chdir", "/tmp"])?,
    }
    list.push_all(&[
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/local/bin:/usr/bin",
        "--setenv",
        "HOME",
        "/tmp",
        "--setenv",
        "LANG",
        "C.UTF-8",
    ])?;
    for (name, value) in environment {
        if !is_variable_name(name) {
            return Err(SandboxError::InvalidVariableName(name.clone()));
        }
        if value.expose_secret().contains(&0) {
            return Err(SandboxError::ValueWithNul(name.clone()));
        }
        list.push(b"--setenv")?;
        list.push(name.as_bytes())?;
        list.push(value.expose_secret())?;
    }
    Ok(list.0)
}

/// bwrap reads its options from standard input and then hands its own sync pipe on as the
/// command's standard input. A shell in the sandbox puts `/dev/null` there before it runs the
/// command; the command and the caller's arguments stay separate words, never shell text.
const STDIN_FROM_DEV_NULL: [&str; 5] = ["--", "/usr/bin/sh", "-c", "exec \"$@\" < /dev/null", "sh"];

/// The sandbox prefix, the template command and the caller's arguments.
pub(crate) fn command_line<'part>(
    template: &'part RunTemplate,
    arguments: &'part [String],
) -> Result<Vec<&'part str>, SandboxError> {
    let parts: Vec<&str> = STDIN_FROM_DEV_NULL
        .into_iter()
        .chain(template.command.iter().chain(arguments).map(String::as_str))
        .collect();
    if parts.iter().any(|part| part.contains('\0')) {
        return Err(SandboxError::ArgumentWithNul);
    }
    Ok(parts)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn parts(list: &[u8]) -> Vec<String> {
        list.split(|&byte| byte == 0)
            .filter(|part| !part.is_empty())
            .map(|part| String::from_utf8_lossy(part).into_owned())
            .collect()
    }

    #[test]
    fn no_network_unless_the_template_names_hosts() {
        let mut template = RunTemplate {
            command: vec!["true".into()],
            ..RunTemplate::default()
        };
        let list = bwrap_options(&template, None, &[]).unwrap();
        assert!(parts(&list).contains(&"--unshare-net".to_owned()));
        template.network = vec!["api.github.com".into()];
        let list = bwrap_options(&template, None, &[]).unwrap();
        assert!(!parts(&list).contains(&"--unshare-net".to_owned()));
    }

    #[test]
    fn values_go_in_the_options_and_the_command_stays_apart() {
        let template = RunTemplate {
            command: vec!["gh".into(), "pr".into()],
            allow_arguments: true,
            ..RunTemplate::default()
        };
        let environment = [("GH_TOKEN".to_owned(), SecretSlice::from(b"value".to_vec()))];
        let list = bwrap_options(&template, None, &environment).unwrap();
        let parts = parts(&list);
        let setenv = parts.iter().position(|part| part == "GH_TOKEN").unwrap();
        assert_eq!(parts[setenv - 1], "--setenv");
        assert_eq!(parts[setenv + 1], "value");
        let arguments = ["list".to_owned()];
        let command = command_line(&template, &arguments).unwrap();
        assert_eq!(command[command.len() - 3..], ["gh", "pr", "list"]);
        assert_eq!(command[0], "--");
    }

    #[test]
    fn bad_names_and_nul_bytes_are_refused() {
        let template = RunTemplate {
            command: vec!["true".into()],
            ..RunTemplate::default()
        };
        let bad_name = [("1X".to_owned(), SecretSlice::from(b"v".to_vec()))];
        assert!(matches!(
            bwrap_options(&template, None, &bad_name),
            Err(SandboxError::InvalidVariableName(_))
        ));
        let nul_value = [("X".to_owned(), SecretSlice::from(b"a\0b".to_vec()))];
        assert!(matches!(
            bwrap_options(&template, None, &nul_value),
            Err(SandboxError::ValueWithNul(_))
        ));
        let arguments = ["a\0".to_owned()];
        assert!(matches!(
            command_line(&template, &arguments),
            Err(SandboxError::ArgumentWithNul)
        ));
    }
}
