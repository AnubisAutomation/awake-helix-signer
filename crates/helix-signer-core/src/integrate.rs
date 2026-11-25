//! Desktop integration: the per-user config directory and the
//! ``anubisauto-signer`` command symlink (``install-cli``).

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Name of the terminal command.
pub const COMMAND: &str = "anubisauto-signer";

fn home(home: Option<&Path>) -> PathBuf {
    home.map(Path::to_path_buf).unwrap_or_else(|| {
        std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."))
    })
}

/// Per-user settings directory (``AWAKE_HELIX_SIGNER_HOME`` wins).
pub fn config_dir() -> PathBuf {
    if let Some(configured) = std::env::var_os("AWAKE_HELIX_SIGNER_HOME").filter(|value| !value.is_empty()) {
        return PathBuf::from(configured);
    }
    if cfg!(windows) {
        let base = std::env::var_os("APPDATA").filter(|value| !value.is_empty()).map(PathBuf::from).unwrap_or_else(|| home(None));
        return base.join("AnubisAutoSigner");
    }
    if cfg!(target_os = "macos") {
        return home(None).join("Library/Application Support/AnubisAutoSigner");
    }
    let base = std::env::var_os("XDG_CONFIG_HOME").filter(|value| !value.is_empty()).map(PathBuf::from).unwrap_or_else(|| home(None).join(".config"));
    base.join(COMMAND)
}

/// Candidate directories for the command symlink, best first.
pub fn cli_dirs(home_dir: Option<&Path>) -> Vec<PathBuf> {
    let local = home(home_dir).join(".local/bin");
    if cfg!(target_os = "macos") {
        vec![PathBuf::from("/usr/local/bin"), local]
    } else {
        vec![local]
    }
}

fn writable(directory: &Path) -> bool {
    if std::fs::create_dir_all(directory).is_err() {
        return false;
    }
    let probe = directory.join(format!(".{COMMAND}-probe-{}", std::process::id()));
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// Whether ``directory`` is on ``$PATH``.
pub fn on_path(directory: &Path) -> bool {
    std::env::var_os("PATH").map(|paths| std::env::split_paths(&paths).any(|entry| entry == directory)).unwrap_or(false)
}

/// The existing command symlink that points to ``target``, if any.
pub fn cli_link(target: &Path, home_dir: Option<&Path>) -> Option<PathBuf> {
    cli_dirs(home_dir).into_iter().map(|dir| dir.join(COMMAND)).find(|link| std::fs::read_link(link).map(|to| to == target).unwrap_or(false))
}

/// Create (or refresh) the ``anubisauto-signer`` command symlink to ``target``.
pub fn install_cli(directory: Option<&Path>, home_dir: Option<&Path>, target: &Path) -> Result<String> {
    if cfg!(windows) {
        return Ok("On Windows the installer adds the program folder to PATH; open a new terminal.".into());
    }
    let candidates = match directory {
        Some(directory) => vec![directory.to_path_buf()],
        None => cli_dirs(home_dir),
    };
    let chosen = candidates.iter().find(|item| writable(item)).cloned().ok_or_else(|| {
        let names: Vec<String> = candidates.iter().map(|item| item.display().to_string()).collect();
        Error::io(format!("None of {} is writable.", names.join(", ")))
    })?;
    let link = chosen.join(COMMAND);
    if let Ok(metadata) = std::fs::symlink_metadata(&link) {
        if !metadata.file_type().is_symlink() {
            return Err(Error::io(format!("{} exists and is not a symlink; remove it first.", link.display())));
        }
        std::fs::remove_file(&link).map_err(|error| Error::io(error.to_string()))?;
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, &link).map_err(|error| Error::io(error.to_string()))?;
    let mut message = format!("linked {} -> {}", link.display(), target.display());
    if !on_path(&chosen) {
        let shell = if cfg!(target_os = "macos") { "~/.zprofile" } else { "~/.profile" };
        message.push_str(&format!(
            ". {} is not on your PATH: add it with echo 'export PATH=\"{}:$PATH\"' >> {shell} and open a new terminal.",
            chosen.display(),
            chosen.display()
        ));
    }
    Ok(message)
}

/// Remove our command symlink(s); foreign files are left alone.
pub fn uninstall_cli(target: &Path, home_dir: Option<&Path>) -> String {
    let mut removed = Vec::new();
    for directory in cli_dirs(home_dir) {
        let link = directory.join(COMMAND);
        let Ok(to) = std::fs::read_link(&link) else { continue };
        let named = to.file_name().map(|name| name.to_string_lossy().to_lowercase().contains(COMMAND)).unwrap_or(false);
        if (to == target || named) && std::fs::remove_file(&link).is_ok() {
            removed.push(link.display().to_string());
        }
    }
    if removed.is_empty() {
        format!("no {COMMAND} command link found")
    } else {
        format!("removed {}", removed.join(", "))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn install_and_uninstall() {
        let folder = std::env::temp_dir().join(format!("helix-cli-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&folder);
        let target = folder.join("app/anubisauto-signer");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, b"#!/bin/sh\n").unwrap();
        let message = install_cli(None, Some(&folder), &target).unwrap();
        assert!(message.starts_with("linked "), "{message}");
        let link = folder.join(".local/bin/anubisauto-signer");
        assert_eq!(std::fs::read_link(&link).unwrap(), target);
        assert_eq!(cli_link(&target, Some(&folder)), Some(link.clone()));
        install_cli(None, Some(&folder), &target).unwrap();
        assert!(uninstall_cli(&target, Some(&folder)).starts_with("removed "));
        assert!(!link.exists());
        std::fs::write(&link, b"foreign").unwrap();
        assert!(install_cli(None, Some(&folder), &target).unwrap_err().message().contains("not a symlink"));
        assert_eq!(uninstall_cli(&target, Some(&folder)), "no anubisauto-signer command link found");
        assert!(link.exists());
        let _ = std::fs::remove_dir_all(&folder);
    }
}
