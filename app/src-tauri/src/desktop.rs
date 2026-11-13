//! "This computer": where awakehelix:// links and the terminal command point,
//! registering them, and the AppImage first-run question. Phones have none of
//! this (the OS registers the link scheme at install; there is no CLI).

use std::path::{Path, PathBuf};

use crate::views::{CommandError, CommandResult, SetupView};

pub const COMMAND: &str = "awake-helix-signer";
pub const SCHEME: &str = "awakehelix";
const STATE_FILE: &str = "integration.json";

pub fn os_name() -> &'static str {
    if cfg!(target_os = "android") {
        "android"
    } else if cfg!(target_os = "ios") {
        "ios"
    } else if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

pub fn arch_name() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else {
        std::env::consts::ARCH
    }
}

pub fn mobile() -> bool {
    cfg!(any(target_os = "android", target_os = "ios"))
}

/// The AppImage this program runs from, if any.
pub fn appimage() -> Option<PathBuf> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    std::env::var_os("APPIMAGE").map(PathBuf::from).filter(|path| path.is_file())
}

/// Candidate directories for the terminal command, best first.
pub fn cli_dirs(home: &Path) -> Vec<PathBuf> {
    let local = home.join(".local/bin");
    if cfg!(target_os = "macos") {
        vec![PathBuf::from("/usr/local/bin"), local]
    } else {
        vec![local]
    }
}

fn home() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."))
}

/// The command-line binary shipped next to the app (Tauri externalBin).
pub fn bundled_cli() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let name = if cfg!(windows) { format!("{COMMAND}.exe") } else { COMMAND.to_string() };
    let path = exe.parent()?.join(name);
    path.is_file().then_some(path)
}

/// Where `awake-helix-signer` runs from today, if anywhere we know.
pub fn installed_cli(home: &Path) -> Option<PathBuf> {
    if cfg!(windows) || mobile() {
        return None;
    }
    let mut candidates = cli_dirs(home);
    candidates.push(PathBuf::from("/usr/bin"));
    candidates.into_iter().map(|dir| dir.join(COMMAND)).find(|path| path.exists())
}

fn state_path() -> PathBuf {
    helix_signer_core::integrate::config_dir().join(STATE_FILE)
}

fn read_state() -> serde_json::Map<String, serde_json::Value> {
    std::fs::read_to_string(state_path())
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default()
}

/// Whether this AppImage location was not asked about yet (moving it asks again).
pub fn first_run_needed() -> bool {
    match appimage() {
        Some(image) => read_state().get("askedFor").and_then(|value| value.as_str()) != Some(&image.to_string_lossy()),
        None => false,
    }
}

pub fn mark_first_run() -> CommandResult<()> {
    let path = state_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| CommandError::error(error.to_string()))?;
    }
    let mut state = read_state();
    state.insert("askedFor".into(), appimage().map(|image| image.to_string_lossy().into_owned()).unwrap_or_default().into());
    std::fs::write(&path, serde_json::to_string_pretty(&state).unwrap_or_default() + "\n").map_err(|error| CommandError::error(error.to_string()))
}

/// Linux: the .desktop file that opens awakehelix:// links (xdg-mime).
fn linux_handler() -> Option<String> {
    let output = std::process::Command::new("xdg-mime").args(["query", "default", &format!("x-scheme-handler/{SCHEME}")]).output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!text.is_empty()).then_some(text)
}

/// macOS: links open the app when it runs from an installed .app bundle.
fn macos_handler() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let bundle = exe.ancestors().find(|path| path.extension().map(|ext| ext == "app").unwrap_or(false))?;
    let text = bundle.to_string_lossy().into_owned();
    (text.starts_with("/Applications/") || text.contains("/Applications/")).then_some(text)
}

pub fn setup(handler_registered: Option<bool>) -> SetupView {
    let os = os_name();
    if mobile() {
        return SetupView {
            os,
            mobile: true,
            handler: Some("Awake Helix Signer".into()),
            command: None,
            can_register: false,
            can_install_cli: false,
            cli_places: Vec::new(),
            first_run: false,
        };
    }
    let home = home();
    let handler = match os {
        "macos" => macos_handler(),
        "linux" => linux_handler(),
        _ => handler_registered.filter(|registered| *registered).map(|_| {
            std::env::current_exe().map(|exe| exe.to_string_lossy().into_owned()).unwrap_or_else(|_| "Awake Helix Signer".into())
        }),
    };
    SetupView {
        os,
        mobile: false,
        handler,
        command: installed_cli(&home).map(|path| path.to_string_lossy().into_owned()),
        can_register: os != "macos",
        can_install_cli: os != "windows" && bundled_cli().is_some(),
        cli_places: cli_dirs(&home).iter().map(|dir| dir.to_string_lossy().into_owned()).collect(),
        first_run: first_run_needed(),
    }
}

fn writable(dir: &Path) -> bool {
    if std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    let probe = dir.join(".awake-helix-write-test");
    let ok = std::fs::write(&probe, b"").is_ok();
    let _ = std::fs::remove_file(&probe);
    ok
}

fn on_path(dir: &Path) -> bool {
    std::env::var_os("PATH").map(|path| std::env::split_paths(&path).any(|entry| entry == dir)).unwrap_or(false)
}

/// Put the terminal command in ~/.local/bin (or /usr/local/bin on macOS).
///
/// From an AppImage the bundled binary lives in a mount that disappears when
/// the app quits, so it is copied; elsewhere a symlink follows app updates.
pub fn install_cli_at(dirs: &[PathBuf], source: &Path, copy: bool) -> CommandResult<String> {
    if cfg!(windows) {
        return Ok("On Windows the installer adds the program folder to PATH; open a new terminal.".into());
    }
    let chosen = dirs.iter().find(|dir| writable(dir)).ok_or_else(|| {
        CommandError::refused(format!("None of {} is writable.", dirs.iter().map(|dir| dir.display().to_string()).collect::<Vec<_>>().join(", ")))
    })?;
    let link = chosen.join(COMMAND);
    if let Ok(meta) = std::fs::symlink_metadata(&link) {
        let ours = meta.file_type().is_symlink() || copy;
        if !ours {
            return Err(CommandError::refused(format!("{} exists and is not a symlink; remove it first.", link.display())));
        }
        std::fs::remove_file(&link).map_err(|error| CommandError::error(error.to_string()))?;
    }
    let mut message = if copy {
        std::fs::copy(source, &link).map_err(|error| CommandError::error(error.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&link, std::fs::Permissions::from_mode(0o755));
        }
        format!("copied {} to {}", source.display(), link.display())
    } else {
        #[cfg(unix)]
        std::os::unix::fs::symlink(source, &link).map_err(|error| CommandError::error(error.to_string()))?;
        format!("linked {} -> {}", link.display(), source.display())
    };
    if !on_path(chosen) {
        let shell = if cfg!(target_os = "macos") { "~/.zprofile" } else { "~/.profile" };
        message.push_str(&format!(
            ". {} is not on your PATH: add it with echo 'export PATH=\"{}:$PATH\"' >> {shell} and open a new terminal.",
            chosen.display(),
            chosen.display()
        ));
    }
    Ok(message)
}

pub fn install_cli() -> CommandResult<String> {
    if mobile() {
        return Err(CommandError::refused("There is no command-line tool on a phone."));
    }
    let source = bundled_cli().ok_or_else(|| CommandError::refused("This build does not include the command-line tool."))?;
    install_cli_at(&cli_dirs(&home()), &source, appimage().is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(["windows", "macos", "linux", "android", "ios"].contains(&os_name()));
        assert!(!arch_name().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn installs_link_and_refuses_foreign_file() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("bundled");
        std::fs::write(&source, b"#!/bin/sh\n").unwrap();
        let bin = temp.path().join("bin");
        let message = install_cli_at(std::slice::from_ref(&bin), &source, false).unwrap();
        assert!(message.starts_with("linked"), "{message}");
        assert_eq!(std::fs::read_link(bin.join(COMMAND)).unwrap(), source);
        // Refreshing our own link works.
        install_cli_at(std::slice::from_ref(&bin), &source, false).unwrap();
        // A foreign file is left alone.
        std::fs::remove_file(bin.join(COMMAND)).unwrap();
        std::fs::write(bin.join(COMMAND), b"foreign").unwrap();
        let error = install_cli_at(std::slice::from_ref(&bin), &source, false).unwrap_err();
        assert!(error.message.contains("not a symlink"));
        // An AppImage copies (the mount disappears).
        std::fs::remove_file(bin.join(COMMAND)).unwrap();
        let message = install_cli_at(std::slice::from_ref(&bin), &source, true).unwrap();
        assert!(message.starts_with("copied"), "{message}");
        assert!(!std::fs::symlink_metadata(bin.join(COMMAND)).unwrap().file_type().is_symlink());
    }
}
