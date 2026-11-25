//! Register a program as the handler of ``anubisauto://`` links and of the
//! legacy scheme of the signers before 0.7.0 (both in
//! [`crate::links::SCHEMES`]), so old links and QR codes open it too.
//!
//! * Linux: a ``.desktop`` entry with ``MimeType=x-scheme-handler/<scheme>;``
//!   for both schemes in ``~/.local/share/applications`` and ``xdg-mime
//!   default``. Inside an AppImage the entry runs the AppImage file itself
//!   (``$APPIMAGE``).
//! * Windows: ``HKEY_CURRENT_USER\Software\Classes\<scheme>`` for both
//!   schemes (per user, no administrator rights).
//! * macOS: the app bundle declares the schemes in ``Info.plist``
//!   (``CFBundleURLTypes``); ``register`` re-registers the bundle with
//!   ``lsregister``.
//!
//! Every platform implements [`UrlSchemeRegistrar`], so the app can reuse it
//! with its own executable as the handler.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{Error, Result};

/// Desktop entry file name.
pub const DESKTOP_ID: &str = "anubisauto-signer.desktop";
/// MIME types of the schemes ([`crate::links::SCHEMES`], the primary one first).
pub const MIMES: [&str; 2] = ["x-scheme-handler/anubisauto", "x-scheme-handler/awakehelix"];
/// Per-user registry keys of the schemes (the primary one first).
pub const WINDOWS_KEYS: [&str; 2] = [r"Software\Classes\anubisauto", r"Software\Classes\awakehelix"];
/// Name of the icon the desktop entry shows.
pub const ICON_NAME: &str = "anubisauto-signer";
/// macOS Launch Services tool.
pub const LSREGISTER: &str = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister";

/// Registers and removes the handler of the link schemes.
pub trait UrlSchemeRegistrar: Send + Sync {
    /// Register; returns what was done.
    fn register(&self) -> Result<String>;
    /// Remove the registration; returns what was done.
    fn unregister(&self) -> Result<String>;
    /// The current registration, or None.
    fn registration(&self) -> Option<String>;
}

/// The AppImage file this program runs from, if any.
pub fn appimage() -> Option<PathBuf> {
    std::env::var_os("APPIMAGE").filter(|value| !value.is_empty()).map(PathBuf::from)
}

/// The file users start: the AppImage, else this executable.
pub fn program() -> PathBuf {
    appimage().unwrap_or_else(|| {
        std::env::current_exe().and_then(|path| path.canonicalize()).unwrap_or_else(|_| PathBuf::from(crate::integrate::COMMAND))
    })
}

fn shell_quote(part: &str) -> String {
    if !part.is_empty() && part.chars().all(|ch| ch.is_ascii_alphanumeric() || "@%+=:,./-_".contains(ch)) {
        return part.to_string();
    }
    format!("'{}'", part.replace('\'', "'\"'\"'"))
}

/// Render the Linux desktop entry (``shlex.quote`` per argument).
pub fn desktop_entry(command: &[String], terminal: bool) -> String {
    let exec: Vec<String> = command.iter().map(|part| shell_quote(part)).collect();
    [
        "[Desktop Entry]".to_string(),
        "Type=Application".into(),
        "Name=Anubis Automation Script Signer".into(),
        "Comment=Verify and sign Anubis Automation hosted-bot authorizations locally".into(),
        format!("Exec={} %u", exec.join(" ")),
        format!("Icon={ICON_NAME}"),
        format!("Terminal={}", if terminal { "true" } else { "false" }),
        format!("MimeType={};", MIMES.join(";")),
        "Categories=Utility;".into(),
        String::new(),
    ]
    .join("\n")
}

fn which(tool: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(tool).is_file()))
        .unwrap_or(false)
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."))
}

/// ``.desktop`` + ``xdg-mime`` registration.
#[derive(Clone, Debug)]
pub struct LinuxRegistrar {
    /// Handler command (the link is appended as ``%u``).
    pub command: Vec<String>,
    /// Home directory (None: ``$HOME``).
    pub home: Option<PathBuf>,
    /// Open a terminal for the handler (the CLI needs one; the app does not).
    pub terminal: bool,
}

impl LinuxRegistrar {
    fn data_home(&self) -> PathBuf {
        match std::env::var_os("XDG_DATA_HOME").filter(|value| !value.is_empty()) {
            Some(value) => PathBuf::from(value),
            None => self.home.clone().unwrap_or_else(home_dir).join(".local/share"),
        }
    }

    /// Path of the desktop entry.
    pub fn entry(&self) -> PathBuf {
        self.data_home().join("applications").join(DESKTOP_ID)
    }

    /// Path of the icon written next to it.
    pub fn icon(&self) -> PathBuf {
        self.data_home().join(format!("icons/hicolor/256x256/apps/{ICON_NAME}.png"))
    }
}

impl UrlSchemeRegistrar for LinuxRegistrar {
    fn register(&self) -> Result<String> {
        let entry = self.entry();
        let parent = entry.parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent).map_err(|error| Error::io(error.to_string()))?;
        std::fs::write(&entry, desktop_entry(&self.command, self.terminal)).map_err(|error| Error::io(error.to_string()))?;
        let mut done = vec![format!("wrote {}", entry.display())];
        let icon = self.icon();
        let written = icon
            .parent()
            .map(std::fs::create_dir_all)
            .unwrap_or(Ok(()))
            .and_then(|_| std::fs::write(&icon, crate::icon::png(256)));
        if let Err(error) = written {
            done.push(format!("icon not written: {error}"));
        }
        if which("xdg-mime") {
            let _ = Command::new("xdg-mime").arg("default").arg(DESKTOP_ID).args(MIMES).status();
            done.push(format!("xdg-mime default {DESKTOP_ID} {}", MIMES.join(" ")));
        } else {
            done.push("xdg-mime not found: set the handler in your desktop settings".into());
        }
        if which("update-desktop-database") {
            let _ = Command::new("update-desktop-database").arg(parent).status();
        }
        Ok(done.join("; "))
    }

    fn unregister(&self) -> Result<String> {
        let entry = self.entry();
        let _ = std::fs::remove_file(&entry);
        let _ = std::fs::remove_file(self.icon());
        if which("update-desktop-database") {
            if let Some(parent) = entry.parent() {
                let _ = Command::new("update-desktop-database").arg(parent).status();
            }
        }
        Ok(format!("removed {}", entry.display()))
    }

    fn registration(&self) -> Option<String> {
        let text = std::fs::read_to_string(self.entry()).ok()?;
        text.lines().find_map(|line| line.strip_prefix("Exec=").map(str::to_string))
    }
}

/// ``HKCU\Software\Classes\<scheme>`` registration of both schemes.
#[derive(Clone, Debug)]
pub struct WindowsRegistrar {
    /// Handler command (``"%1"`` is appended).
    pub command: Vec<String>,
}

impl WindowsRegistrar {
    /// The ``shell\open\command`` line.
    pub fn command_line(&self) -> String {
        let parts: Vec<String> = self.command.iter().map(|part| format!("\"{part}\"")).collect();
        format!("{} \"%1\"", parts.join(" "))
    }
}

#[cfg(windows)]
impl UrlSchemeRegistrar for WindowsRegistrar {
    fn register(&self) -> Result<String> {
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let io = |error: std::io::Error| Error::io(error.to_string());
        let line = self.command_line();
        for scheme_key in WINDOWS_KEYS {
            let (key, _) = hkcu.create_subkey(scheme_key).map_err(io)?;
            key.set_value("", &"URL:Anubis Automation Script Signer").map_err(io)?;
            key.set_value("URL Protocol", &"").map_err(io)?;
            let (command, _) = hkcu.create_subkey(format!(r"{scheme_key}\shell\open\command")).map_err(io)?;
            command.set_value("", &line).map_err(io)?;
        }
        Ok(format!(r"registered HKCU\{} -> {line}", WINDOWS_KEYS.join(r", HKCU\")))
    }

    fn unregister(&self) -> Result<String> {
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        for scheme_key in WINDOWS_KEYS {
            for sub in [r"\shell\open\command", r"\shell\open", r"\shell", ""] {
                let _ = hkcu.delete_subkey(format!("{scheme_key}{sub}"));
            }
        }
        Ok(format!(r"removed HKCU\{}", WINDOWS_KEYS.join(r", HKCU\")))
    }

    fn registration(&self) -> Option<String> {
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;
        let key = RegKey::predef(HKEY_CURRENT_USER).open_subkey(format!(r"{}\shell\open\command", WINDOWS_KEYS[0])).ok()?;
        key.get_value::<String, _>("").ok()
    }
}

#[cfg(not(windows))]
impl UrlSchemeRegistrar for WindowsRegistrar {
    fn register(&self) -> Result<String> {
        Err(Error::io("The Windows registry is only available on Windows."))
    }

    fn unregister(&self) -> Result<String> {
        Err(Error::io("The Windows registry is only available on Windows."))
    }

    fn registration(&self) -> Option<String> {
        None
    }
}

/// macOS: the bundle's ``Info.plist`` declares the scheme.
#[derive(Clone, Debug)]
pub struct MacosRegistrar {
    /// The ``.app`` bundle this program runs from, if any.
    pub bundle: Option<PathBuf>,
}

/// The ``.app`` bundle containing ``executable``, if any.
pub fn bundle_of(executable: &Path) -> Option<PathBuf> {
    executable.ancestors().skip(1).find(|parent| parent.extension().map(|ext| ext == "app").unwrap_or(false)).map(Path::to_path_buf)
}

impl UrlSchemeRegistrar for MacosRegistrar {
    fn register(&self) -> Result<String> {
        let Some(bundle) = &self.bundle else {
            return Ok("On macOS the anubisauto:// scheme is declared by the app bundle (Info.plist). Move 'Anubis Automation Script Signer.app' to /Applications and open it once.".into());
        };
        if Path::new(LSREGISTER).exists() {
            let _ = Command::new(LSREGISTER).arg("-f").arg(bundle).status();
        }
        Ok(format!("registered {} with Launch Services", bundle.display()))
    }

    fn unregister(&self) -> Result<String> {
        Ok("Delete 'Anubis Automation Script Signer.app' to remove the macOS registration.".into())
    }

    fn registration(&self) -> Option<String> {
        self.bundle.as_ref().map(|bundle| bundle.display().to_string())
    }
}

/// Mobile platforms register their scheme in the app manifest; nothing to do here.
#[derive(Clone, Debug, Default)]
pub struct ManifestRegistrar;

impl UrlSchemeRegistrar for ManifestRegistrar {
    fn register(&self) -> Result<String> {
        Ok("The anubisauto:// scheme is declared by the app's manifest on this platform.".into())
    }

    fn unregister(&self) -> Result<String> {
        Ok("Uninstall the app to remove the anubisauto:// registration.".into())
    }

    fn registration(&self) -> Option<String> {
        None
    }
}

/// The registrar of the running operating system for ``command``.
/// ``terminal``: the Linux entry opens a terminal (CLI handlers).
pub fn for_this_os(command: Vec<String>, terminal: bool) -> Box<dyn UrlSchemeRegistrar> {
    if cfg!(windows) {
        Box::new(WindowsRegistrar { command })
    } else if cfg!(target_os = "macos") {
        Box::new(MacosRegistrar { bundle: std::env::current_exe().ok().and_then(|exe| bundle_of(&exe)) })
    } else if cfg!(any(target_os = "android", target_os = "ios")) {
        Box::new(ManifestRegistrar)
    } else {
        Box::new(LinuxRegistrar { command, home: None, terminal })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_entry_quotes_like_shlex() {
        let text = desktop_entry(&["/opt/Anubis Automation/signer".to_string()], false);
        assert!(text.contains("MimeType=x-scheme-handler/anubisauto;x-scheme-handler/awakehelix;"));
        assert!(text.contains("Exec='/opt/Anubis Automation/signer' %u"));
        assert!(text.contains("Name=Anubis Automation Script Signer\n"));
        assert!(text.contains("Icon=anubisauto-signer\n"));
        assert!(text.contains("Terminal=false"));
        assert!(desktop_entry(&["/usr/bin/anubisauto-signer".into(), "open".into()], true).contains("Exec=/usr/bin/anubisauto-signer open %u"));
        assert_eq!(WindowsRegistrar { command: vec!["C:\\A B\\x.exe".into()] }.command_line(), "\"C:\\A B\\x.exe\" \"%1\"");
        let bundle = "/Applications/Anubis Automation Script Signer.app";
        assert_eq!(bundle_of(Path::new(&format!("{bundle}/Contents/MacOS/x"))).unwrap(), PathBuf::from(bundle));
    }

    #[test]
    fn every_link_scheme_is_registered() {
        let schemes: Vec<String> = crate::links::SCHEMES.iter().map(|scheme| scheme.to_string()).collect();
        assert_eq!(MIMES.map(|mime| mime.strip_prefix("x-scheme-handler/").unwrap().to_string()).to_vec(), schemes);
        assert_eq!(WINDOWS_KEYS.map(|key| key.strip_prefix(r"Software\Classes\").unwrap().to_string()).to_vec(), schemes);
        assert_eq!(DESKTOP_ID, "anubisauto-signer.desktop");
        let home = std::env::temp_dir().join("helix-register-test");
        let registrar = LinuxRegistrar { command: vec!["x".into()], home: Some(home.clone()), terminal: false };
        if std::env::var_os("XDG_DATA_HOME").is_none() {
            assert_eq!(registrar.entry(), home.join(".local/share/applications/anubisauto-signer.desktop"));
            assert_eq!(registrar.icon(), home.join(".local/share/icons/hicolor/256x256/apps/anubisauto-signer.png"));
        }
    }
}
