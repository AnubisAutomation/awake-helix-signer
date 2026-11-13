//! Start-up options: the link the app was opened with, `--selftest`,
//! `--version`, and (only in a `dev-constants` build) development constants.

use crate::backend::RealCore;
use crate::views::CommandError;

#[derive(Debug, Clone, Default)]
pub struct Options {
    /// The awakehelix:// link the app was started with.
    pub link: Option<String>,
    pub selftest: bool,
    pub version: bool,
}

/// The first awakehelix:// argument (macOS adds -psn_… arguments; ignored).
pub fn link_in<'a>(args: impl IntoIterator<Item = &'a str>) -> Option<String> {
    args.into_iter().find(|arg| arg.to_ascii_lowercase().starts_with("awakehelix:")).map(str::to_string)
}

impl Options {
    pub fn from_args(args: impl IntoIterator<Item = String>) -> Self {
        let args: Vec<String> = args.into_iter().filter(|arg| !arg.starts_with("-psn_")).collect();
        Options {
            link: link_in(args.iter().map(String::as_str)),
            selftest: args.iter().any(|arg| arg == "--selftest"),
            version: args.iter().any(|arg| arg == "--version"),
        }
    }

    /// The core with the pinned constants; a `dev-constants` build reads
    /// AWAKE_HELIX_SIGNER_DEV_CONSTANTS, _RPC and _API (loopback RPC only).
    pub fn core(&self) -> Result<RealCore, CommandError> {
        #[cfg(feature = "dev-constants")]
        if let Some(file) = std::env::var_os("AWAKE_HELIX_SIGNER_DEV_CONSTANTS") {
            let rpc = std::env::var("AWAKE_HELIX_SIGNER_RPC").unwrap_or_default();
            let api = std::env::var("AWAKE_HELIX_SIGNER_API").ok();
            return RealCore::development(std::path::Path::new(&file), &rpc, api.as_deref());
        }
        Ok(RealCore::production())
    }

    pub fn launched_for_ping(&self) -> bool {
        self.link.as_deref().map(|url| url.to_ascii_lowercase().starts_with("awakehelix://ping")).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_link_and_flags() {
        let options = Options::from_args(["-psn_0_123".to_string(), "awakehelix://ping?token=x".to_string(), "--selftest".into()]);
        assert_eq!(options.link.as_deref(), Some("awakehelix://ping?token=x"));
        assert!(options.selftest && !options.version && options.launched_for_ping());
        assert_eq!(link_in(["--x", "AwakeHelix://sign?plan=1"]), Some("AwakeHelix://sign?plan=1".into()));
        assert_eq!(link_in(["https://example.com"]), None);
    }

    #[test]
    fn production_by_default() {
        let core = Options::default().core().unwrap();
        assert!(!core.constants.development);
        assert_eq!(core.default_api, helix_signer_core::DEFAULT_API);
    }
}
