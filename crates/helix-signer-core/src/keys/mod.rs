//! Load the owner key from a keystore, a hidden private-key prompt or a mnemonic.
//!
//! Secrets are read with hidden input and kept only in memory: the raw key
//! bytes live in a [`Zeroizing`] buffer that is overwritten when the
//! [`KeyMaterial`] is wiped or dropped. No secret is ever printed, logged,
//! formatted into an error or sent anywhere.

pub mod bip39;
pub mod keystore;

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;
use zeroize::Zeroizing;

pub use keystore::Kdf;

use crate::address::Address;
use crate::error::{Error, ErrorKind, Result};
use crate::secp::{self, RecoverableSignature};

/// Largest BIP-44 account index.
pub const MAX_ACCOUNT_INDEX: i64 = 2_147_483_647;
/// Shown before a mnemonic is read.
pub const MNEMONIC_WARNING: &str = "A mnemonic (recovery phrase) controls EVERY account of that wallet, not only this one. Prefer an encrypted keystore file of a dedicated bot wallet.";

/// One loaded private key.
#[derive(Clone)]
pub struct KeyMaterial {
    address: Address,
    source: &'static str,
    path: String,
    key: Option<Zeroizing<[u8; 32]>>,
}

impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyMaterial(address='{}', source='{}')", self.address, self.source)
    }
}

fn material(raw: &[u8], source: &'static str, path: String) -> Result<KeyMaterial> {
    let invalid = || Error::key("This is not a valid secp256k1 private key.");
    if raw.len() != 32 {
        return Err(invalid());
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(raw);
    let address = secp::address_of(&key).ok_or_else(invalid)?;
    Ok(KeyMaterial { address, source, path, key: Some(key) })
}

impl KeyMaterial {
    /// Parse a hex private key (with or without ``0x``).
    pub fn from_private_key(text: &str) -> Result<KeyMaterial> {
        let value = text.trim();
        let value = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")).unwrap_or(value);
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(Error::key("A private key is 64 hexadecimal characters (optionally with 0x)."));
        }
        let mut raw = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(value, raw.as_mut()).map_err(|_| Error::key("A private key is 64 hexadecimal characters (optionally with 0x)."))?;
        material(raw.as_ref(), "private-key", String::new())
    }

    /// Decrypt an Ethereum V3 keystore file in memory.
    pub fn from_keystore(path: &Path, password: &str) -> Result<KeyMaterial> {
        let text = fs::read(path)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .ok_or_else(|| Error::key(format!("Cannot read the keystore file {}.", path.display())))?;
        Self::from_keystore_json(&text, &path.display().to_string(), password)
    }

    /// Decrypt keystore JSON text; ``label`` names it in messages.
    pub fn from_keystore_json(text: &str, label: &str, password: &str) -> Result<KeyMaterial> {
        let document: Value =
            serde_json::from_str(text).map_err(|_| Error::key(format!("Cannot read the keystore file {label}.")))?;
        let is_keystore = document.as_object().map(|map| map.keys().any(|key| key.to_lowercase() == "crypto")).unwrap_or(false);
        if !is_keystore {
            return Err(Error::key(format!("{label} is not an Ethereum keystore (V3 JSON) file.")));
        }
        let raw = keystore::decrypt(&document, password)
            .ok_or_else(|| Error::key("Wrong keystore password, or the keystore is damaged."))?;
        let mut loaded = material(&raw, "keystore", String::new())?;
        let stored = document.get("address").map(crate::pyfmt::py_str).unwrap_or_default().to_lowercase();
        let stored = stored.strip_prefix("0x").unwrap_or(&stored);
        if !stored.is_empty() && stored != &loaded.address.to_lower()[2..] {
            loaded.wipe();
            return Err(Error::key("The keystore's address field does not match its key."));
        }
        Ok(loaded)
    }

    /// Derive one account from a BIP-39 mnemonic on ``m/44'/60'/0'/0/<index>``.
    pub fn from_mnemonic(phrase: &str, index: i64, passphrase: &str) -> Result<KeyMaterial> {
        let path = derivation_path(index)?;
        let words = Zeroizing::new(phrase.split_whitespace().collect::<Vec<_>>().join(" "));
        let invalid = || Error::key("This is not a valid BIP-39 mnemonic (check the words and their order).");
        let seed = bip39::seed_from_mnemonic(&words, passphrase).ok_or_else(invalid)?;
        let key = bip39::derive_ethereum(&seed, index as u32).ok_or_else(invalid)?;
        material(key.as_ref(), "mnemonic", path).map_err(|_| invalid())
    }

    /// Checksummed address of the key.
    pub fn address(&self) -> Address {
        self.address
    }

    /// ``keystore``, ``private-key`` or ``mnemonic``.
    pub fn source(&self) -> &'static str {
        self.source
    }

    /// Derivation path for a mnemonic, else "".
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Whether the key was wiped.
    pub fn is_wiped(&self) -> bool {
        self.key.is_none()
    }

    /// Overwrite the raw key bytes with zeros and forget them.
    pub fn wipe(&mut self) {
        self.key = None;
    }

    /// The raw key, or the "already wiped" refusal.
    pub(crate) fn raw(&self) -> Result<&Zeroizing<[u8; 32]>> {
        self.key.as_ref().ok_or_else(|| Error::key("The key was already wiped."))
    }

    /// Sign a 32-byte digest.
    pub fn sign_digest(&self, digest: &[u8; 32]) -> Result<RecoverableSignature> {
        secp::sign_digest(self.raw()?, digest).ok_or_else(|| Error::key("The key was already wiped."))
    }

    /// EIP-191 ``personal_sign`` of a text: ``0x`` + 130 hex (v = 27/28).
    pub fn sign_message(&self, message: &str) -> Result<String> {
        let signature = self.sign_digest(&secp::personal_digest(message.as_bytes()))?;
        Ok(crate::address::hex0x(&signature.to_bytes_65()))
    }
}

/// The BIP-44 Ethereum path of one account index.
pub fn derivation_path(index: i64) -> Result<String> {
    if !(0..=MAX_ACCOUNT_INDEX).contains(&index) {
        return Err(Error::key("The account index must be between 0 and 2147483647."));
    }
    Ok(format!("m/44'/60'/0'/0/{index}"))
}

fn check_keystore_password(password: &str) -> Result<()> {
    if password.chars().count() < 8 {
        return Err(Error::key("Use a keystore password of at least 8 characters."));
    }
    Ok(())
}

fn encrypt_keystore(material: &KeyMaterial, password: &str, kdf: Kdf, work_factor: Option<u32>) -> Result<Value> {
    let raw = material.raw()?;
    keystore::encrypt(raw, &material.address.to_checksum(), password, kdf, work_factor)
        .ok_or_else(|| Error::key("Cannot encrypt the key with these keystore parameters."))
}

/// The V3 keystore document of ``material`` as JSON text (scrypt, the default
/// work factor), the same bytes [`create_keystore`] writes, without touching
/// the file system (the app hands it to a save dialog). Refuses a password
/// shorter than 8 characters, like [`create_keystore`].
pub fn keystore_json(material: &KeyMaterial, password: &str) -> Result<String> {
    check_keystore_password(password)?;
    let document = encrypt_keystore(material, password, Kdf::Scrypt, None)?;
    Ok(crate::pyjson::dumps(&document, false))
}

/// Write an encrypted V3 keystore file for a loaded key (the file must not
/// exist; it is created with mode 0600 on POSIX).
pub fn create_keystore(material: &KeyMaterial, password: &str, out: &Path, kdf: Kdf, work_factor: Option<u32>) -> Result<PathBuf> {
    check_keystore_password(password)?;
    if out.exists() {
        return Err(Error::key(format!("{} already exists; choose another file name.", out.display())));
    }
    let document = encrypt_keystore(material, password, kdf, work_factor)?;
    if let Some(parent) = out.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|error| Error::io(error.to_string()))?;
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(out).map_err(|error| match error.kind() {
        std::io::ErrorKind::AlreadyExists => Error::key(format!("{} already exists; choose another file name.", out.display())),
        _ => Error::io(format!("{error}: '{}'", out.display())),
    })?;
    use std::io::Write;
    file.write_all(crate::pyjson::dumps(&document, false).as_bytes()).map_err(|error| Error::io(error.to_string()))?;
    Ok(out.to_path_buf())
}

/// Terminal (or window) input for loading a key.
pub trait Prompter {
    /// Print one message.
    fn say(&self, text: &str);
    /// Hidden input; ``Err(Cancelled)`` when the input is closed.
    fn secret(&self, prompt: &str) -> Result<Zeroizing<String>>;
    /// Visible input; ``Err(Cancelled)`` when the input is closed.
    fn ask(&self, prompt: &str) -> Result<String>;
}

/// Where the key comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeySource {
    /// An encrypted keystore file (asks its password).
    Keystore(PathBuf),
    /// A hex private key typed hidden.
    PrivateKey,
    /// A BIP-39 mnemonic typed hidden, account ``index``, optional passphrase.
    Mnemonic {
        /// Account index on m/44'/60'/0'/0/N.
        index: i64,
        /// Also ask for a BIP-39 passphrase.
        passphrase: bool,
    },
}

impl KeySource {
    /// ``keystore``, ``private-key`` or ``mnemonic``.
    pub fn name(&self) -> &'static str {
        match self {
            KeySource::Keystore(_) => "keystore",
            KeySource::PrivateKey => "private-key",
            KeySource::Mnemonic { .. } => "mnemonic",
        }
    }
}

/// Load the key from the chosen source with hidden prompts (``keys.load_key``).
pub fn load_key(source: &KeySource, prompter: &dyn Prompter) -> Result<KeyMaterial> {
    match source {
        KeySource::Keystore(path) => {
            let password = prompter.secret(&format!("Password for {}: ", path.display()))?;
            KeyMaterial::from_keystore(path, &password)
        }
        KeySource::PrivateKey => {
            prompter.say("The private key is read with hidden input and never leaves this computer.");
            let text = prompter.secret("Private key (hidden): ")?;
            KeyMaterial::from_private_key(&text)
        }
        KeySource::Mnemonic { index, passphrase } => {
            prompter.say(&format!("WARNING: {MNEMONIC_WARNING}"));
            let phrase = prompter.secret("Mnemonic words (hidden): ")?;
            let extra = if *passphrase {
                prompter.secret("BIP-39 passphrase (hidden, empty if none): ")?
            } else {
                Zeroizing::new(String::new())
            };
            let mut loaded = KeyMaterial::from_mnemonic(&phrase, *index, &extra)?;
            drop(phrase);
            drop(extra);
            let answer = prompter.ask(&format!(
                "Derived {} -> {}. Is this the right address? [y/N] ",
                loaded.path, loaded.address
            ))?;
            if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
                loaded.wipe();
                return Err(Error::key("Address not confirmed; nothing was signed. Try another --account-index."));
            }
            Ok(loaded)
        }
    }
}

/// Whether an error is a wrong keystore password (the CLI retries those).
pub fn is_password_error(error: &Error) -> bool {
    error.kind() == ErrorKind::Key && error.message().contains("password")
}
