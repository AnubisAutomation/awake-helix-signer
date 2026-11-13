//! Pin the platform attestation address at build time.
//!
//! The address comes from one committed file, `attestation_address.txt` at the
//! repository root (the release step sets it); nothing outside the repository
//! is read. `AWAKE_HELIX_ATTESTATION_FILE` names another
//! file (tests of this script). The file must hold exactly one checksummed,
//! non-zero address, otherwise the build fails. With `AWAKE_HELIX_RELEASE=1`
//! the build also refuses the placeholder address (whose private key nobody
//! knows; the same value as `constants::ATTESTATION_PLACEHOLDER`).

use std::env;
use std::fs;
use std::path::PathBuf;

use sha3::{Digest, Keccak256};

const PLACEHOLDER: &str = "0xF049968F26EC5CA1D32E9668153ccE7a789CD54F";

fn checksum(lower: &str) -> String {
    let hash = Keccak256::digest(lower.as_bytes());
    lower
        .chars()
        .enumerate()
        .map(|(index, ch)| {
            let nibble = (hash[index / 2] >> (if index % 2 == 0 { 4 } else { 0 })) & 0x0f;
            if ch.is_ascii_alphabetic() && nibble > 7 {
                ch.to_ascii_uppercase()
            } else {
                ch
            }
        })
        .collect()
}

fn main() {
    println!("cargo:rerun-if-env-changed=AWAKE_HELIX_ATTESTATION_FILE");
    println!("cargo:rerun-if-env-changed=AWAKE_HELIX_RELEASE");
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let workspace = manifest.join("../..");
    let candidates: Vec<PathBuf> = match env::var("AWAKE_HELIX_ATTESTATION_FILE") {
        Ok(path) if !path.is_empty() => vec![PathBuf::from(path)],
        _ => vec![workspace.join("attestation_address.txt")],
    };
    for path in &candidates {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    let path = candidates
        .iter()
        .find(|path| path.is_file())
        .unwrap_or_else(|| panic!("This signer build has no attestation_address.txt (looked at {candidates:?})."));
    let text = fs::read_to_string(path).unwrap_or_else(|error| panic!("Cannot read {}: {error}", path.display()));
    let address = text.trim();
    let valid = address.len() == 42
        && address.starts_with("0x")
        && address[2..].chars().all(|ch| ch.is_ascii_hexdigit())
        && checksum(&address[2..].to_ascii_lowercase()) == address[2..]
        && address[2..].chars().any(|ch| ch != '0');
    if !valid {
        panic!("{} must hold one checksummed, non-zero address.", path.display());
    }
    if env::var("AWAKE_HELIX_RELEASE").map(|value| value == "1").unwrap_or(false) && address == PLACEHOLDER {
        panic!(
            "{} still holds the placeholder attestation address: a release build would refuse every grant.",
            path.display()
        );
    }
    println!("cargo:rustc-env=HELIX_ATTESTATION_ADDRESS={address}");
}
