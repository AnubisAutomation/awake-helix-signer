//! 20-byte Ethereum addresses with EIP-55 checksums, and Keccak-256.

use std::fmt;

use serde::{Serialize, Serializer};
use sha3::{Digest, Keccak256};

/// Keccak-256 of bytes.
pub fn keccak(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// ``0x``-prefixed lowercase hex.
pub fn hex0x(data: &[u8]) -> String {
    format!("0x{}", hex::encode(data))
}

/// One address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Address(pub [u8; 20]);

impl Address {
    /// The zero address.
    pub const ZERO: Address = Address([0u8; 20]);

    /// Parse like ``eth_utils.is_address`` + ``to_checksum_address``:
    /// optional ``0x``/``0X`` and exactly 40 hex digits of any case.
    pub fn parse(text: &str) -> Option<Address> {
        let hex = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")).unwrap_or(text);
        if hex.len() != 40 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        let mut out = [0u8; 20];
        hex::decode_to_slice(hex, &mut out).ok()?;
        Some(Address(out))
    }

    /// Parse a compile-time constant (panics on a typo; used for pinned values).
    pub fn constant(text: &str) -> Address {
        Address::parse(text).expect("pinned address")
    }

    /// ``0x`` + lowercase hex.
    pub fn to_lower(&self) -> String {
        hex0x(&self.0)
    }

    /// EIP-55 checksummed form.
    pub fn to_checksum(&self) -> String {
        let lower = hex::encode(self.0);
        let hash = keccak(lower.as_bytes());
        let mut out = String::with_capacity(42);
        out.push_str("0x");
        for (index, ch) in lower.chars().enumerate() {
            let nibble = (hash[index / 2] >> if index % 2 == 0 { 4 } else { 0 }) & 0x0f;
            if ch.is_ascii_alphabetic() && nibble > 7 {
                out.push(ch.to_ascii_uppercase());
            } else {
                out.push(ch);
            }
        }
        out
    }

    /// Whether ``text`` is exactly the checksummed form of an address.
    pub fn is_checksummed(text: &str) -> bool {
        text.len() == 42 && text.starts_with("0x") && Address::parse(text).map(|a| a.to_checksum() == text).unwrap_or(false)
    }

    /// Whether this is the zero address.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 20]
    }

    /// The 32-byte ABI word (left-padded).
    pub fn word(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[12..].copy_from_slice(&self.0);
        out
    }

    /// Address of an uncompressed secp256k1 public key (65 bytes, 0x04 prefix).
    pub fn from_public_key(uncompressed: &[u8]) -> Address {
        let hash = keccak(&uncompressed[1..]);
        let mut out = [0u8; 20];
        out.copy_from_slice(&hash[12..]);
        Address(out)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_checksum())
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_checksum())
    }
}

impl Serialize for Address {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_checksum())
    }
}

/// Whether two address texts name the same address (case-insensitive).
pub fn same(left: &str, right: &str) -> bool {
    left.to_lowercase() == right.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_and_parsing() {
        let address = Address::parse("0xdafcb6c6b3d2af124d58c5e05ce44abd8c8ff56a").unwrap();
        assert_eq!(address.to_checksum(), "0xdaFCb6c6B3d2Af124d58c5e05Ce44ABd8C8ff56A");
        assert!(Address::parse("0XDAFCB6C6B3D2AF124D58C5E05CE44ABD8C8FF56A").is_some());
        assert!(Address::parse("dafcb6c6b3d2af124d58c5e05ce44abd8c8ff56a").is_some());
        assert!(Address::parse("0xdafcb6c6b3d2af124d58c5e05ce44abd8c8ff5").is_none());
        assert!(Address::parse("0xzzfcb6c6b3d2af124d58c5e05ce44abd8c8ff56a").is_none());
        assert!(Address::is_checksummed("0xdaFCb6c6B3d2Af124d58c5e05Ce44ABd8C8ff56A"));
        assert!(!Address::is_checksummed("0xdafcb6c6b3d2af124d58c5e05ce44abd8c8ff56a"));
    }
}
