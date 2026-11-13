//! secp256k1 signing and recovery (k256, pure Rust), as eth-account does it:
//! RFC 6979 deterministic nonces, low-S signatures, recovery accepting any
//! S below the curve order.

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use crate::address::{keccak, Address};

/// A recoverable signature: r, s (big-endian) and y parity (0 or 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoverableSignature {
    /// r.
    pub r: [u8; 32],
    /// s (low half of the order).
    pub s: [u8; 32],
    /// y parity.
    pub y_parity: u8,
}

impl RecoverableSignature {
    /// ``r || s || v`` with ``v = 27 + y_parity`` (personal_sign / EIP-712 form).
    pub fn to_bytes_65(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[..32].copy_from_slice(&self.r);
        out[32..64].copy_from_slice(&self.s);
        out[64] = 27 + self.y_parity;
        out
    }
}

/// The signing key of 32 raw bytes, or None when not a valid secp256k1 key.
pub fn signing_key(raw: &[u8; 32]) -> Option<SigningKey> {
    SigningKey::from_bytes(raw.into()).ok()
}

/// Address of a private key.
pub fn address_of(raw: &[u8; 32]) -> Option<Address> {
    let key = signing_key(raw)?;
    let point = key.verifying_key().to_encoded_point(false);
    Some(Address::from_public_key(point.as_bytes()))
}

/// Sign a 32-byte digest.
pub fn sign_digest(raw: &Zeroizing<[u8; 32]>, digest: &[u8; 32]) -> Option<RecoverableSignature> {
    let key = signing_key(raw)?;
    let (signature, recovery) = key.sign_prehash_recoverable(digest).ok()?;
    let (signature, recovery) = match signature.normalize_s() {
        Some(normalized) => (normalized, RecoveryId::new(!recovery.is_y_odd(), recovery.is_x_reduced())),
        None => (signature, recovery),
    };
    let bytes = signature.to_bytes();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&bytes[..32]);
    s.copy_from_slice(&bytes[32..]);
    Some(RecoverableSignature { r, s, y_parity: recovery.is_y_odd() as u8 })
}

/// Recover the signer of a digest from ``r``, ``s`` and a y parity (0/1).
pub fn recover(digest: &[u8; 32], r: &[u8; 32], s: &[u8; 32], y_parity: u8) -> Option<Address> {
    if y_parity > 1 {
        return None;
    }
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(r);
    bytes[32..].copy_from_slice(s);
    let signature = Signature::from_slice(&bytes).ok()?;
    let mut odd = y_parity == 1;
    let signature = match signature.normalize_s() {
        Some(normalized) => {
            odd = !odd;
            normalized
        }
        None => signature,
    };
    let key = VerifyingKey::recover_from_prehash(digest, &signature, RecoveryId::new(odd, false)).ok()?;
    let point = key.to_encoded_point(false);
    Some(Address::from_public_key(point.as_bytes()))
}

/// Recover from 65 signature bytes ``r || s || v`` with eth-account's ``v``
/// rules (0, 1, 27, 28 or EIP-155 values from 35).
pub fn recover_65(digest: &[u8; 32], signature: &[u8; 65]) -> Option<Address> {
    let v = signature[64];
    let parity = match v {
        0 | 1 => v,
        27 | 28 => v - 27,
        35..=255 => (v - 35) % 2,
        _ => return None,
    };
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&signature[..32]);
    s.copy_from_slice(&signature[32..64]);
    recover(digest, &r, &s, parity)
}

/// EIP-191 ``personal_sign`` digest of a text message.
pub fn personal_digest(message: &[u8]) -> [u8; 32] {
    let mut data = format!("\x19Ethereum Signed Message:\n{}", message.len()).into_bytes();
    data.extend_from_slice(message);
    keccak(&data)
}
