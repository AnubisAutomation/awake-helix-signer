//! Minimal RLP and EIP-1559 (type 2) / EIP-7702 (type 4) transactions.

use ruint::aliases::U256;
use zeroize::Zeroizing;

use crate::address::{keccak, Address};
use crate::secp::{sign_digest, RecoverableSignature};

/// An RLP item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rlp {
    /// A byte string.
    Bytes(Vec<u8>),
    /// A list.
    List(Vec<Rlp>),
}

fn length_prefix(length: usize, short: u8, long: u8) -> Vec<u8> {
    if length < 56 {
        return vec![short + length as u8];
    }
    let bytes = (length as u64).to_be_bytes();
    let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(7);
    let mut out = vec![long + (8 - first) as u8];
    out.extend_from_slice(&bytes[first..]);
    out
}

impl Rlp {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Rlp::Bytes(bytes) if bytes.len() == 1 && bytes[0] < 0x80 => bytes.clone(),
            Rlp::Bytes(bytes) => {
                let mut out = length_prefix(bytes.len(), 0x80, 0xb7);
                out.extend_from_slice(bytes);
                out
            }
            Rlp::List(items) => {
                let body: Vec<u8> = items.iter().flat_map(Rlp::encode).collect();
                let mut out = length_prefix(body.len(), 0xc0, 0xf7);
                out.extend_from_slice(&body);
                out
            }
        }
    }

    /// An unsigned integer (minimal big-endian, zero is the empty string).
    pub fn uint(value: U256) -> Rlp {
        let bytes = value.to_be_bytes::<32>();
        let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(32);
        Rlp::Bytes(bytes[first..].to_vec())
    }

    /// A u64 integer.
    pub fn u64(value: u64) -> Rlp {
        Rlp::uint(U256::from(value))
    }

    /// A 32-byte big-endian integer (r, s).
    pub fn word(bytes: &[u8; 32]) -> Rlp {
        Rlp::uint(U256::from_be_bytes(*bytes))
    }

    /// An address.
    pub fn address(address: &Address) -> Rlp {
        Rlp::Bytes(address.0.to_vec())
    }
}

/// A signed EIP-7702 authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Authorization {
    /// Chain ID.
    pub chain_id: u64,
    /// Delegate.
    pub address: Address,
    /// Authority nonce (the account nonce + 1 when the authority sends the tx).
    pub nonce: u64,
    /// Signature.
    pub signature: RecoverableSignature,
}

impl Authorization {
    /// ``keccak(0x05 || rlp([chain_id, address, nonce]))``.
    pub fn digest(chain_id: u64, address: &Address, nonce: u64) -> [u8; 32] {
        let mut data = vec![0x05];
        data.extend(Rlp::List(vec![Rlp::u64(chain_id), Rlp::address(address), Rlp::u64(nonce)]).encode());
        keccak(&data)
    }

    /// Sign an authorization.
    pub fn sign(key: &Zeroizing<[u8; 32]>, chain_id: u64, address: Address, nonce: u64) -> Option<Authorization> {
        let signature = sign_digest(key, &Authorization::digest(chain_id, &address, nonce))?;
        Some(Authorization { chain_id, address, nonce, signature })
    }

    fn rlp(&self) -> Rlp {
        Rlp::List(vec![
            Rlp::u64(self.chain_id),
            Rlp::address(&self.address),
            Rlp::u64(self.nonce),
            Rlp::u64(self.signature.y_parity as u64),
            Rlp::word(&self.signature.r),
            Rlp::word(&self.signature.s),
        ])
    }
}

/// The value-0 self-call the signer sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    /// Chain ID.
    pub chain_id: u64,
    /// Sender nonce.
    pub nonce: u64,
    /// maxPriorityFeePerGas.
    pub max_priority_fee_per_gas: U256,
    /// maxFeePerGas.
    pub max_fee_per_gas: U256,
    /// Gas limit.
    pub gas: U256,
    /// Destination (the owner itself).
    pub to: Address,
    /// Calldata.
    pub data: Vec<u8>,
    /// EIP-7702 authorizations (type 4 when present).
    pub authorization_list: Option<Vec<Authorization>>,
}

impl Transaction {
    /// 2 or 4.
    pub fn tx_type(&self) -> u8 {
        if self.authorization_list.is_some() {
            4
        } else {
            2
        }
    }

    fn fields(&self) -> Vec<Rlp> {
        let mut fields = vec![
            Rlp::u64(self.chain_id),
            Rlp::u64(self.nonce),
            Rlp::uint(self.max_priority_fee_per_gas),
            Rlp::uint(self.max_fee_per_gas),
            Rlp::uint(self.gas),
            Rlp::address(&self.to),
            Rlp::u64(0),
            Rlp::Bytes(self.data.clone()),
            Rlp::List(Vec::new()),
        ];
        if let Some(list) = &self.authorization_list {
            fields.push(Rlp::List(list.iter().map(Authorization::rlp).collect()));
        }
        fields
    }

    /// The hash the sender signs.
    pub fn signing_hash(&self) -> [u8; 32] {
        let mut data = vec![self.tx_type()];
        data.extend(Rlp::List(self.fields()).encode());
        keccak(&data)
    }

    /// Sign: returns the raw transaction and its hash.
    pub fn sign(&self, key: &Zeroizing<[u8; 32]>) -> Option<(Vec<u8>, [u8; 32])> {
        let signature = sign_digest(key, &self.signing_hash())?;
        let mut fields = self.fields();
        fields.push(Rlp::u64(signature.y_parity as u64));
        fields.push(Rlp::word(&signature.r));
        fields.push(Rlp::word(&signature.s));
        let mut raw = vec![self.tx_type()];
        raw.extend(Rlp::List(fields).encode());
        let hash = keccak(&raw);
        Some((raw, hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rlp_known_values() {
        assert_eq!(Rlp::u64(0).encode(), vec![0x80]);
        assert_eq!(Rlp::u64(0x7f).encode(), vec![0x7f]);
        assert_eq!(Rlp::u64(0x80).encode(), vec![0x81, 0x80]);
        assert_eq!(Rlp::u64(1024).encode(), vec![0x82, 0x04, 0x00]);
        assert_eq!(Rlp::Bytes(b"dog".to_vec()).encode(), b"\x83dog".to_vec());
        assert_eq!(Rlp::List(vec![]).encode(), vec![0xc0]);
        let long = Rlp::Bytes(vec![0x61; 56]).encode();
        assert_eq!(&long[..2], &[0xb8, 56]);
        let list = Rlp::List(vec![Rlp::Bytes(b"cat".to_vec()), Rlp::Bytes(b"dog".to_vec())]).encode();
        assert_eq!(list, b"\xc8\x83cat\x83dog".to_vec());
    }
}
