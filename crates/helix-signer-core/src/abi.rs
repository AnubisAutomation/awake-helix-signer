//! Strict ABI decoding of the few calls the signer handles, mirroring
//! ``eth_abi.decode`` (padding bytes must be zero, tuple pointers must point
//! past the head and inside the payload) and canonical re-encoding.

use ruint::aliases::U256;

use crate::address::Address;

/// One raw ABI rule tuple ``(uint8,address,address,address,uint256 x4,uint48,uint48,uint256)``.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawRule {
    /// RuleKind.
    pub kind: u8,
    /// Called contract.
    pub target: Address,
    /// Input token or zero.
    pub token_in: Address,
    /// Spender, output token or zero.
    pub counterparty: Address,
    /// Per-call cap.
    pub max_amount: U256,
    /// Secondary cap.
    pub max_secondary: U256,
    /// Daily cap.
    pub max_daily: U256,
    /// Swap price floor (1e18 scale).
    pub min_out_per_in_wad: U256,
    /// Deadline bound in seconds.
    pub max_deadline_delay: u64,
    /// Usage day counter (must be zero).
    pub usage_day: u64,
    /// Used today counter (must be zero).
    pub used_today: U256,
}

/// Decoded ``installPolicyGrant(bytes32, PolicyGrant, Rule[])`` arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallCall {
    /// Grant ID.
    pub grant_id: [u8; 32],
    /// Session key.
    pub key: Address,
    /// Bot UUID bytes.
    pub bot: [u8; 16],
    /// validAfter (uint48).
    pub valid_after: u64,
    /// validUntil (uint48).
    pub valid_until: u64,
    /// remainingCalls (uint32).
    pub remaining_calls: u64,
    /// Rules.
    pub rules: Vec<RawRule>,
}

/// A decoding failure (``eth_abi.exceptions.DecodingError``).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeError;

struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    fn word(&self, at: usize) -> Result<&'a [u8], DecodeError> {
        let end = at.checked_add(32).ok_or(DecodeError)?;
        self.data.get(at..end).ok_or(DecodeError)
    }

    fn uint(&self, at: usize, bits: usize) -> Result<U256, DecodeError> {
        let word = self.word(at)?;
        let padding = 32 - bits / 8;
        if word[..padding].iter().any(|byte| *byte != 0) {
            return Err(DecodeError);
        }
        Ok(U256::from_be_slice(word))
    }

    fn small(&self, at: usize, bits: usize) -> Result<u64, DecodeError> {
        Ok(self.uint(at, bits)?.to::<u64>())
    }

    fn address(&self, at: usize) -> Result<Address, DecodeError> {
        let word = self.word(at)?;
        if word[..12].iter().any(|byte| *byte != 0) {
            return Err(DecodeError);
        }
        let mut out = [0u8; 20];
        out.copy_from_slice(&word[12..]);
        Ok(Address(out))
    }

    fn bytes16(&self, at: usize) -> Result<[u8; 16], DecodeError> {
        let word = self.word(at)?;
        if word[16..].iter().any(|byte| *byte != 0) {
            return Err(DecodeError);
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(&word[..16]);
        Ok(out)
    }
}

const RULE_WORDS: usize = 11;

/// Decode the installPolicyGrant arguments (the calldata without its selector).
pub fn decode_install(body: &[u8]) -> Result<InstallCall, DecodeError> {
    let reader = Reader { data: body };
    // eth_abi counts the static grant tuple as one head slot: three slots.
    let end_of_offsets = 3 * 32;
    let grant_id: [u8; 32] = reader.word(0)?.try_into().map_err(|_| DecodeError)?;
    let key = reader.address(32)?;
    let bot = reader.bytes16(64)?;
    let valid_after = reader.small(96, 48)?;
    let valid_until = reader.small(128, 48)?;
    let remaining_calls = reader.small(160, 32)?;
    let offset = U256::from_be_slice(reader.word(192)?);
    if offset < U256::from(end_of_offsets) || offset >= U256::from(body.len()) {
        return Err(DecodeError);
    }
    let start = offset.to::<usize>();
    let length = U256::from_be_slice(reader.word(start)?);
    let items = start + 32;
    let available = body.len().saturating_sub(items) / (RULE_WORDS * 32);
    if length > U256::from(available) {
        return Err(DecodeError);
    }
    let mut rules = Vec::new();
    for index in 0..length.to::<usize>() {
        let at = items + index * RULE_WORDS * 32;
        rules.push(RawRule {
            kind: reader.small(at, 8)? as u8,
            target: reader.address(at + 32)?,
            token_in: reader.address(at + 64)?,
            counterparty: reader.address(at + 96)?,
            max_amount: reader.uint(at + 128, 256)?,
            max_secondary: reader.uint(at + 160, 256)?,
            max_daily: reader.uint(at + 192, 256)?,
            min_out_per_in_wad: reader.uint(at + 224, 256)?,
            max_deadline_delay: reader.small(at + 256, 48)?,
            usage_day: reader.small(at + 288, 48)?,
            used_today: reader.uint(at + 320, 256)?,
        });
    }
    Ok(InstallCall { grant_id, key, bot, valid_after, valid_until, remaining_calls, rules })
}

fn push_uint(out: &mut Vec<u8>, value: U256) {
    out.extend_from_slice(&value.to_be_bytes::<32>());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    push_uint(out, U256::from(value));
}

/// Canonical encoding of the installPolicyGrant arguments (no selector).
pub fn encode_install(call: &InstallCall) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 * (8 + RULE_WORDS * call.rules.len()));
    out.extend_from_slice(&call.grant_id);
    out.extend_from_slice(&call.key.word());
    let mut bot = [0u8; 32];
    bot[..16].copy_from_slice(&call.bot);
    out.extend_from_slice(&bot);
    push_u64(&mut out, call.valid_after);
    push_u64(&mut out, call.valid_until);
    push_u64(&mut out, call.remaining_calls);
    push_u64(&mut out, 7 * 32);
    push_u64(&mut out, call.rules.len() as u64);
    for rule in &call.rules {
        push_u64(&mut out, rule.kind as u64);
        out.extend_from_slice(&rule.target.word());
        out.extend_from_slice(&rule.token_in.word());
        out.extend_from_slice(&rule.counterparty.word());
        push_uint(&mut out, rule.max_amount);
        push_uint(&mut out, rule.max_secondary);
        push_uint(&mut out, rule.max_daily);
        push_uint(&mut out, rule.min_out_per_in_wad);
        push_u64(&mut out, rule.max_deadline_delay);
        push_u64(&mut out, rule.usage_day);
        push_uint(&mut out, rule.used_today);
    }
    out
}

/// Decode the key of a ``policyGrants``/``grants`` getter answer, checking
/// every returned field's padding like eth_abi.
pub fn decode_getter_key(data: &[u8], session: bool) -> Result<Address, DecodeError> {
    let reader = Reader { data };
    let key = reader.address(0)?;
    if session {
        reader.address(32)?;
        reader.word(64)?;
        reader.small(96, 48)?;
        reader.small(128, 48)?;
        reader.small(160, 32)?;
    } else {
        reader.bytes16(32)?;
        reader.small(64, 48)?;
        reader.small(96, 48)?;
        reader.small(128, 32)?;
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> InstallCall {
        InstallCall {
            grant_id: [1u8; 32],
            key: Address([0x33; 20]),
            bot: [2u8; 16],
            valid_after: 1,
            valid_until: 2,
            remaining_calls: 3,
            rules: vec![RawRule {
                kind: 0,
                target: Address([0x11; 20]),
                token_in: Address::ZERO,
                counterparty: Address([0x22; 20]),
                max_amount: U256::from(5),
                max_secondary: U256::ZERO,
                max_daily: U256::from(5),
                min_out_per_in_wad: U256::ZERO,
                max_deadline_delay: 0,
                usage_day: 0,
                used_today: U256::ZERO,
            }],
        }
    }

    fn word(value: u64) -> [u8; 32] {
        U256::from(value).to_be_bytes::<32>()
    }

    /// The same mutations as eth_abi 6 was probed with: decoded or refused alike.
    #[test]
    fn strictness_matches_eth_abi() {
        let good = encode_install(&sample());
        assert_eq!(decode_install(&good).unwrap(), sample());
        let canonical = |data: &[u8]| decode_install(data).map(|call| encode_install(&call) == data);
        assert_eq!(canonical(&[good.clone(), vec![0; 32]].concat()), Ok(false));
        assert_eq!(canonical(&[good.clone(), vec![0; 1]].concat()), Ok(false));
        let mut beyond = good.clone();
        beyond[192..224].copy_from_slice(&word(0x100));
        assert_eq!(canonical(&beyond), Ok(false));
        let mut gap = good.clone();
        gap[192..224].copy_from_slice(&word(0x80));
        gap.extend_from_slice(&[0; 32]);
        assert_eq!(canonical(&gap), Err(DecodeError));
        let mut unaligned = good.clone();
        unaligned[192..224].copy_from_slice(&word(0x61));
        unaligned.push(0);
        assert_eq!(canonical(&unaligned), Err(DecodeError));
        let mut zero = good.clone();
        zero[192..224].copy_from_slice(&word(0));
        assert_eq!(canonical(&zero), Err(DecodeError));
        let mut long = good.clone();
        long[224..256].copy_from_slice(&word(2));
        assert_eq!(canonical(&long), Err(DecodeError));
        for (at, name) in [(32, "address"), (64 + 20, "bytes16"), (8 * 32 + 30, "uint8"), (96, "uint48")] {
            let mut padded = good.clone();
            padded[at] = 1;
            assert_eq!(canonical(&padded), Err(DecodeError), "{name}");
        }
        assert_eq!(canonical(&good[..good.len() - 1]), Err(DecodeError));
        assert_eq!(canonical(&good[..100]), Err(DecodeError));
    }
}
