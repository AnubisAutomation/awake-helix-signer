//! Constants compiled into the signer. The website is never trusted for these.
//!
//! Every value here is public and was read from Anubis Chain 6714. A plan from
//! the website is signed only when it matches them exactly: the EIP-7702
//! delegate and its runtime code hash, the platform key that attests each
//! bot's session key (`ATTESTATION_ADDRESS`, read from
//! `attestation_address.txt` at the repository root at build time), the HELIX
//! contracts and methods a grant rule may name (identical to the allow-list the
//! Awake Helix website applies), and the bounds on lifetime and call count.
//!
//! Only `--dev-constants FILE` changes the delegate, its code hash, the
//! EntryPoint and the attestation address, and only against a loopback RPC.
//! The allow-list and bounds cannot be overridden.

use serde::Serialize;
use serde_json::Value;

use crate::address::{hex0x, keccak, Address};
use crate::error::{Error, Result};
use crate::pyfmt::py_str;

/// Anubis Chain ID.
pub const CHAIN_ID: u64 = 6714;
/// Default RPC.
pub const DEFAULT_RPC: &str = "https://rpc.anubispace.org";
/// Official website API.
pub const DEFAULT_API: &str = "https://anubis.sivilization.com";
/// Native gas token symbol.
pub const GAS_SYMBOL: &str = "DAI";

/// Helix7702Diamond, the pinned EIP-7702 delegate.
pub const IMPLEMENTATION: &str = "0xdaFCb6c6B3d2Af124d58c5e05Ce44ABd8C8ff56A";
/// keccak256 of eth_getCode(IMPLEMENTATION) on chain 6714 (7217 bytes).
pub const IMPLEMENTATION_CODE_HASH: &str = "0x68525a27d760b50b797d6c7ba18b247c8530487b5e95ef820b859d36749d8e3f";
/// ERC-4337 EntryPoint the implementation is bound to.
pub const ENTRY_POINT: &str = "0xf7697e63911f73C72375886f34658d4416986DD6";
/// The former single hosted session key: refused for new grants.
pub const LEGACY_SESSION_KEY: &str = "0x8Efa0a5e3083B1843Cf0A03dCb79131A3F4144B9";
/// keccak256("awake-helix: no attestation address was set for this build")[12:].
pub const ATTESTATION_PLACEHOLDER: &str = "0xF049968F26EC5CA1D32E9668153ccE7a789CD54F";
/// The platform attestation address of this build (`attestation_address.txt`).
pub const ATTESTATION_ADDRESS: &str = env!("HELIX_ATTESTATION_ADDRESS");

/// HELIX contracts on Anubis.
pub const DAI: &str = "0x83fd06F0846d9D90B3016bF670Efe2E0B11cDe14";
/// PowerLedger.
pub const LEDGER: &str = "0x9E68F61E2615cc1D2C4a2D0026bFc1EBFdf68C1b";
/// LGNS.
pub const LGNS: &str = "0x4D1D808a081FdAc440703b3765FC61f8028C06B8";
/// aiLGNS.
pub const AILGNS: &str = "0x256EdB652db43E721EC6A12B6b51b6967D3bb8cB";
/// Turbine.
pub const TURBINE: &str = "0xE884A336550a4482Ca6A17A3F93aa30Ed4eD9BaD";
/// HELIX Router.
pub const HELIX_ROUTER: &str = "0x0527935979d10685B8571Fa02A8DEDbd6f3024E3";
/// RocketSwap Router.
pub const ROCKETSWAP_ROUTER: &str = "0x3E412E02B6157fBE80b6C6697f3Ce1142E629019";
/// Community Vault.
pub const COMMUNITY_VAULT: &str = "0x3DEea5f638cA0dFb03A0873CF4c0b90BA50E1aA2";
/// The zero address.
pub const ZERO: &str = "0x0000000000000000000000000000000000000000";

/// Pinned contract names for the summary.
pub const CONTRACT_NAMES: &[(&str, &str)] = &[
    (DAI, "DAI"),
    (LEDGER, "PowerLedger"),
    (LGNS, "LGNS"),
    (AILGNS, "aiLGNS"),
    (TURBINE, "Turbine"),
    (HELIX_ROUTER, "HELIX Router"),
    (ROCKETSWAP_ROUTER, "RocketSwap Router"),
    (COMMUNITY_VAULT, "Community Vault"),
];

/// Helix7702Account.RuleKind -> canonical method each rule kind may call.
pub const RULE_METHODS: [&str; 10] = [
    "approve(address,uint256)",
    "participate(uint256)",
    "burnForPower(uint256)",
    "swapExactIn(address,address,uint256,uint256,address,uint256)",
    "swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)",
    "activate(uint256,uint256,uint256)",
    "claimStatic(uint256)",
    "claimDynamic(uint256)",
    "claimDynamicWithRoot(uint256,bytes32[],uint256)",
    "claimUnlocked(uint256[])",
];

/// RuleKind -> every allowed (target, tokenIn, counterparty). For approvals the
/// target is the token and the counterparty the only permitted spender.
/// (rule kind, allowed targets) pairs.
#[allow(clippy::type_complexity)]
pub const RULE_ALLOWLIST: &[(u8, &[(&str, &str, &str)])] = &[
    (
        0,
        &[
            (DAI, ZERO, LEDGER),
            (DAI, ZERO, TURBINE),
            (DAI, ZERO, ROCKETSWAP_ROUTER),
            (AILGNS, ZERO, HELIX_ROUTER),
            (LGNS, ZERO, LEDGER),
        ],
    ),
    (1, &[(LEDGER, ZERO, ZERO)]),
    (2, &[(LEDGER, ZERO, ZERO)]),
    (3, &[(HELIX_ROUTER, AILGNS, DAI)]),
    (4, &[(ROCKETSWAP_ROUTER, DAI, LGNS)]),
    (5, &[(TURBINE, ZERO, ZERO)]),
    (6, &[(COMMUNITY_VAULT, ZERO, ZERO)]),
    (7, &[(COMMUNITY_VAULT, ZERO, ZERO)]),
    (8, &[(COMMUNITY_VAULT, ZERO, ZERO)]),
    (9, &[(TURBINE, ZERO, ZERO)]),
];
/// Rule kinds whose calls carry a protocol deadline (swaps and activation).
pub const DEADLINE_KINDS: [u8; 3] = [3, 4, 5];
/// Swap rule kinds.
pub const SWAP_KINDS: [u8; 2] = [3, 4];
/// The owner may extend a grant up to 90 days.
pub const MAX_GRANT_DAYS: u64 = 90;
/// 90 days plus one hour of clock skew.
pub const MAX_VALIDITY_SECONDS: u64 = MAX_GRANT_DAYS * 86400 + 3600;
/// A grant must stay valid at least this long after signing.
pub const MIN_REMAINING_SECONDS: u64 = 600;
/// validAfter may lie at most this far in the future.
pub const MAX_START_DELAY_SECONDS: u64 = 600;
/// Total bot operations a grant may allow.
pub const MAX_CALLS: u64 = 4096;
/// Rules per grant.
pub const MAX_RULES: usize = 16;
/// Swap/activation deadline bound.
pub const MAX_DEADLINE_DELAY_SECONDS: u64 = 3600;

/// ABI type of the PolicyGrant tuple.
pub const GRANT_TYPE: &str = "(address,bytes16,uint48,uint48,uint32)";
/// ABI type of one Rule tuple.
pub const RULE_TYPE: &str = "(uint8,address,address,address,uint256,uint256,uint256,uint256,uint48,uint48,uint256)";
/// installPolicyGrant(bytes32,(address,bytes16,uint48,uint48,uint32),(uint8,…)[]).
pub const INSTALL_SIGNATURE: &str = "installPolicyGrant(bytes32,(address,bytes16,uint48,uint48,uint32),(uint8,address,address,address,uint256,uint256,uint256,uint256,uint48,uint48,uint256)[])";
/// Revoke method of a policy grant.
pub const REVOKE_POLICY_SIGNATURE: &str = "revokePolicyGrant(bytes32)";
/// Revoke method of a session grant.
pub const REVOKE_SESSION_SIGNATURE: &str = "revokeGrant(bytes32)";
/// Getter of a policy grant.
pub const POLICY_GETTER: &str = "policyGrants(bytes32)";
/// Getter of a session grant.
pub const SESSION_GETTER: &str = "grants(bytes32)";
/// Install event.
pub const POLICY_INSTALLED_EVENT: &str = "PolicyGrantInstalled(bytes32,address)";
/// Grant plan schema (version 2 added sessionKeyAttestation).
pub const PLAN_SCHEMA: &str = "awake-helix-signer-plan/2";
/// Revocation plan schemas (no attestation needed).
pub const REVOKE_PLAN_SCHEMAS: [&str; 2] = ["awake-helix-signer-plan/1", PLAN_SCHEMA];

/// Session key attestation document version.
pub const ATTESTATION_VERSION: u64 = 1;
/// EIP-712 domain name.
pub const ATTESTATION_NAME: &str = "Awake Helix Session Key Attestation";
/// EIP-712 domain version.
pub const ATTESTATION_DOMAIN_VERSION: &str = "1";

/// The 0x-prefixed lowercase four-byte selector of a canonical signature.
pub fn selector(signature: &str) -> String {
    hex0x(&keccak(signature.as_bytes())[..4])
}

/// installPolicyGrant selector (0x853051bd).
pub fn install_selector() -> String {
    selector(INSTALL_SIGNATURE)
}

/// Selector of the revoke method for ``policy``/``session``.
pub fn revoke_selector(kind: GrantKind) -> String {
    selector(kind.revoke_signature())
}

/// Topic 0 of PolicyGrantInstalled.
pub fn policy_installed_topic() -> String {
    hex0x(&keccak(POLICY_INSTALLED_EVENT.as_bytes()))
}

/// Name of a pinned HELIX contract, or "".
pub fn contract_name(address: &str) -> &'static str {
    let lower = address.to_lowercase();
    CONTRACT_NAMES.iter().find(|(item, _)| item.to_lowercase() == lower).map(|(_, name)| *name).unwrap_or("")
}

/// The allowed (target, tokenIn, counterparty) of one rule kind.
pub fn allowed_for(kind: u8) -> Option<&'static [(&'static str, &'static str, &'static str)]> {
    RULE_ALLOWLIST.iter().find(|(item, _)| *item == kind).map(|(_, entries)| *entries)
}

/// A grant's on-chain kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GrantKind {
    /// installPolicyGrant / revokePolicyGrant.
    Policy,
    /// installGrant / revokeGrant (older session grants).
    Session,
}

impl GrantKind {
    /// ``policy`` or ``session``.
    pub fn as_str(&self) -> &'static str {
        match self {
            GrantKind::Policy => "policy",
            GrantKind::Session => "session",
        }
    }

    /// Parse ``policy``/``session``.
    pub fn parse(text: &str) -> Option<GrantKind> {
        match text {
            "policy" => Some(GrantKind::Policy),
            "session" => Some(GrantKind::Session),
            _ => None,
        }
    }

    /// Revoke method signature.
    pub fn revoke_signature(&self) -> &'static str {
        match self {
            GrantKind::Policy => REVOKE_POLICY_SIGNATURE,
            GrantKind::Session => REVOKE_SESSION_SIGNATURE,
        }
    }

    /// Getter signature and the number of 32-byte words it returns.
    pub fn getter(&self) -> (&'static str, usize) {
        match self {
            GrantKind::Policy => (POLICY_GETTER, 5),
            GrantKind::Session => (SESSION_GETTER, 6),
        }
    }
}

/// The values a plan is verified against.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Constants {
    /// Required chain (6714).
    pub chain_id: u64,
    /// EIP-7702 delegate.
    pub implementation: Address,
    /// keccak of its runtime code (lowercase 0x hex), None to skip (dev only).
    pub implementation_code_hash: Option<String>,
    /// ERC-4337 EntryPoint.
    pub entry_point: Address,
    /// Platform key that attests session keys.
    pub attestation_address: Address,
    /// Former single key, refused for new grants.
    pub legacy_session_key: Address,
    /// True when loaded from ``--dev-constants``.
    pub development: bool,
}

/// The pinned production constants.
pub fn production() -> Constants {
    Constants {
        chain_id: CHAIN_ID,
        implementation: Address::constant(IMPLEMENTATION),
        implementation_code_hash: Some(IMPLEMENTATION_CODE_HASH.to_string()),
        entry_point: Address::constant(ENTRY_POINT),
        attestation_address: Address::constant(ATTESTATION_ADDRESS),
        legacy_session_key: Address::constant(LEGACY_SESSION_KEY),
        development: false,
    }
}

const OVERRIDE_FIELDS: [&str; 5] =
    ["implementation", "implementationCodeHash", "entryPoint", "attestationAddress", "legacySessionKey"];

impl Constants {
    /// A development copy with delegate, EntryPoint and keys replaced.
    ///
    /// ``values``: ``implementation``, ``implementationCodeHash`` (optional),
    /// ``entryPoint`` (optional), ``attestationAddress``, ``legacySessionKey``
    /// (optional). The message of every refusal is the Python one.
    pub fn with_overrides(&self, values: &Value) -> Result<Constants> {
        let map = values.as_object().ok_or_else(|| Error::plan("--dev-constants must be a JSON object."))?;
        let mut unknown: Vec<&str> =
            map.keys().map(String::as_str).filter(|key| !OVERRIDE_FIELDS.contains(key)).collect();
        if !unknown.is_empty() {
            unknown.sort();
            return Err(Error::plan(format!("Unknown dev-constants fields: {}", unknown.join(", "))));
        }
        let required = || Error::plan("dev-constants needs implementation and attestationAddress addresses.");
        let address = |value: Option<&Value>, default: Option<&str>| -> Result<Address> {
            let text = match value {
                Some(value) if crate::pyfmt::truthy(value) || default.is_none() => py_str(value),
                _ => match default {
                    Some(default) => default.to_string(),
                    None => return Err(required()),
                },
            };
            Address::parse(&text).ok_or_else(required)
        };
        let implementation = address(map.get("implementation"), None)?;
        let attestation = address(map.get("attestationAddress"), None)?;
        let entry_point = address(map.get("entryPoint"), Some(ZERO))?;
        let legacy = address(map.get("legacySessionKey"), Some(LEGACY_SESSION_KEY))?;
        let code_hash = match map.get("implementationCodeHash") {
            None | Some(Value::Null) => None,
            Some(Value::String(text)) if text.chars().count() == 66 && text.starts_with("0x") => Some(text.to_lowercase()),
            Some(_) => return Err(Error::plan("implementationCodeHash must be a 0x-prefixed 32-byte hash.")),
        };
        Ok(Constants {
            chain_id: self.chain_id,
            implementation,
            implementation_code_hash: code_hash,
            entry_point,
            attestation_address: attestation,
            legacy_session_key: legacy,
            development: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn selectors_and_pins() {
        assert_eq!(install_selector(), "0x853051bd");
        assert_eq!(revoke_selector(GrantKind::Policy), "0x4f2c9f0c");
        assert_eq!(RULE_ALLOWLIST.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(), (0..10).collect::<Vec<_>>());
        assert_eq!(IMPLEMENTATION_CODE_HASH, "0x68525a27d760b50b797d6c7ba18b247c8530487b5e95ef820b859d36749d8e3f");
        assert!(Address::is_checksummed(ATTESTATION_ADDRESS));
        assert!(!Address::constant(ATTESTATION_ADDRESS).is_zero());
        assert_eq!(production().attestation_address.to_checksum(), ATTESTATION_ADDRESS);
        let derived = keccak(b"awake-helix: no attestation address was set for this build");
        assert_eq!(ATTESTATION_PLACEHOLDER.to_lowercase(), hex0x(&derived[12..]));
        assert!(Address::is_checksummed(ATTESTATION_PLACEHOLDER));
        for name in [DAI, LEDGER, LGNS, AILGNS, TURBINE, HELIX_ROUTER, ROCKETSWAP_ROUTER, COMMUNITY_VAULT, IMPLEMENTATION, ENTRY_POINT, LEGACY_SESSION_KEY] {
            assert!(Address::is_checksummed(name), "{name}");
        }
    }

    #[test]
    fn committed_file_is_the_pinned_constant() {
        // Unless AWAKE_HELIX_ATTESTATION_FILE named another file for this build.
        if std::env::var_os("AWAKE_HELIX_ATTESTATION_FILE").is_some_and(|file| !file.is_empty()) {
            return;
        }
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../attestation_address.txt");
        let text = std::fs::read_to_string(path).unwrap_or_else(|error| panic!("{path}: {error}"));
        assert_eq!(text.trim(), ATTESTATION_ADDRESS);
    }

    #[test]
    fn overrides() {
        let attestor = "0x3434343434343434343434343434343434343434";
        let dev = production().with_overrides(&json!({"implementation": IMPLEMENTATION, "attestationAddress": attestor})).unwrap();
        assert!(dev.development);
        assert_eq!(dev.attestation_address, Address::constant(attestor));
        assert_eq!(dev.legacy_session_key, Address::constant(LEGACY_SESSION_KEY));
        assert_eq!(dev.entry_point, Address::ZERO);
        assert_eq!(dev.implementation_code_hash, None);
        let legacy = "0x5656565656565656565656565656565656565656";
        let with_legacy = production()
            .with_overrides(&json!({"implementation": IMPLEMENTATION, "attestationAddress": attestor, "legacySessionKey": legacy}))
            .unwrap();
        assert_eq!(with_legacy.legacy_session_key, Address::constant(legacy));
        assert!(production().with_overrides(&json!({"implementation": IMPLEMENTATION})).is_err());
        let unknown = production()
            .with_overrides(&json!({"implementation": IMPLEMENTATION, "attestationAddress": attestor, "sessionKey": legacy, "ruleAllowlist": {}}))
            .unwrap_err();
        assert_eq!(unknown.message(), "Unknown dev-constants fields: ruleAllowlist, sessionKey");
        let bad_hash = production()
            .with_overrides(&json!({"implementation": IMPLEMENTATION, "attestationAddress": attestor, "implementationCodeHash": "0x12"}))
            .unwrap_err();
        assert!(bad_hash.message().contains("32-byte hash"));
        let upper = production()
            .with_overrides(&json!({"implementation": IMPLEMENTATION, "attestationAddress": attestor, "implementationCodeHash": format!("0x{}", "AB".repeat(32))}))
            .unwrap();
        assert_eq!(upper.implementation_code_hash.unwrap(), format!("0x{}", "ab".repeat(32)));
    }
}
