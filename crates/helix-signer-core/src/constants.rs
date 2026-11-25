//! Constants compiled into the signer. The website is never trusted for these.
//!
//! Every value here is public and was read from Anubis Chain 6714. A plan from
//! the website is signed only when it matches them exactly: the EIP-7702
//! delegates and their runtime code hashes (the version 2 Diamond every grant
//! installs with, and the version 1 Diamond older wallets may still use), the
//! platform key that attests each bot's session key (`ATTESTATION_ADDRESS`,
//! read from `attestation_address.txt` at the repository root at build time),
//! the HELIX and Origin contracts and methods a grant rule may name (identical
//! to the allow-list the Anubis Automation website applies), and the bounds on
//! lifetime and call count.
//!
//! Only `--dev-constants FILE` changes the delegates, their code hashes, the
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

/// Helix7702Diamond version 2 (Helix7702AccountV2: rule kinds 0-26), the
/// pinned EIP-7702 delegate every grant installs with.
pub const IMPLEMENTATION: &str = "0xA37eBF54868c76B52A35741859d9835609d48695";
/// keccak256 of eth_getCode(IMPLEMENTATION) on chain 6714 (7217 bytes).
pub const IMPLEMENTATION_CODE_HASH: &str = "0x59e8a79333ae7ada0b3465b8da009d336379888004712711cc62d4658164c9f2";
/// Helix7702Diamond version 1 (Helix7702Account: rule kinds 0-9). Wallets
/// still delegated to it can revoke with a plain self-call; a new grant
/// re-delegates them to version 2 in the same transaction (same storage
/// layout and selectors, so their grants are kept).
pub const IMPLEMENTATION_V1: &str = "0xdaFCb6c6B3d2Af124d58c5e05Ce44ABd8C8ff56A";
/// keccak256 of eth_getCode(IMPLEMENTATION_V1) on chain 6714 (7217 bytes).
pub const IMPLEMENTATION_V1_CODE_HASH: &str = "0x68525a27d760b50b797d6c7ba18b247c8530487b5e95ef820b859d36749d8e3f";
/// ERC-4337 EntryPoint both implementations are bound to.
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

/// Origin (origindefi) contracts on Anubis, checked on chain on 2026-11-24.
/// New Turbo 2.5x.
pub const NEW_TURBO_25X: &str = "0x0664F1369209677FEcb279F5EC3Df1E53a22212e";
/// New Turbo 4x.
pub const NEW_TURBO_4X: &str = "0x229e0aA54ebcFD887a1c06bc649AD1AFcA87486A";
/// New Turbo Community.
pub const NEW_TURBO_COMMUNITY: &str = "0x8250F8EeaAe5B6e21043fbD8c61C70E1B0906109";
/// Community Distributor.
pub const COMMUNITY_DISTRIBUTOR: &str = "0x71B514b8d08F61e39e24442c2Fc83297584C1Dd6";
/// Long Staking 360.
pub const LONG_STAKING_360: &str = "0x88ea98af226Cd4402A3873400308a4D78784eCE6";
/// Long Staking 600 (closed to new stakes; existing stakes still pay).
pub const LONG_STAKING_600: &str = "0x04eD22c6d1D020A9B5e032E93D79ab28293EF72f";
/// Energy Staking.
pub const ENERGY_STAKING: &str = "0x1E5FeeC473F7F445FC7F5FeEC0beABB2270b0b4E";
/// Energy Burner.
pub const ENERGY_BURNER: &str = "0x31Fe4354218e387a236c531C5cCeE8149474E773";
/// Origin's own turbine (not the HELIX `TURBINE`).
pub const ORIGIN_TURBINE: &str = "0x92B53785090F6FE0717Ca3cF5dB8f8040d3B070b";
/// Burn Bond.
pub const BURN_BOND: &str = "0x11b10C9827c5B7071E96fcAa143B4e6E86b17c69";
/// Burn Fixed.
pub const BURN_FIXED: &str = "0x3f403751975e1EB06d95901f7FF246513444E71F";
/// Burn Bond Ranking Reward.
pub const BURN_BOND_REWARD: &str = "0x6170743b440696e17c9c0dbC551E0B8C010694d8";
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
    (NEW_TURBO_25X, "New Turbo 2.5x"),
    (NEW_TURBO_4X, "New Turbo 4x"),
    (NEW_TURBO_COMMUNITY, "New Turbo Community"),
    (COMMUNITY_DISTRIBUTOR, "Community Distributor"),
    (LONG_STAKING_360, "Long Staking 360"),
    (LONG_STAKING_600, "Long Staking 600"),
    (ENERGY_STAKING, "Energy Staking"),
    (ENERGY_BURNER, "Energy Burner"),
    (ORIGIN_TURBINE, "Origin Turbine"),
    (BURN_BOND, "Burn Bond"),
    (BURN_FIXED, "Burn Fixed"),
    (BURN_BOND_REWARD, "Burn Bond Ranking Reward"),
];

/// Helix7702AccountV2.RuleKind -> canonical method each rule kind may call
/// (``_selector``). Kinds 0-9 are version 1's; 10-26 are the Origin kinds of
/// version 2. Method names repeat (participate 1/10, activate 5/11, claim
/// 14/18): a rule is told apart by its kind and target, never by its name.
pub const RULE_METHODS: [&str; 27] = [
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
    "participate(uint256,uint256,uint256)",
    "activate(uint256,uint256,uint256,uint256,uint256,uint256)",
    "sell(uint256,uint256,uint256)",
    "stakeAgain(uint256)",
    "claim()",
    "stake(uint256)",
    "claimInterest(uint256,uint256)",
    "unstakePrincipal(uint256)",
    "claim(uint256)",
    "claimAll()",
    "turbineExtraInterest(uint256,uint256)",
    "depositDAI(uint256)",
    "depositLGNS(uint256)",
    "burn(uint256)",
    "claimReward()",
    "silence(address,uint256,uint256)",
    "redeemSilence(address,uint256)",
];

/// RuleKind -> unit and decimals of its per-call and daily caps
/// (``helix_runtime/rule_kinds.py``). None: the unit follows the rule's token
/// (kind 0: the approved token; kinds 3 and 4: the input token). "calls":
/// the caps count calls (see ``COUNTED_KINDS``).
pub const RULE_UNITS: [(Option<&str>, u32); 27] = [
    (None, 0),
    (Some("DAI"), 18),
    (Some("LGNS"), 9),
    (None, 0),
    (None, 0),
    (Some("aiLGNS"), 18),
    (Some("aiLGNS"), 18),
    (Some("aiLGNS"), 18),
    (Some("aiLGNS"), 18),
    (Some("lock IDs"), 0),
    (Some("DAI"), 18),
    (Some("LGNS"), 9),
    (Some("LGNS"), 9),
    (Some("LGNS"), 9),
    (Some("calls"), 0),
    (Some("LGNS"), 9),
    (Some("LGNS"), 9),
    (Some("calls"), 0),
    (Some("calls"), 0),
    (Some("calls"), 0),
    (Some("LGNS"), 9),
    (Some("DAI"), 18),
    (Some("LGNS"), 9),
    (Some("LGNS"), 9),
    (Some("calls"), 0),
    (Some("DAI"), 18),
    (Some("calls"), 0),
];

/// The first rule kind of the version 2 account (the Origin kinds).
pub const FIRST_VERSION_2_KIND: u8 = 10;

/// RuleKind -> every allowed (target, tokenIn, counterparty). For approvals the
/// target is the token and the counterparty the only permitted spender.
/// Kinds 0-9 are the HELIX allow-list; the Origin entries (the kind 0
/// approvals after the HELIX ones, and kinds 10-26) are
/// ``helix_runtime/origin_contracts.py`` ``ORIGIN_RULE_ALLOWLIST``.
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
            // Origin approvals.
            (DAI, ZERO, NEW_TURBO_25X),
            (DAI, ZERO, NEW_TURBO_4X),
            (DAI, ZERO, NEW_TURBO_COMMUNITY),
            (LGNS, ZERO, LONG_STAKING_360),
            (LGNS, ZERO, ENERGY_STAKING),
            (DAI, ZERO, BURN_BOND),
            (LGNS, ZERO, BURN_BOND),
            (LGNS, ZERO, ENERGY_BURNER),
            (DAI, ZERO, ORIGIN_TURBINE),
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
    (10, &[(NEW_TURBO_25X, ZERO, ZERO), (NEW_TURBO_4X, ZERO, ZERO), (NEW_TURBO_COMMUNITY, ZERO, ZERO)]),
    (11, &[(NEW_TURBO_25X, ZERO, ZERO), (NEW_TURBO_4X, ZERO, ZERO), (NEW_TURBO_COMMUNITY, ZERO, ZERO)]),
    (12, &[(NEW_TURBO_25X, ZERO, ZERO), (NEW_TURBO_4X, ZERO, ZERO), (NEW_TURBO_COMMUNITY, ZERO, ZERO)]),
    (13, &[(NEW_TURBO_25X, ZERO, ZERO), (NEW_TURBO_4X, ZERO, ZERO), (NEW_TURBO_COMMUNITY, ZERO, ZERO)]),
    (14, &[(COMMUNITY_DISTRIBUTOR, ZERO, ZERO)]),
    (15, &[(LONG_STAKING_360, ZERO, ZERO), (ENERGY_STAKING, ZERO, ZERO)]),
    (16, &[(LONG_STAKING_360, ZERO, ZERO), (LONG_STAKING_600, ZERO, ZERO), (ENERGY_STAKING, ZERO, ZERO)]),
    (17, &[(LONG_STAKING_360, ZERO, ZERO), (LONG_STAKING_600, ZERO, ZERO), (ENERGY_STAKING, ZERO, ZERO)]),
    (18, &[(BURN_FIXED, ZERO, ZERO), (BURN_BOND, ZERO, ZERO)]),
    (19, &[(BURN_FIXED, ZERO, ZERO), (BURN_BOND, ZERO, ZERO)]),
    (20, &[(LONG_STAKING_360, ZERO, ZERO), (LONG_STAKING_600, ZERO, ZERO)]),
    (21, &[(BURN_BOND, ZERO, ZERO)]),
    (22, &[(BURN_BOND, ZERO, ZERO)]),
    (23, &[(ENERGY_BURNER, ZERO, ZERO)]),
    (24, &[(BURN_BOND_REWARD, ZERO, ZERO)]),
    (25, &[(ORIGIN_TURBINE, ZERO, ZERO)]),
    (26, &[(ORIGIN_TURBINE, ZERO, ZERO)]),
];
/// Rule kinds whose rule carries a price floor (minOutPerInWad) and a
/// deadline: the swaps and New Turbo participate, activate and sell.
pub const SWAP_KINDS: [u8; 5] = [3, 4, 10, 11, 12];
/// Rule kinds whose calls carry a protocol deadline (the swap kinds, Turbine
/// activation and Origin turbine silence).
pub const DEADLINE_KINDS: [u8; 7] = [3, 4, 5, 10, 11, 12, 25];
/// Rule kinds with a secondary DAI cap (maxSecondary): activations.
pub const SECONDARY_KINDS: [u8; 2] = [5, 11];
/// Rule kinds counted one per call: maxAmount is 1 and maxDaily the number
/// of calls per UTC day.
pub const COUNTED_KINDS: [u8; 6] = [14, 17, 18, 19, 24, 26];
/// Rule kinds whose call names a recipient that must be the account itself.
pub const OWN_RECIPIENT_KINDS: [u8; 2] = [25, 26];
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
/// Grant plan schema (version 2 added sessionKeyAttestation); the only one a
/// grant plan may name.
pub const PLAN_SCHEMA: &str = "anubisauto-signer-plan/2";
/// Revocation plan schema the website writes.
pub const REVOKE_PLAN_SCHEMA: &str = "anubisauto-signer-plan/1";
/// Schemas of the signers before 0.7.0, accepted for revocations only, so
/// grants made with the old app can still be revoked.
pub const LEGACY_REVOKE_PLAN_SCHEMAS: [&str; 2] = ["awake-helix-signer-plan/1", "awake-helix-signer-plan/2"];
/// Revocation plan schemas (no attestation needed).
pub const REVOKE_PLAN_SCHEMAS: [&str; 4] = [REVOKE_PLAN_SCHEMA, PLAN_SCHEMA, LEGACY_REVOKE_PLAN_SCHEMAS[0], LEGACY_REVOKE_PLAN_SCHEMAS[1]];

/// Session key attestation document version.
pub const ATTESTATION_VERSION: u64 = 1;
/// EIP-712 domain name.
pub const ATTESTATION_NAME: &str = "Anubis Automation Session Key Attestation";
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

/// Name of a pinned HELIX or Origin contract, or "".
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
    /// EIP-7702 delegate of every grant: the version 2 Diamond.
    pub implementation: Address,
    /// keccak of its runtime code (lowercase 0x hex), None to skip (dev only).
    pub implementation_code_hash: Option<String>,
    /// The version 1 Diamond: wallets delegated to it may revoke with a plain
    /// self-call, and a grant re-delegates them to ``implementation``.
    #[serde(rename = "implementationV1")]
    pub implementation_v1: Address,
    /// keccak of its runtime code (lowercase 0x hex), None to skip (dev only).
    #[serde(rename = "implementationV1CodeHash")]
    pub implementation_v1_code_hash: Option<String>,
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
        implementation_v1: Address::constant(IMPLEMENTATION_V1),
        implementation_v1_code_hash: Some(IMPLEMENTATION_V1_CODE_HASH.to_string()),
        entry_point: Address::constant(ENTRY_POINT),
        attestation_address: Address::constant(ATTESTATION_ADDRESS),
        legacy_session_key: Address::constant(LEGACY_SESSION_KEY),
        development: false,
    }
}

const OVERRIDE_FIELDS: [&str; 7] = [
    "implementation",
    "implementationCodeHash",
    "implementationV1",
    "implementationV1CodeHash",
    "entryPoint",
    "attestationAddress",
    "legacySessionKey",
];

fn code_hash_of(value: Option<&Value>, field: &str) -> Result<Option<String>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if text.chars().count() == 66 && text.starts_with("0x") => Ok(Some(text.to_lowercase())),
        Some(_) => Err(Error::plan(format!("{field} must be a 0x-prefixed 32-byte hash."))),
    }
}

impl Constants {
    /// A development copy with delegates, EntryPoint and keys replaced.
    ///
    /// ``values``: ``implementation``, ``implementationCodeHash`` (optional),
    /// ``implementationV1`` and ``implementationV1CodeHash`` (optional: the
    /// pinned version 1 Diamond and its hash when ``implementationV1`` is not
    /// named; no hash check when only the address is named), ``entryPoint``
    /// (optional), ``attestationAddress``, ``legacySessionKey`` (optional).
    /// The message of every refusal is the Python one.
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
        let code_hash = code_hash_of(map.get("implementationCodeHash"), "implementationCodeHash")?;
        let named_v1 = map.get("implementationV1").filter(|value| crate::pyfmt::truthy(value));
        let implementation_v1 = match named_v1 {
            None => Address::constant(IMPLEMENTATION_V1),
            Some(value) => Address::parse(&py_str(value)).ok_or_else(|| Error::plan("implementationV1 must be an address."))?,
        };
        let v1_code_hash = match (named_v1, map.get("implementationV1CodeHash")) {
            (None, None | Some(Value::Null)) => Some(IMPLEMENTATION_V1_CODE_HASH.to_string()),
            (_, value) => code_hash_of(value, "implementationV1CodeHash")?,
        };
        Ok(Constants {
            chain_id: self.chain_id,
            implementation,
            implementation_code_hash: code_hash,
            implementation_v1,
            implementation_v1_code_hash: v1_code_hash,
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
        assert_eq!(RULE_ALLOWLIST.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(), (0..27).collect::<Vec<_>>());
        assert_eq!(IMPLEMENTATION, "0xA37eBF54868c76B52A35741859d9835609d48695");
        assert_eq!(IMPLEMENTATION_CODE_HASH, "0x59e8a79333ae7ada0b3465b8da009d336379888004712711cc62d4658164c9f2");
        assert_eq!(IMPLEMENTATION_V1, "0xdaFCb6c6B3d2Af124d58c5e05Ce44ABd8C8ff56A");
        assert_eq!(IMPLEMENTATION_V1_CODE_HASH, "0x68525a27d760b50b797d6c7ba18b247c8530487b5e95ef820b859d36749d8e3f");
        let pinned = production();
        assert_eq!((pinned.implementation, pinned.implementation_v1), (Address::constant(IMPLEMENTATION), Address::constant(IMPLEMENTATION_V1)));
        assert_eq!(pinned.implementation_v1_code_hash.as_deref(), Some(IMPLEMENTATION_V1_CODE_HASH));
        let shown = serde_json::to_value(&pinned).unwrap();
        assert_eq!((shown["implementationV1"].as_str(), shown["implementationV1CodeHash"].as_str()), (Some(IMPLEMENTATION_V1), Some(IMPLEMENTATION_V1_CODE_HASH)));
        assert!(Address::is_checksummed(ATTESTATION_ADDRESS));
        assert!(!Address::constant(ATTESTATION_ADDRESS).is_zero());
        assert_eq!(production().attestation_address.to_checksum(), ATTESTATION_ADDRESS);
        let derived = keccak(b"awake-helix: no attestation address was set for this build");
        assert_eq!(ATTESTATION_PLACEHOLDER.to_lowercase(), hex0x(&derived[12..]));
        assert!(Address::is_checksummed(ATTESTATION_PLACEHOLDER));
        for name in [DAI, LEDGER, LGNS, AILGNS, TURBINE, HELIX_ROUTER, ROCKETSWAP_ROUTER, COMMUNITY_VAULT, IMPLEMENTATION, IMPLEMENTATION_V1, ENTRY_POINT, LEGACY_SESSION_KEY] {
            assert!(Address::is_checksummed(name), "{name}");
        }
        for (address, _) in CONTRACT_NAMES {
            assert!(Address::is_checksummed(address), "{address}");
        }
    }

    #[test]
    fn rule_kinds_follow_the_v2_contract() {
        // A few selectors of Helix7702AccountV2._selector.
        for (kind, expected) in [(0usize, "0x095ea7b3"), (14, "0x4e71d92d"), (18, "0x379607f5"), (19, "0xd1058e59"), (24, "0xb88a802f")] {
            assert_eq!(selector(RULE_METHODS[kind]), expected, "kind {kind}");
        }
        let names: Vec<&str> = RULE_METHODS.iter().map(|signature| &signature[..signature.find('(').unwrap()]).collect();
        assert_eq!((names[1], names[10], names[5], names[11], names[14], names[18]), ("participate", "participate", "activate", "activate", "claim", "claim"));
        // Counted kinds are exactly the kinds whose caps count calls.
        let counted: Vec<u8> = (0..27u8).filter(|kind| RULE_UNITS[*kind as usize].0 == Some("calls")).collect();
        assert_eq!(counted, COUNTED_KINDS.to_vec());
        assert!(SECONDARY_KINDS.iter().chain(&SWAP_KINDS).all(|kind| DEADLINE_KINDS.contains(kind)));
        // The Origin allow-list: kind 0 adds nine approvals after the five HELIX ones
        // (DAI -> PowerLedger stays first), Origin kinds name no token and no counterparty,
        // and every address has a pinned name.
        let sizes: Vec<usize> = RULE_ALLOWLIST.iter().map(|(_, entries)| entries.len()).collect();
        assert_eq!(sizes, [14, 1, 1, 1, 1, 1, 1, 1, 1, 1, 3, 3, 3, 3, 1, 2, 3, 3, 2, 2, 2, 1, 1, 1, 1, 1, 1]);
        assert_eq!(allowed_for(0).unwrap()[0], (DAI, ZERO, LEDGER));
        for (kind, entries) in RULE_ALLOWLIST {
            for (target, token_in, counterparty) in entries.iter() {
                assert!(!contract_name(target).is_empty(), "{kind} {target}");
                if *kind >= FIRST_VERSION_2_KIND {
                    assert_eq!((*token_in, *counterparty), (ZERO, ZERO), "{kind}");
                }
            }
        }
        assert_eq!(contract_name(ORIGIN_TURBINE), "Origin Turbine");
        assert_eq!(contract_name(TURBINE), "Turbine");
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
        // The version 1 Diamond: the pinned one unless named; named without a hash, no hash check.
        assert_eq!((dev.implementation_v1, dev.implementation_v1_code_hash.as_deref()), (Address::constant(IMPLEMENTATION_V1), Some(IMPLEMENTATION_V1_CODE_HASH)));
        let v1 = "0x7878787878787878787878787878787878787878";
        let named = production().with_overrides(&json!({"implementation": IMPLEMENTATION, "attestationAddress": attestor, "implementationV1": v1})).unwrap();
        assert_eq!((named.implementation_v1, named.implementation_v1_code_hash), (Address::constant(v1), None));
        let hashed = production()
            .with_overrides(&json!({"implementation": IMPLEMENTATION, "attestationAddress": attestor, "implementationV1": v1, "implementationV1CodeHash": format!("0x{}", "CD".repeat(32))}))
            .unwrap();
        assert_eq!(hashed.implementation_v1_code_hash.unwrap(), format!("0x{}", "cd".repeat(32)));
        let bad_v1 = production().with_overrides(&json!({"implementation": IMPLEMENTATION, "attestationAddress": attestor, "implementationV1": "0x12"})).unwrap_err();
        assert_eq!(bad_v1.message(), "implementationV1 must be an address.");
        let bad_v1_hash = production()
            .with_overrides(&json!({"implementation": IMPLEMENTATION, "attestationAddress": attestor, "implementationV1CodeHash": "0x12"}))
            .unwrap_err();
        assert_eq!(bad_v1_hash.message(), "implementationV1CodeHash must be a 0x-prefixed 32-byte hash.");
    }
}
