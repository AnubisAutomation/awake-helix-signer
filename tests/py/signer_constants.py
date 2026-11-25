"""The signer's public constants, for the test fakes (no signer import).

A copy of the values the Rust core pins (crates/helix-signer-core/src/
constants.rs), so these fakes keep working once the Python signer is gone.
"""

from __future__ import annotations

from decimal import Decimal

from eth_utils import keccak

CHAIN_ID = 6714
# The version 2 Diamond (every grant installs with it) and the version 1
# Diamond (older wallets revoke on it; a grant moves them to version 2).
IMPLEMENTATION = "0xA37eBF54868c76B52A35741859d9835609d48695"
IMPLEMENTATION_CODE_HASH = "0x59e8a79333ae7ada0b3465b8da009d336379888004712711cc62d4658164c9f2"
IMPLEMENTATION_V1 = "0xdaFCb6c6B3d2Af124d58c5e05Ce44ABd8C8ff56A"
IMPLEMENTATION_V1_CODE_HASH = "0x68525a27d760b50b797d6c7ba18b247c8530487b5e95ef820b859d36749d8e3f"
LEGACY_SESSION_KEY = "0x8Efa0a5e3083B1843Cf0A03dCb79131A3F4144B9"
DAI = "0x83fd06F0846d9D90B3016bF670Efe2E0B11cDe14"
LEDGER = "0x9E68F61E2615cc1D2C4a2D0026bFc1EBFdf68C1b"
LGNS = "0x4D1D808a081FdAc440703b3765FC61f8028C06B8"
AILGNS = "0x256EdB652db43E721EC6A12B6b51b6967D3bb8cB"
TURBINE = "0xE884A336550a4482Ca6A17A3F93aa30Ed4eD9BaD"
HELIX_ROUTER = "0x0527935979d10685B8571Fa02A8DEDbd6f3024E3"
ROCKETSWAP_ROUTER = "0x3E412E02B6157fBE80b6C6697f3Ce1142E629019"
COMMUNITY_VAULT = "0x3DEea5f638cA0dFb03A0873CF4c0b90BA50E1aA2"
# Origin (origindefi) contracts.
NEW_TURBO_25X = "0x0664F1369209677FEcb279F5EC3Df1E53a22212e"
NEW_TURBO_4X = "0x229e0aA54ebcFD887a1c06bc649AD1AFcA87486A"
NEW_TURBO_COMMUNITY = "0x8250F8EeaAe5B6e21043fbD8c61C70E1B0906109"
COMMUNITY_DISTRIBUTOR = "0x71B514b8d08F61e39e24442c2Fc83297584C1Dd6"
LONG_STAKING_360 = "0x88ea98af226Cd4402A3873400308a4D78784eCE6"
LONG_STAKING_600 = "0x04eD22c6d1D020A9B5e032E93D79ab28293EF72f"
ENERGY_STAKING = "0x1E5FeeC473F7F445FC7F5FeEC0beABB2270b0b4E"
ENERGY_BURNER = "0x31Fe4354218e387a236c531C5cCeE8149474E773"
ORIGIN_TURBINE = "0x92B53785090F6FE0717Ca3cF5dB8f8040d3B070b"
BURN_BOND = "0x11b10C9827c5B7071E96fcAa143B4e6E86b17c69"
BURN_FIXED = "0x3f403751975e1EB06d95901f7FF246513444E71F"
BURN_BOND_REWARD = "0x6170743b440696e17c9c0dbC551E0B8C010694d8"
ZERO = "0x0000000000000000000000000000000000000000"
RULE_METHODS = (
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
    # Origin kinds (version 2 Diamond only).
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
)
GRANT_TYPE = "(address,bytes16,uint48,uint48,uint32)"
RULE_TYPE = "(uint8,address,address,address,uint256,uint256,uint256,uint256,uint48,uint48,uint256)"
INSTALL_SIGNATURE = f"installPolicyGrant(bytes32,{GRANT_TYPE},{RULE_TYPE}[])"
INSTALL_TYPES = ("bytes32", GRANT_TYPE, f"{RULE_TYPE}[]")
REVOKE_SIGNATURES = {"policy": "revokePolicyGrant(bytes32)", "session": "revokeGrant(bytes32)"}
PLAN_SCHEMA = "anubisauto-signer-plan/2"
REVOKE_PLAN_SCHEMA = "anubisauto-signer-plan/1"
# The signers before 0.7.0 used these; revocations still accept them.
LEGACY_REVOKE_PLAN_SCHEMAS = ("awake-helix-signer-plan/1", "awake-helix-signer-plan/2")
ATTESTATION_VERSION = 1
ATTESTATION_NAME = "Anubis Automation Session Key Attestation"
ATTESTATION_DOMAIN_VERSION = "1"


def selector(signature: str) -> str:
    """0x-prefixed four-byte selector."""
    return "0x" + keccak(text=signature)[:4].hex()


INSTALL_SELECTOR = selector(INSTALL_SIGNATURE)
REVOKE_SELECTORS = {kind: selector(sig) for kind, sig in REVOKE_SIGNATURES.items()}
POLICY_INSTALLED_TOPIC = "0x" + keccak(text="PolicyGrantInstalled(bytes32,address)").hex()


def amount(value: int, decimals: int) -> str:
    """Base units as a plain decimal string (the signer's formatting)."""
    if decimals == 0:
        return str(value)
    return format((Decimal(value) / Decimal(10) ** decimals).normalize(), "f")


def attestation_typed_data(chain_id: int, owner: str, bot_bytes: bytes, session_key: str) -> dict:
    """The EIP-712 document a session key attestation signs."""
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
            ],
            "SessionKeyAttestation": [
                {"name": "version", "type": "uint256"},
                {"name": "chainId", "type": "uint256"},
                {"name": "owner", "type": "address"},
                {"name": "botId", "type": "bytes16"},
                {"name": "sessionKey", "type": "address"},
            ],
        },
        "primaryType": "SessionKeyAttestation",
        "domain": {"name": ATTESTATION_NAME, "version": ATTESTATION_DOMAIN_VERSION, "chainId": chain_id},
        "message": {
            "version": ATTESTATION_VERSION,
            "chainId": chain_id,
            "owner": owner,
            "botId": bot_bytes,
            "sessionKey": session_key,
        },
    }

