"""The signer's public constants, for the test fakes (no signer import).

A copy of the values the Rust core pins (crates/helix-signer-core/src/
constants.rs), so these fakes keep working once the Python signer is gone.
"""

from __future__ import annotations

from decimal import Decimal

from eth_utils import keccak

CHAIN_ID = 6714
IMPLEMENTATION = "0xdaFCb6c6B3d2Af124d58c5e05Ce44ABd8C8ff56A"
LEGACY_SESSION_KEY = "0x8Efa0a5e3083B1843Cf0A03dCb79131A3F4144B9"
DAI = "0x83fd06F0846d9D90B3016bF670Efe2E0B11cDe14"
LEDGER = "0x9E68F61E2615cc1D2C4a2D0026bFc1EBFdf68C1b"
LGNS = "0x4D1D808a081FdAc440703b3765FC61f8028C06B8"
AILGNS = "0x256EdB652db43E721EC6A12B6b51b6967D3bb8cB"
TURBINE = "0xE884A336550a4482Ca6A17A3F93aa30Ed4eD9BaD"
HELIX_ROUTER = "0x0527935979d10685B8571Fa02A8DEDbd6f3024E3"
ROCKETSWAP_ROUTER = "0x3E412E02B6157fBE80b6C6697f3Ce1142E629019"
COMMUNITY_VAULT = "0x3DEea5f638cA0dFb03A0873CF4c0b90BA50E1aA2"
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
)
GRANT_TYPE = "(address,bytes16,uint48,uint48,uint32)"
RULE_TYPE = "(uint8,address,address,address,uint256,uint256,uint256,uint256,uint48,uint48,uint256)"
INSTALL_SIGNATURE = f"installPolicyGrant(bytes32,{GRANT_TYPE},{RULE_TYPE}[])"
INSTALL_TYPES = ("bytes32", GRANT_TYPE, f"{RULE_TYPE}[]")
REVOKE_SIGNATURES = {"policy": "revokePolicyGrant(bytes32)", "session": "revokeGrant(bytes32)"}
PLAN_SCHEMA = "awake-helix-signer-plan/2"
ATTESTATION_VERSION = 1
ATTESTATION_NAME = "Awake Helix Session Key Attestation"
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

