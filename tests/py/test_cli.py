"""Behaviour of the ``awake-helix-signer`` executable against the HTTP fakes.

The cases of the former Python signer's unit tests (signing, the grant
editor, grants, the install ping and the companion), run against the real
executable (``HELIX_SIGNER_BIN``, default
``target/release/awake-helix-signer``) as a user would: secrets on
stdin of a process without a controlling terminal, the website and the chain
served over loopback HTTP by ``server.py``.

    uv run --no-project --python 3.12 --with eth-account==0.13.7 \
        python -m unittest discover -s tests/py -p 'test_*.py' -v
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import secrets
import socket
import stat
import tempfile
import time
import unittest
from pathlib import Path

from eth_abi import decode
from eth_account import Account

import fake_website
import fakes
import harness
import signer_constants as c

BIN = harness.RUST_BIN
MNEMONIC = "test test test test test test test test test test test junk"
MNEMONIC_ADDRESSES = ("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", "0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
GRANT_A, GRANT_B, GRANT_C = "0x" + "a1" * 32, "0x" + "b2" * 32, "0x" + "c3" * 32


@unittest.skipUnless(BIN.is_file(), f"{BIN} not built (cargo build --release -p helix-signer-cli)")
class CliCase(unittest.TestCase):
    """A fresh fake world per test."""

    def setUp(self) -> None:
        self.folder = tempfile.TemporaryDirectory(prefix="helix-cli-")
        self.addCleanup(self.folder.cleanup)
        self.world = harness.World(Path(self.folder.name))
        self.addCleanup(self.world.close)
        self.chain, self.site, self.backend = self.world.chain, self.world.site, self.world.backend
        self.owner = self.world.owner

    def cli(self, args: list[str], lines: list[str] | None = None) -> harness.Run:
        result = harness.run(BIN, args, lines)
        for secret in (self.world.password, self.world.private_key):
            self.assertNotIn(secret, result.text, "a secret was printed")
        return result

    def sign(self, *extra: str, lines: list[str] | None = None, token: str = fakes.TOKEN) -> harness.Run:
        return self.cli(["sign", "--plan", token, *self.world.api, *self.world.network, *extra], lines)

    def keystore(self) -> list[str]:
        return ["--keystore", str(self.world.keystore)]


class SignTests(CliCase):
    """``sign``: verification, delegation states, gas, keys and reporting."""

    def test_plain_eoa_type4_with_nonce_plus_one(self) -> None:
        self.site.plans[fakes.TOKEN] = fakes.grant_plan(self.owner)
        result = self.sign(*self.keystore(), lines=[self.world.password, "AUTHORIZE"])
        self.assertEqual(result.code, 0, result)
        sent = self.chain.sent[-1]
        self.assertEqual(sent["type"], 4)
        self.assertEqual(sent["tx"]["nonce"], 3)
        self.assertEqual(sent["authorities"], [{"authority": self.owner.lower(), "nonce": 4, "address": c.IMPLEMENTATION.lower()}])
        self.assertEqual(self.chain.code[self.owner.lower()], bytes.fromhex("ef0100" + c.IMPLEMENTATION[2:].lower()))
        self.assertEqual(self.chain.policy[self.owner.lower()][self.site.plans[fakes.TOKEN]["grantId"]], fakes.SESSION_KEY.lower())
        self.assertEqual(self.site.reports, [(fakes.TOKEN, list(self.chain.receipts)[-1])])
        for expected in ("Owner:       " + self.owner, c.IMPLEMENTATION, fakes.SESSION_KEY, "ONE EIP-7702 type-4", "UTC", "approve on DAI",
                         "spender: PowerLedger", "10 DAI per call", "participate on PowerLedger", "Done. Transaction 0x",
                         "The website was notified; the dashboard continues automatically."):
            self.assertIn(expected, result.stdout)

    def test_customized_values_are_shown(self) -> None:
        rules = [fakes.rule(0, c.DAI, 15 * 10**18, counterparty=c.LEDGER, daily=40 * 10**18), fakes.rule(1, c.LEDGER, 15 * 10**18, daily=40 * 10**18)]
        plan = fakes.grant_plan(self.owner, rules=rules, valid_seconds=60 * 86400, calls=1000)
        plan["remainingCalls"] = 1000
        plan["customization"] = {"customized": ["validUntil", "remainingCalls", "rules[0].maxPerDay"]}
        self.site.plans[fakes.TOKEN] = plan
        result = self.sign(*self.keystore(), lines=[self.world.password, "AUTHORIZE"])
        self.assertEqual(result.code, 0, result)
        self.assertIn("Expires:     " + time.strftime("%Y-%m-%d", time.gmtime(plan["validUntil"])), result.stdout)
        self.assertIn("at most 1000 bot operations", result.stdout)
        self.assertIn("15 DAI per call, 40 DAI per UTC day", result.stdout)
        self.assertIn("You customized: validUntil, remainingCalls, rules[0].maxPerDay", result.stdout)

    def test_already_delegated_uses_plain_self_call(self) -> None:
        self.chain.delegate(self.owner)
        self.site.plans[fakes.TOKEN] = fakes.grant_plan(self.owner)
        result = self.sign("--private-key", lines=[self.world.private_key, "AUTHORIZE"])
        self.assertEqual(result.code, 0, result)
        self.assertEqual(self.chain.sent[-1]["type"], 2)
        self.assertEqual(self.chain.sent[-1]["authorities"], [])
        self.assertIn("ordinary self-call", result.stdout)

    def test_refusals_sign_nothing(self) -> None:
        cases = [
            (lambda: self.chain.delegate(self.owner, "0x" + "99" * 20), "already delegated"),
            (lambda: self.chain.code.__setitem__(self.owner.lower(), b"\x60\x80"), "is a contract"),
            (lambda: setattr(self.chain, "chain_id", 1), "not Anubis Chain 6714"),
            (lambda: self.chain.code.__setitem__(c.IMPLEMENTATION.lower(), b"\x00malicious"), "code hash"),
            (lambda: self.chain.balances.__setitem__(self.owner.lower(), 1000), "Not enough DAI for gas"),
        ]
        for prepare, fragment in cases:
            with self.subTest(fragment=fragment):
                self.world = self._fresh()
                self.chain, self.site = self.world.chain, self.world.site
                prepare()
                self.site.plans[fakes.TOKEN] = fakes.grant_plan(self.owner)
                result = self.sign(*self.keystore(), lines=[self.world.password, "AUTHORIZE"])
                self.assertEqual(result.code, 2, result)
                self.assertIn(fragment, result.stdout)
                self.assertIn("Refused: ", result.stdout)
                self.assertEqual(self.chain.sent, [])

    def _fresh(self) -> harness.World:
        folder = Path(tempfile.mkdtemp(dir=self.folder.name))
        world = harness.World(folder, self.world.account)
        self.addCleanup(world.close)
        return world

    def test_wrong_key_is_refused_before_signing(self) -> None:
        other = Account.create()
        self.site.plans[fakes.TOKEN] = fakes.grant_plan(self.owner)
        result = self.sign("--private-key", lines=[other.key.hex(), "AUTHORIZE"])
        self.assertEqual(result.code, 2, result)
        self.assertIn(f"controls {other.address}", result.stdout)
        self.assertEqual(self.chain.sent, [])

    def test_cancel_signs_nothing(self) -> None:
        self.site.plans[fakes.TOKEN] = fakes.grant_plan(self.owner)
        result = self.sign(*self.keystore(), lines=[self.world.password, "authorize"])
        self.assertEqual(result.code, 1, result)
        self.assertIn("Cancelled; nothing was signed.", result.stdout)
        self.assertEqual(self.chain.sent, [])

    def test_closed_input_cancels(self) -> None:
        self.site.plans[fakes.TOKEN] = fakes.grant_plan(self.owner)
        result = self.sign(*self.keystore(), lines=[self.world.password])
        self.assertEqual(result.code, 1, result)
        self.assertIn("Cancelled; nothing was signed.", result.stdout)
        self.assertEqual(self.chain.sent, [])

    def test_tampered_plans_sign_nothing(self) -> None:
        attacker = Account.create().address
        tampered = {
            "Wrong delegate": {**fakes.grant_plan(self.owner), "implementation": "0x" + "66" * 20},
            "names another session key": fakes.grant_plan(self.owner, session_key=attacker) | {"sessionKey": attacker},
            "former shared hosted key": fakes.grant_plan(self.owner, session_key=c.LEGACY_SESSION_KEY) | {"sessionKey": c.LEGACY_SESSION_KEY},
            "not on the HELIX allow-list": fakes.grant_plan(self.owner, rules=[fakes.rule(0, c.DAI, 10**18, counterparty=attacker)]),
            "native value": {**fakes.grant_plan(self.owner), "value": "0x1"},
            "90 days": fakes.grant_plan(self.owner, valid_seconds=91 * 86400),
        }
        for index, (fragment, plan) in enumerate(tampered.items()):
            with self.subTest(fragment=fragment):
                token = f"tok_{index:02d}" + "T" * 30
                self.site.plans[token] = plan
                result = self.sign(*self.keystore(), lines=[self.world.password, "AUTHORIZE"], token=token)
                self.assertEqual(result.code, 2, result)
                self.assertIn(fragment, result.stdout)
        self.assertEqual(self.chain.sent, [])

    def test_used_and_unknown_token(self) -> None:
        self.site.plans[fakes.TOKEN] = fakes.grant_plan(self.owner)
        self.site.fetched.add(fakes.TOKEN)
        result = self.sign(*self.keystore(), lines=[self.world.password])
        self.assertEqual(result.code, 2, result)
        self.assertIn("expired (15 minutes) or was already fetched", result.stdout)
        result = self.sign(*self.keystore(), lines=[self.world.password], token="tok_" + "U" * 40)
        self.assertIn("does not know this plan token", result.stdout)
        result = self.sign(*self.keystore(), lines=[self.world.password], token="short")
        self.assertIn("The plan token is malformed", result.stdout)

    def test_wrong_password_retries(self) -> None:
        self.site.plans[fakes.TOKEN] = fakes.grant_plan(self.owner)
        result = self.sign(*self.keystore(), lines=["nope", "still nope", self.world.password, "AUTHORIZE"])
        self.assertEqual(result.code, 0, result)
        self.assertEqual(result.stdout.count("Wrong keystore password"), 2)
        self.assertNotIn("still nope", result.text)
        result = self.sign(*self.keystore(), lines=["a", "b", "c"])
        self.assertEqual(result.code, 2, result)

    def test_estimate_fallback_without_authorization_support(self) -> None:
        self.chain.estimate_with_authorization = False
        self.site.plans[fakes.TOKEN] = fakes.grant_plan(self.owner)
        result = self.sign(*self.keystore(), lines=[self.world.password, "AUTHORIZE"])
        self.assertEqual(result.code, 0, result)
        self.assertIn("delegation override", result.stdout)

    def test_mnemonic_flow_and_secret_hygiene(self) -> None:
        Account.enable_unaudited_hdwallet_features()
        owner = Account.from_mnemonic(MNEMONIC, account_path="m/44'/60'/0'/0/1").address
        self.assertEqual(owner, MNEMONIC_ADDRESSES[1])
        self.chain.balances[owner.lower()] = 10**18
        self.site.plans[fakes.TOKEN] = fakes.grant_plan(owner)
        result = self.sign("--mnemonic", "--account-index", "1", lines=[MNEMONIC, "y", "AUTHORIZE"])
        self.assertEqual(result.code, 0, result)
        self.assertNotIn("junk", result.text)
        self.assertIn("WARNING: A mnemonic (recovery phrase) controls EVERY account", result.stdout)
        self.assertIn(f"Derived m/44'/60'/0'/0/1 -> {owner}. Is this the right address? [y/N]", result.stdout)
        self.assertEqual(self.chain.sent[-1]["authorities"][0]["authority"], owner.lower())
        refused = self.sign("--mnemonic", "--account-index", "1", lines=[MNEMONIC, "n"])
        self.assertEqual(refused.code, 2, refused)
        self.assertIn("Address not confirmed", refused.stdout)
        bad_index = self.sign("--mnemonic", "--account-index", "-1", lines=[MNEMONIC])
        self.assertIn("The account index must be between 0 and 2147483647.", bad_index.stdout)

    def test_report_rejected_still_succeeds(self) -> None:
        self.site.report_status = 409
        self.site.plans[fakes.TOKEN] = fakes.grant_plan(self.owner)
        result = self.sign(*self.keystore(), lines=[self.world.password, "AUTHORIZE"])
        self.assertEqual(result.code, 0, result)
        self.assertIn("detects the transaction on chain", result.stdout)
        self.assertEqual(len(self.site.reports), 1)

    def test_report_retried_on_server_errors(self) -> None:
        self.site.report_status = 503
        self.site.plans[fakes.TOKEN] = fakes.grant_plan(self.owner)
        result = self.sign(*self.keystore(), lines=[self.world.password, "AUTHORIZE"])
        self.assertEqual(result.code, 0, result)
        self.assertEqual(len(self.site.reports), 3)

    def test_interactive_key_source(self) -> None:
        self.site.plans[fakes.TOKEN] = fakes.grant_plan(self.owner)
        result = self.sign(lines=["1", str(self.world.keystore), self.world.password, "AUTHORIZE"])
        self.assertEqual(result.code, 0, result)
        self.assertIn("Key source: [1] keystore file (recommended)  [2] private key  [3] mnemonic", result.stdout)
        result = self.sign(lines=["9"])
        self.assertIn("Refused: No key source chosen.", result.stdout)

    def test_dev_constants_need_a_loopback_rpc(self) -> None:
        result = self.cli(["sign", "--plan", fakes.TOKEN, "--rpc", "https://rpc.anubispace.org", "--dev-constants", str(self.world.constants), "--private-key"])
        self.assertEqual(result.code, 2, result)
        self.assertIn("--dev-constants is refused", result.stdout)
        bad = Path(self.folder.name) / "bad.json"
        bad.write_text(json.dumps({**fakes.dev_constants(), "ruleAllowlist": {}}))
        result = self.cli(["sign", "--plan", fakes.TOKEN, "--rpc", self.world.fake.rpc, "--dev-constants", str(bad), "--private-key"])
        self.assertIn("Unknown dev-constants fields: ruleAllowlist", result.stdout)

    def test_open_link(self) -> None:
        self.site.plans[fakes.TOKEN] = fakes.grant_plan(self.owner)
        api = self.world.fake.url.replace(":", "%3A").replace("/", "%2F")
        result = self.cli(["open", f"awakehelix://sign?plan={fakes.TOKEN}&api={api}", *self.world.network, *self.keystore()], [self.world.password, "AUTHORIZE"])
        self.assertEqual(result.code, 0, result)
        result = self.cli([f"awakehelix://sign?plan={fakes.TOKEN}&api=https%3A%2F%2Fevil.example", *self.world.network, *self.keystore()], [])
        self.assertEqual(result.code, 2, result)
        self.assertIn("not the official Awake Helix website", result.stdout)

    def test_bad_private_key_error_does_not_echo(self) -> None:
        secret = "f" * 63 + "g"
        result = self.cli(["sign", "--plan", fakes.TOKEN, "--private-key"], [secret])
        self.assertEqual(result.code, 2, result)
        self.assertNotIn(secret, result.text)
        self.assertIn("A private key is 64 hexadecimal characters", result.stdout)


class EditTests(CliCase):
    """``sign --expires --calls --cap`` and the interactive EDIT prompt."""

    def setUp(self) -> None:
        super().setUp()
        self.site.plans[fakes.TOKEN] = fakes.grant_plan(self.owner)

    def test_flags_customize_before_the_confirmation(self) -> None:
        until = int(time.time()) + 20 * 86400
        result = self.sign("--private-key", "--expires", str(until), "--calls", "100", "--cap", "1=15,30", lines=[self.world.private_key, "AUTHORIZE"])
        self.assertEqual(result.code, 0, result)
        self.assertEqual(len(self.backend.customized), 1)
        self.assertEqual(self.backend.customized[0], {"validUntil": until, "remainingCalls": 100, "rules": [{"index": 0, "maxPerCall": "15", "maxPerDay": "30"}, {"index": 1, "maxPerCall": "10", "maxPerDay": "10"}]})
        self.assertIn("at most 100 bot operations", result.stdout)
        self.assertIn("15 DAI per call, 30 DAI per UTC day", result.stdout)
        self.assertIn("New plan verified against the pinned constants.", result.stdout)
        sent = "0x" + bytes(self.chain.sent[0]["tx"]["data"]).hex()
        self.assertEqual(sent, self.site.plans[fakes.TOKEN]["data"])
        _, grant, _ = decode(list(c.INSTALL_TYPES), bytes.fromhex(sent[10:]))
        self.assertEqual((grant[3], grant[4]), (until, 100))

    def test_cap_by_method_and_per_day_only(self) -> None:
        result = self.sign("--private-key", "--cap", "participate=12", "--cap", "1=,20", lines=[self.world.private_key, "AUTHORIZE"])
        self.assertEqual(result.code, 0, result)
        self.assertEqual(self.backend.customized[0]["rules"], [{"index": 0, "maxPerCall": "10", "maxPerDay": "20"}, {"index": 1, "maxPerCall": "12", "maxPerDay": "12"}])

    def test_refused_flag_stops_without_signing(self) -> None:
        result = self.sign("--private-key", "--cap", "1=99,99", lines=[self.world.private_key, "AUTHORIZE"])
        self.assertEqual(result.code, 2, result)
        self.assertIn("Refused: Rule 1: the per-call cap is out of range", result.stdout)
        self.assertEqual(self.chain.sent, [])

    def test_malformed_flags(self) -> None:
        for flags, fragment in ((["--expires", "tomorrow"], "not understood"), (["--calls", "many"], "must be a whole number"),
                                (["--cap", "9=1,1"], "There is no rule 9"), (["--cap", "1=abc"], "must be a decimal number")):
            with self.subTest(flags=flags):
                token = "tok_" + secrets.token_hex(20)
                self.site.plans[token] = fakes.grant_plan(self.owner)
                result = self.sign("--private-key", *flags, lines=[self.world.private_key], token=token)
                self.assertEqual(result.code, 2, result)
                self.assertIn(fragment, result.stdout)
        self.assertEqual((self.backend.customized, self.chain.sent), ([], []))

    def test_interactive_edit(self) -> None:
        result = self.sign("--private-key", lines=[self.world.private_key, "EDIT", "", "100", "15", "30", "", "", "AUTHORIZE"])
        self.assertEqual(result.code, 0, result)
        self.assertEqual(self.backend.customized[0]["remainingCalls"], 100)
        self.assertEqual(self.backend.customized[0]["rules"][0], {"index": 0, "maxPerCall": "15", "maxPerDay": "30"})
        self.assertEqual(result.stdout.count("Grant ID:"), 2)
        self.assertIn("Press Enter to keep a value.", result.stdout)
        self.assertEqual(len(self.chain.sent), 1)

    def test_interactive_refusal_returns_to_the_prompt(self) -> None:
        result = self.sign("--private-key", lines=[self.world.private_key, "EDIT", "", "", "99", "", "", "", "no"])
        self.assertEqual(result.code, 1, result)
        self.assertIn("Not changed: Rule 1", result.stdout)
        self.assertEqual(self.chain.sent, [])

    def test_tampered_answer_ends_the_request(self) -> None:
        other = fakes.grant_plan(self.owner)
        self.backend.tamper = lambda answer: {**other, "reportUrl": answer.get("reportUrl")}
        result = self.sign("--private-key", "--calls", "100", lines=[self.world.private_key, "AUTHORIZE"])
        self.assertEqual(result.code, 2, result)
        self.assertIn("The website's new plan was refused", result.stdout)
        self.assertIn("may never change", result.stdout)
        self.assertEqual(self.chain.sent, [])

    def test_gone_plan_cannot_be_edited(self) -> None:
        self.backend.customize_status = 410
        result = self.sign("--private-key", "--calls", "100", lines=[self.world.private_key])
        self.assertEqual(result.code, 2, result)
        self.assertIn("can no longer be edited", result.stdout)


class RevokeTests(CliCase):
    """``revoke --plan`` and the offline revoke."""

    def test_revoke_with_plan_and_offline(self) -> None:
        self.chain.delegate(self.owner)
        grant = "0x" + "cd" * 32
        self.chain.policy[self.owner.lower()] = {grant: fakes.SESSION_KEY.lower()}
        self.site.plans[fakes.TOKEN] = fakes.revoke_plan(self.owner, grant)
        result = self.cli(["revoke", "--plan", fakes.TOKEN, *self.world.api, *self.world.network, *self.keystore()], [self.world.password, "REVOKE"])
        self.assertEqual(result.code, 0, result)
        self.assertNotIn(grant, self.chain.policy[self.owner.lower()])
        self.assertEqual(self.chain.sent[-1]["type"], 2)
        self.assertEqual(self.site.reports[-1][0], fakes.TOKEN)
        self.assertIn("Transaction: ordinary self-call revokePolicyGrant(bytes32)", result.stdout)
        self.assertIn("Done. Grant revoked in transaction 0x", result.stdout)
        session_grant = "0x" + "ef" * 32
        self.chain.session[self.owner.lower()] = {session_grant: "0x" + "77" * 20}
        offline = ["revoke", "--grant", session_grant, "--owner", self.owner, *self.world.network, "--private-key"]
        result = self.cli(offline, [self.world.private_key, "REVOKE"])
        self.assertEqual(result.code, 0, result)
        self.assertNotIn(session_grant, self.chain.session[self.owner.lower()])
        self.assertEqual("0x" + bytes(self.chain.sent[-1]["tx"]["data"]).hex(), c.REVOKE_SELECTORS["session"] + "ef" * 32)
        self.assertNotIn("Website (plan source)", result.stdout)
        result = self.cli(offline, [self.world.private_key])
        self.assertEqual(result.code, 2, result)
        self.assertIn("not active on chain", result.stdout)

    def test_revoke_of_an_undelegated_account_without_the_grant(self) -> None:
        self.site.plans[fakes.TOKEN] = fakes.revoke_plan(self.owner, "0x" + "cd" * 32)
        result = self.cli(["revoke", "--plan", fakes.TOKEN, *self.world.api, *self.world.network, *self.keystore()], [self.world.password])
        self.assertEqual(result.code, 2, result)
        self.assertIn("is not active on chain", result.stdout)
        self.assertEqual(self.chain.sent, [])

    def test_revoke_of_a_dormant_grant_redelegates_in_the_same_type4(self) -> None:
        owner, grant = self.owner.lower(), "0x" + "d0" * 32
        # Delegation cleared earlier; the grant is still in the account's storage.
        self.chain.policy[owner] = {grant: fakes.SESSION_KEY.lower()}
        self.chain.nonces[owner] = 6
        self.site.plans[fakes.TOKEN] = fakes.revoke_plan(self.owner, grant)
        result = self.cli(["revoke", "--plan", fakes.TOKEN, *self.world.api, *self.world.network, *self.keystore()], [self.world.password, "REVOKE"])
        self.assertEqual(result.code, 0, result)
        self.assertIn("re-delegate the account to Helix and revokePolicyGrant(bytes32)", result.stdout)
        self.assertIn("Delegation:  none now. The grant is inactive but still stored", result.stdout)
        sent = self.chain.sent[-1]
        self.assertEqual((sent["type"], sent["tx"]["nonce"]), (4, 6))
        self.assertEqual(sent["authorities"], [{"authority": owner, "nonce": 7, "address": c.IMPLEMENTATION.lower()}])
        self.assertNotIn(grant, self.chain.policy[owner])
        self.assertEqual(self.chain.code[owner], bytes.fromhex("ef0100" + c.IMPLEMENTATION[2:].lower()))
        self.assertIn("delegated to Helix again and the grant is revoked", result.stdout)

    def test_revoke_refuses_a_foreign_delegation(self) -> None:
        owner, grant = self.owner.lower(), "0x" + "d1" * 32
        self.chain.policy[owner] = {grant: fakes.SESSION_KEY.lower()}
        self.chain.delegate(owner, "0x" + "99" * 20)
        self.site.plans[fakes.TOKEN] = fakes.revoke_plan(self.owner, grant)
        result = self.cli(["revoke", "--plan", fakes.TOKEN, *self.world.api, *self.world.network, *self.keystore()], [self.world.password])
        self.assertEqual(result.code, 2, result)
        self.assertIn("already delegated (EIP-7702) to another contract", result.stdout)
        self.assertEqual(self.chain.sent, [])

    def test_kind_mismatch_and_missing_arguments(self) -> None:
        self.chain.delegate(self.owner)
        grant = "0x" + "cd" * 32
        self.chain.session[self.owner.lower()] = {grant: fakes.SESSION_KEY.lower()}
        result = self.cli(["revoke", "--grant", grant, "--owner", self.owner, "--kind", "policy", *self.world.network, "--private-key"], [self.world.private_key])
        self.assertIn("On chain this is a session grant, but the plan revokes a policy grant.", result.stdout)
        result = self.cli(["revoke", "--grant", grant, *self.world.network, "--private-key"], [])
        self.assertEqual(result.code, 2, result)
        self.assertIn("Pass --plan TOKEN, or --grant ID and --owner ADDRESS.", result.stdout)
        result = self.cli(["revoke", "--kind", "other", "--grant", grant], [])
        self.assertEqual(result.code, 2, result)


class GrantsTests(CliCase):
    """``grants list`` / ``grants revoke`` through the owner's own login."""

    def setUp(self) -> None:
        super().setUp()
        owner = self.owner.lower()
        # A loopback API only signs in with a loopback site's message.
        self.backend.login_domain = self.world.fake.url.removeprefix("http://")
        self.chain.delegate(owner)
        for grant in (GRANT_A, GRANT_B, GRANT_C):
            self.chain.policy.setdefault(owner, {})[grant] = fakes.SESSION_KEY.lower()
        self.backend.grants[owner] = [fake_website.row(owner, grant, bot={"id": 7, "script": "dai-power", "status": "active"}) for grant in (GRANT_A, GRANT_B, GRANT_C)]

    def grants(self, args: list[str], answers: list[str] | None = None) -> harness.Run:
        result = self.cli(["grants", *args, *self.world.api, *self.world.network, "--private-key"], [self.world.private_key, *(answers or [])])
        for session in self.backend.session_cookies:
            self.assertNotIn(session, result.text)
        self.assertNotIn("csrf-", result.text)
        return result

    def test_list(self) -> None:
        owner = self.owner.lower()
        self.backend.grants[owner][1] = fake_website.row(owner, GRANT_B, status="revoked", calls=None, bot={"id": 3, "script": "lgns-power", "status": "draft", "deleted": True})
        self.backend.grants[owner][2] = fake_website.row(owner, GRANT_C, status="expired")
        result = self.grants(["list"])
        self.assertEqual(result.code, 0, result)
        for fragment in (GRANT_A, GRANT_B, GRANT_C, "active", "revoked", "expired", "dai-power #7 (running)", "lgns-power (deleted)",
                         "valid until:", "remaining calls: 256", "remaining calls: -", fakes.SESSION_KEY, "hosted key, bot unknown",
                         "a signature only; no transaction", "NOT the official site"):
            self.assertIn(fragment, result.stdout)
        self.assertEqual(self.backend.requests[:4], [("GET", "/api/csrf"), ("POST", "/api/auth/challenge"), ("POST", "/api/auth/verify"), ("GET", "/api/grants")])
        self.assertEqual(self.chain.sent, [])
        self.assertEqual(self.backend.logged_out, 1)

    def test_list_explains_new_statuses(self) -> None:
        owner = self.owner.lower()
        rows = self.backend.grants[owner]
        rows[0] = {**fake_website.row(owner, GRANT_A, status="inactive"), "revocable": True, "delegation": "none"}
        rows[1] = {**fake_website.row(owner, GRANT_B, status="inactive"), "revocable": False, "delegation": "other", "notRevocableReason": "otherDelegation"}
        rows[2] = {**fake_website.row(owner, GRANT_C, status="unavailable"), "revocable": False}
        rows.append({**fake_website.row(owner, "0x" + "c4" * 32, status="missing"), "revocable": False})
        rows.append({**fake_website.row(owner, "0x" + "c5" * 32, status="paused_by_future_release"), "revocable": False})
        result = self.grants(["list"])
        self.assertEqual(result.code, 0, result)
        for fragment in ("inactive: this account is not delegated to Helix7702Account; it becomes active again if the account re-delegates",
                         "delegated to another contract, so it cannot be revoked here", "temporarily unreadable",
                         "run `grants list` again", "not installed (never on chain)", "paused by future release",
                         "revocable here: no"):
            self.assertIn(fragment, result.stdout)

    def test_revoke_grant_of_a_foreign_delegation_is_explained(self) -> None:
        self.chain.delegate(self.owner.lower(), "0x" + "99" * 20)
        result = self.grants(["revoke", "--grant", GRANT_A], ["REVOKE"])
        self.assertEqual(result.code, 2, result)
        self.assertIn("cannot be revoked here", result.stdout)
        self.assertIn("never overwrites", result.stdout)
        self.assertEqual(self.chain.sent, [])

    def test_revoke_one(self) -> None:
        result = self.grants(["revoke", "--grant", GRANT_B], ["REVOKE"])
        self.assertEqual(result.code, 0, result)
        self.assertEqual([item[0] for item in self.backend.confirmations], [GRANT_B])
        self.assertIn("Revoked 1 of 1", result.stdout)
        self.assertIn("The website stopped bot(s): 7.", result.stdout)
        self.assertNotIn(GRANT_B, self.chain.policy[self.owner.lower()])

    def test_revoke_all_in_sequence(self) -> None:
        self.backend.grants[self.owner.lower()][2] = fake_website.row(self.owner.lower(), GRANT_C, status="expired")
        result = self.grants(["revoke", "--all"], ["REVOKE"])
        self.assertEqual(result.code, 0, result)
        self.assertEqual([item[0] for item in self.backend.confirmations], [GRANT_A, GRANT_B])
        self.assertEqual(self.chain.nonces[self.owner.lower()], 5)
        self.assertIn("Revoking 2 of 2", result.stdout)

    def test_cancel_signs_nothing(self) -> None:
        result = self.grants(["revoke", "--all"], ["no"])
        self.assertEqual(result.code, 1, result)
        self.assertEqual(self.chain.sent, [])
        self.assertIn("nothing was signed", result.stdout)

    def test_needs_grant_or_all(self) -> None:
        self.assertEqual(self.cli(["grants", "revoke"]).code, 2)
        self.assertEqual(self.cli(["grants", "revoke", "--all", "--grant", GRANT_A]).code, 2)

    def test_unknown_and_revoked_grants(self) -> None:
        result = self.grants(["revoke", "--grant", "0x" + "dd" * 32])
        self.assertEqual(result.code, 2, result)
        self.assertIn("refused to prepare", result.stdout)
        del self.chain.policy[self.owner.lower()][GRANT_A]
        result = self.grants(["revoke", "--grant", GRANT_A])
        self.assertEqual(result.code, 0, result)
        self.assertIn("already revoked or not on chain", result.stdout)
        self.assertIn("Nothing to revoke", result.stdout)

    def test_tampered_revoke_call_is_refused(self) -> None:
        self.backend.tamper_call = lambda call: {**call, "value": "0x1"}
        result = self.grants(["revoke", "--grant", GRANT_A], ["REVOKE"])
        self.assertEqual(result.code, 2, result)
        self.assertIn(f"Grant {GRANT_A}: The plan moves native value", result.stdout)
        self.assertEqual(self.chain.sent, [])

    def test_hostile_challenge_is_never_signed(self) -> None:
        domain = self.backend.login_domain
        self.backend.tamper_challenge = lambda message: message.replace(domain, "bank.example")
        result = self.grants(["list"])
        self.assertEqual(result.code, 2, result)
        self.assertNotIn(("POST", "/api/auth/verify"), self.backend.requests)

    def test_open_grants_link_and_scan(self) -> None:
        self.backend.scan_pages = 1
        api = self.world.fake.url.replace(":", "%3A").replace("/", "%2F")
        result = self.cli(["open", f"awakehelix://grants?api={api}", *self.world.network, "--private-key"], [self.world.private_key])
        self.assertEqual(result.code, 0, result)
        self.assertIn(GRANT_A, result.stdout)
        self.assertIn("scanning the install history (50%)", result.stdout)

    def test_refused_confirmation_is_not_fatal(self) -> None:
        self.backend.confirm_status = 409
        result = self.grants(["revoke", "--grant", GRANT_A], ["REVOKE"])
        self.assertEqual(result.code, 0, result)
        self.assertIn("detects the revocation on chain", result.stdout)


class PingTests(CliCase):
    """``ping`` and ``open awakehelix://ping``."""

    TOKEN = "chk_" + "Q" * 40

    def test_ping(self) -> None:
        result = self.cli(["ping", "--token", self.TOKEN, *self.world.api])
        self.assertEqual(result.code, 0, result)
        self.assertIn("Awake Helix Signer is installed and linked — you can return to the browser.", result.stdout)
        token, body = self.world.fake.pings[0]
        self.assertEqual(token, self.TOKEN)
        self.assertEqual(set(body), {"version", "os", "arch"})
        self.assertEqual(body["version"], "0.5.2")
        method, _, headers, _ = self.world.fake.log[-1]
        self.assertEqual(method, "POST")
        self.assertEqual(headers.get("User-Agent"), "awake-helix-signer/0.5.2")
        self.assertEqual(headers.get("Content-Type"), "application/json")
        for status, fragment in ((404, "does not know"), (409, "already confirmed"), (410, "expired"), (429, "Too many"), (500, "refused")):
            self.world.fake.ping_status = status
            result = self.cli(["ping", "--token", self.TOKEN, *self.world.api])
            self.assertEqual(result.code, 2, result)
            self.assertIn(fragment, result.stdout)
        self.world.fake.ping_status = 200
        self.world.fake.ping_answer = {"status": "pending"}
        self.assertIn("did not confirm", self.cli(["ping", "--token", self.TOKEN, *self.world.api]).stdout)
        for args in (["--token", "short"], ["--token", self.TOKEN, "--api", "http://example.com"], ["--token", self.TOKEN, "--api", "https://u:p@x.example"]):
            self.assertEqual(self.cli(["ping", *args]).code, 2)

    def test_open_ping_link(self) -> None:
        api = self.world.fake.url.replace(":", "%3A").replace("/", "%2F")
        result = self.cli(["open", f"awakehelix://ping?token={self.TOKEN}&api={api}", *self.world.network])
        self.assertEqual(result.code, 0, result)
        refused = self.cli(["open", f"awakehelix://ping?token={self.TOKEN}&api=https%3A%2F%2Fevil.example"])
        self.assertEqual(refused.code, 2, refused)
        self.assertIn("not the official", refused.stdout)
        self.assertEqual(len(self.world.fake.pings), 1)


class KeystoreAndMiscTests(CliCase):
    """``keystore create``, ``--version``, ``--help``, ``status``."""

    def test_keystore_create_never_echoes(self) -> None:
        account = Account.create()
        out = Path(self.folder.name) / "sub" / "k.json"
        result = harness.run(BIN, ["keystore", "create", "--out", str(out)], [account.key.hex(), "a strong password", "a strong password"])
        self.assertEqual(result.code, 0, result)
        self.assertNotIn(account.key.hex()[2:], result.text)
        self.assertNotIn("a strong password", result.text)
        self.assertIn(f"Wrote encrypted keystore for {account.address} to {out}.", result.stdout)
        document = json.loads(out.read_text())
        self.assertEqual(Account.decrypt(document, "a strong password"), account.key)
        self.assertEqual(document["crypto"]["kdf"], "scrypt")
        self.assertEqual(document["crypto"]["kdfparams"]["n"], 262144)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)
        again = harness.run(BIN, ["keystore", "create", "--out", str(out)], [account.key.hex(), "a strong password", "a strong password"])
        self.assertEqual(again.code, 2, again)
        self.assertIn("already exists", again.stdout)
        short = harness.run(BIN, ["keystore", "create", "--out", str(out) + "2"], [account.key.hex(), "short", "short"])
        self.assertIn("at least 8 characters", short.stdout)
        differ = harness.run(BIN, ["keystore", "create", "--out", str(out) + "3"], [account.key.hex(), "long enough 1", "long enough 2"])
        self.assertIn("The passwords differ; nothing was written.", differ.stdout)
        # The new keystore signs (scrypt, the default work factor).
        self.site.plans[fakes.TOKEN] = fakes.grant_plan(account.address)
        self.chain.balances[account.address.lower()] = 10**18
        signed = self.sign("--keystore", str(out), lines=["a strong password", "AUTHORIZE"])
        self.assertEqual(signed.code, 0, signed)

    def test_version_help_status(self) -> None:
        self.assertEqual(harness.run(BIN, ["--version"]).stdout.strip(), "awake-helix-signer 0.5.2")
        self.assertEqual(harness.run(BIN, ["--version", "sign"]).code, 0)
        help_text = harness.run(BIN, ["--help"])
        self.assertEqual(help_text.code, 0)
        for command in ("sign", "revoke", "grants", "ping", "open", "keystore", "serve", "register", "install-cli", "status"):
            self.assertIn(command, help_text.stdout)
        self.assertEqual(harness.run(BIN, []).code, 2)
        status = harness.run(BIN, ["status"])
        self.assertEqual(status.code, 0, status)
        self.assertIn("awake-helix-signer 0.5.2", status.stdout)
        self.assertIn("awakehelix:// handler:", status.stdout)
        self.assertEqual(harness.run(BIN, ["--selftest"]).code, 0)

    def test_register_writes_a_desktop_entry(self) -> None:
        home = Path(self.folder.name) / "home"
        env = {**harness.environment(), "HOME": str(home), "XDG_DATA_HOME": "", "PATH": "/usr/bin:/bin"}
        result = harness.run(BIN, ["register"], env=env)
        self.assertEqual(result.code, 0, result)
        entry = home / ".local/share/applications/awakehelix-signer.desktop"
        self.assertIn("MimeType=x-scheme-handler/awakehelix;", entry.read_text())
        self.assertTrue((home / ".local/share/icons/hicolor/256x256/apps/awake-helix-signer.png").read_bytes().startswith(b"\x89PNG"))
        self.assertIn("awakehelix:// handler:", harness.run(BIN, ["status"], env=env).stdout)
        self.assertEqual(harness.run(BIN, ["unregister"], env=env).code, 0)
        self.assertFalse(entry.exists())
        link_dir = home / "bin"
        installed = harness.run(BIN, ["install-cli", "--dir", str(link_dir)], env=env)
        self.assertEqual(installed.code, 0, installed)
        self.assertTrue((link_dir / "awake-helix-signer").is_symlink())


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


SITE = "https://anubis.sivilization.com"
DEV = "https://localhost:3443"


def signed_headers(pairing: dict, method: str, path: str, body: bytes, now_ms: int | None = None) -> dict[str, str]:
    timestamp = str(int(time.time() * 1000) if now_ms is None else now_ms)
    nonce = secrets.token_hex(16)
    message = f"{method}\n{path}\n{timestamp}\n{nonce}\n{hashlib.sha256(body).hexdigest()}".encode()
    return {
        "X-Helix-Pairing": pairing["pairingId"], "X-Helix-Timestamp": timestamp, "X-Helix-Nonce": nonce,
        "X-Helix-Signature": hmac.new(bytes.fromhex(pairing["secret"]), message, hashlib.sha256).hexdigest(),
    }


class CompanionTests(CliCase):
    """``serve``: Host, Origin, preflight, pairing, HMAC, confirmations."""

    def serve(self, *extra: str, auto: bool = False) -> harness.Background:
        self.port = free_port()
        self.pairing_file = Path(self.folder.name) / f"pairings-{self.port}.json"
        args = ["serve", "--port", str(self.port), "--allow-origin", DEV, *self.world.api, *self.world.network, "--private-key",
                "--pairing-file", str(self.pairing_file), *extra]
        if auto:
            args.append("--auto-confirm-revoke")
        server = harness.Background(BIN, args)
        self.addCleanup(server.stop)
        server.type(self.world.private_key)
        output = server.wait_for("Pairing code for the website:")
        self.code = output.split("Pairing code for the website: ")[1].split()[0]
        self.server = server
        return server

    def request(self, method: str, path: str, body: dict | None = None, origin: str | None = SITE, host: str | None = None,
                headers: dict | None = None, pairing: dict | None = None) -> tuple[int, dict, dict | None]:
        raw = b"" if body is None else json.dumps(body).encode()
        sent = {"Host": host or f"127.0.0.1:{self.port}", "Content-Type": "application/json"}
        if origin:
            sent["Origin"] = origin
        if pairing:
            sent.update(signed_headers(pairing, method, path, raw))
        sent.update(headers or {})
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        connection.request(method, path, body=raw or None, headers=sent)
        response = connection.getresponse()
        data = response.read()
        connection.close()
        return response.status, dict(response.getheaders()), (json.loads(data) if data else None)

    def pair(self, origin: str = SITE) -> dict:
        status, _, body = self.request("POST", "/pair", {"code": self.code.lower()}, origin=origin)
        self.assertEqual(status, 200, body)
        return body

    def wait(self, job_id: str, pairing: dict) -> dict:
        for _ in range(400):
            _, _, body = self.request("GET", f"/jobs/{job_id}", pairing=pairing)
            if body["state"] in {"done", "failed", "cancelled"}:
                return body
            time.sleep(0.05)
        raise AssertionError(body)

    def test_origin_host_and_preflight(self) -> None:
        self.serve()
        self.assertIn(f"Listening on http://127.0.0.1:{self.port} for {SITE}, {DEV}.", self.server.output)
        status, headers, body = self.request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Access-Control-Allow-Origin"], SITE)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual((body["name"], body["paired"], body["chainId"], body["version"], body["keyLoaded"], body["owner"]),
                         ("awake-helix-signer", False, 6714, "0.5.2", True, self.owner))
        self.assertTrue(body["constantsHash"].startswith("0x"))
        for origin in ("https://evil.example", "https://anubis.sivilization.com.evil.example", "null", None):
            status, headers, _ = self.request("GET", "/health", origin=origin)
            self.assertEqual(status, 403, origin)
            self.assertNotIn("Access-Control-Allow-Origin", headers)
        status, headers, _ = self.request("GET", "/health", origin=DEV + "/")
        self.assertEqual((status, headers["Access-Control-Allow-Origin"]), (200, DEV))
        self.assertEqual(self.request("GET", "/health", host=f"attacker.example:{self.port}")[0], 403)
        self.assertEqual(self.request("GET", "/health", host=f"localhost:{self.port}")[0], 200)
        status, headers, _ = self.request("OPTIONS", "/sign", headers={"Access-Control-Request-Method": "POST", "Access-Control-Request-Private-Network": "true"})
        self.assertEqual(status, 204)
        self.assertEqual(headers["Access-Control-Allow-Private-Network"], "true")
        self.assertIn("X-Helix-Signature", headers["Access-Control-Allow-Headers"])
        self.assertEqual(headers["Access-Control-Allow-Methods"], "GET, POST, OPTIONS")
        status, headers, _ = self.request("OPTIONS", "/sign", origin="https://evil.example", headers={"Access-Control-Request-Private-Network": "true"})
        self.assertEqual(status, 403)
        self.assertNotIn("Access-Control-Allow-Private-Network", headers)
        self.assertEqual(self.request("GET", "/nothing")[0], 404)
        self.assertEqual(self.request("POST", "/sign", headers={"Content-Length": "999999"})[0], 413)

    def test_bad_options_are_refused(self) -> None:
        for extra, fragment in ((["--allow-origin", "http://192.168.1.2:3000"], "--allow-origin only accepts loopback origins"),
                                (["--port", "80"], "--port must be between 1024 and 65535."), (["--idle-timeout", "5"], "--idle-timeout must be at least 30 seconds.")):
            args = ["serve", *self.world.api, *self.world.network, "--private-key", *extra]
            result = self.cli(args, [self.world.private_key])
            self.assertEqual(result.code, 2, result)
            self.assertIn(fragment, result.stdout)

    def test_pairing_code_attempts_and_persistence(self) -> None:
        self.serve()
        for left in (4, 3, 2, 1):
            status, _, body = self.request("POST", "/pair", {"code": "WRONG-CODE"})
            self.assertEqual((status, body["attemptsLeft"]), (403, left))
        self.assertEqual(self.request("POST", "/pair", {"code": "WRONG-CODE"})[0], 410)
        self.assertEqual(self.request("POST", "/pair", {"code": self.code})[0], 410)  # closed after five failures
        self.server.stop()
        self.serve()
        pairing = self.pair()
        self.assertRegex(pairing["secret"], r"^[0-9a-f]{64}$")
        self.assertEqual(self.request("POST", "/pair", {"code": self.code})[0], 410)  # single use
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.pairing_file.stat().st_mode), 0o600)
        stored = json.loads(self.pairing_file.read_text())
        self.assertEqual(stored["pairings"][0]["origin"], SITE)
        self.assertIn("Paired with https://anubis.sivilization.com.", self.server.output)
        _, _, body = self.request("GET", "/health", pairing=pairing)
        self.assertTrue(body["paired"])
        # A restart keeps the pairing.
        pairing_file = self.pairing_file
        self.server.stop()
        self.port = free_port()
        server = harness.Background(BIN, ["serve", "--port", str(self.port), *self.world.api, *self.world.network, "--private-key", "--pairing-file", str(pairing_file)])
        self.addCleanup(server.stop)
        server.type(self.world.private_key)
        server.wait_for("Pairing code")
        self.assertTrue(self.request("GET", "/health", pairing=pairing)[2]["paired"])

    def test_hmac_rules(self) -> None:
        self.serve()
        pairing = self.pair()
        path, body = "/revoke", {"revokeToken": fakes.TOKEN}
        raw = json.dumps(body).encode()
        self.assertEqual(self.request("POST", path, body)[0], 401)
        self.assertEqual(self.request("POST", path, body, pairing={**pairing, "secret": "11" * 32})[0], 401)
        stale = signed_headers(pairing, "POST", path, raw, now_ms=int(time.time() * 1000) - 120_000)
        self.assertEqual(self.request("POST", path, body, headers=stale)[0], 401)
        self.assertEqual(self.request("POST", path, body, origin=DEV, pairing=pairing)[0], 401)
        tampered = signed_headers(pairing, "POST", path, json.dumps({"revokeToken": "other" * 9}).encode())
        self.assertEqual(self.request("POST", path, body, headers=tampered)[0], 401)
        signed = signed_headers(pairing, "POST", path, raw)
        status, _, job = self.request("POST", path, body, headers=signed)
        self.assertEqual(status, 202, job)
        self.assertEqual(self.request("POST", path, body, headers=signed)[0], 401)  # nonce replay
        self.assertEqual(self.request("GET", f"/jobs/{job['jobId']}")[0], 401)
        self.assertEqual(self.request("POST", "/sign", {"planToken": 5}, pairing=pairing)[0], 400)
        self.assertEqual(self.request("POST", "/sign", headers={"Content-Type": "application/json"}, pairing=pairing)[0], 400)

    def test_authorize_always_needs_typed_confirmation(self) -> None:
        self.serve(auto=True)
        pairing = self.pair()
        self.site.plans[fakes.TOKEN] = fakes.grant_plan(self.owner)
        status, _, job = self.request("POST", "/sign", {"planToken": fakes.TOKEN}, pairing=pairing)
        self.assertEqual(status, 202)
        self.server.wait_for("Type AUTHORIZE to sign and broadcast, anything else to cancel: ")
        self.server.type("no")
        self.assertEqual(self.wait(job["jobId"], pairing)["state"], "cancelled")
        self.assertEqual(self.chain.sent, [])
        token = "tok_" + "D" * 40
        self.site.plans[token] = fakes.grant_plan(self.owner)
        _, _, job = self.request("POST", "/sign", {"planToken": token}, pairing=pairing)
        for _ in range(400):
            if self.server.output.count("Type AUTHORIZE to sign") == 2:
                break
            time.sleep(0.05)
        self.server.type("AUTHORIZE")
        done = self.wait(job["jobId"], pairing)
        self.assertEqual(done["state"], "done", done)
        self.assertEqual(self.chain.sent[-1]["type"], 4)
        self.assertEqual(self.site.reports[-1], (token, done["txHash"]))
        self.assertEqual(done["message"], "Reported to the website.")
        self.assertIn("Owner:       " + self.owner, self.server.output)
        self.assertNotIn(self.world.private_key, self.server.output)

    def test_revoke_auto_confirm_only_when_enabled(self) -> None:
        for auto, answer, expected in ((True, None, "done"), (False, "REVOKE", "done"), (False, "nope", "cancelled")):
            with self.subTest(auto=auto, answer=answer):
                grant = "0x" + secrets.token_hex(32)
                self.chain.delegate(self.owner)
                self.chain.policy.setdefault(self.owner.lower(), {})[grant] = fakes.SESSION_KEY.lower()
                token = "tok_" + secrets.token_hex(20)
                self.site.plans[token] = fakes.revoke_plan(self.owner, grant)
                self.serve(auto=auto)
                pairing = self.pair()
                _, _, job = self.request("POST", "/revoke", {"revokeToken": token}, pairing=pairing)
                if answer is not None:
                    self.server.wait_for("Type REVOKE to sign and broadcast")
                    self.server.type(answer)
                result = self.wait(job["jobId"], pairing)
                self.assertEqual(result["state"], expected, (result, self.server.output[-2000:]))
                self.assertEqual(grant in self.chain.policy[self.owner.lower()], expected != "done")
                if auto:
                    self.assertIn("Auto-confirmed (--auto-confirm-revoke)", self.server.output)
                self.server.stop()

    def test_failed_verification_is_reported(self) -> None:
        self.serve()
        pairing = self.pair()
        self.site.plans[fakes.TOKEN] = {**fakes.grant_plan(self.owner), "implementation": "0x" + "66" * 20}
        _, _, job = self.request("POST", "/sign", {"planToken": fakes.TOKEN}, pairing=pairing)
        result = self.wait(job["jobId"], pairing)
        self.assertEqual(result["state"], "failed")
        self.assertIn("Wrong delegate", result["message"])
        self.assertNotIn("Type AUTHORIZE", self.server.output)
        other = {"pairingId": "x" * 32, "secret": "22" * 32}
        self.assertEqual(self.request("GET", f"/jobs/{job['jobId']}", pairing=other)[0], 401)


if __name__ == "__main__":
    unittest.main(verbosity=2)
