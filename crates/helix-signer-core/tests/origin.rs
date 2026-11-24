//! Origin rule kinds (10-26, version 2 Diamond): plan checks mirroring the
//! contract, kind-aware matching, and the summary the owner confirms.

mod common;

use common::*;
use helix_signer_core::abi::RawRule;
use helix_signer_core::chain::{AccountKind, AccountState};
use helix_signer_core::constants::{self as c, GrantKind};
use helix_signer_core::{custom, plan, summary, Address, U256};
use serde_json::{json, Value};

fn owner() -> Address {
    key("awake-helix signer tests: origin owner").address()
}

fn verify(plan_value: &Value) -> helix_signer_core::Result<helix_signer_core::GrantPlan> {
    plan::verify_grant_plan(plan_value, &constants(), Some(now()))
}

fn refusal(rules: Vec<RawRule>) -> String {
    verify(&grant_plan(&owner(), rules, 7 * 86400, 256)).unwrap_err().message().to_string()
}

fn state(kind: AccountKind) -> AccountState {
    let target = match kind {
        AccountKind::V1 => c::IMPLEMENTATION_V1.to_lowercase(),
        AccountKind::V2 => c::IMPLEMENTATION.to_lowercase(),
        _ => String::new(),
    };
    AccountState { kind, target, nonce: 0, balance: U256::from(10u128.pow(18)) }
}

#[test]
fn an_origin_grant_plan_is_accepted_with_its_units() {
    let verified = verify(&grant_plan(&owner(), origin_rules(), 7 * 86400, 256)).unwrap();
    assert_eq!(verified.implementation, Address::constant(c::IMPLEMENTATION));
    let kinds: Vec<u8> = verified.rules.iter().map(|rule| rule.kind).collect();
    assert_eq!(kinds, [0, 10, 11, 12, 14, 18, 25, 26]);
    let units: Vec<(&str, u32)> = verified.rules.iter().map(|rule| rule.unit()).collect();
    assert_eq!(units, [("DAI", 18), ("DAI", 18), ("LGNS", 9), ("LGNS", 9), ("calls", 0), ("calls", 0), ("DAI", 18), ("calls", 0)]);
    // Colliding method names are told apart by kind in messages.
    assert_eq!((verified.rules[1].method(), verified.rules[1].label().as_str()), ("participate", "participate (kind 10)"));
    assert_eq!(verified.rules[0].label(), "approve");
}

#[test]
fn every_origin_kind_and_approval_of_the_allow_list_is_accepted() {
    for (kind, entries) in c::RULE_ALLOWLIST {
        for (target, token_in, counterparty) in entries.iter() {
            let mut raw = rule(*kind, target, 1);
            raw.token_in = Address::constant(token_in);
            raw.counterparty = Address::constant(counterparty);
            if c::SWAP_KINDS.contains(kind) {
                raw.min_out_per_in_wad = U256::from(1);
            }
            if c::DEADLINE_KINDS.contains(kind) {
                raw.max_deadline_delay = 60;
            }
            if c::SECONDARY_KINDS.contains(kind) {
                raw.max_secondary = U256::from(1);
            }
            if *kind == 2 {
                raw.max_amount = U256::from(500_000_000_000u64);
                raw.max_daily = raw.max_amount;
            }
            verify(&grant_plan(&owner(), vec![raw], 7 * 86400, 16)).unwrap_or_else(|error| panic!("kind {kind} {target}: {error}"));
        }
    }
}

#[test]
fn origin_rules_outside_the_contract_bounds_are_refused() {
    let base = origin_rules;
    let with = |index: usize, change: &dyn Fn(&mut RawRule)| {
        let mut rules = base();
        change(&mut rules[index]);
        refusal(rules)
    };
    // Wrong target: participate (kind 10) on the HELIX PowerLedger, claim (kind 18) on the distributor.
    assert_eq!(
        with(1, &|rule| rule.target = Address::constant(c::LEDGER)),
        format!("Rule participate (kind 10) on PowerLedger (tokenIn {}, counterparty {}) is not on the Origin allow-list.", c::ZERO, c::ZERO)
    );
    assert!(with(5, &|rule| rule.target = Address::constant(c::COMMUNITY_DISTRIBUTOR)).contains("Rule claim (kind 18) on Community Distributor"));
    // The HELIX Turbine is not the Origin turbine.
    assert!(with(6, &|rule| rule.target = Address::constant(c::TURBINE)).contains("Rule silence (kind 25) on Turbine"));
    // An Origin kind names no token and no counterparty.
    let token = with(1, &|rule| rule.token_in = Address::constant(c::DAI));
    assert!(token.contains("tokenIn 0x83fd06F0846d9D90B3016bF670Efe2E0B11cDe14") && token.ends_with("is not on the Origin allow-list."), "{token}");
    assert!(with(4, &|rule| rule.counterparty = Address::constant(c::LGNS)).ends_with("is not on the Origin allow-list."));
    // Price floor and deadline of New Turbo participate, activate and sell.
    assert_eq!(with(1, &|rule| rule.min_out_per_in_wad = U256::ZERO), "Rule participate (kind 10) has no price floor.");
    assert_eq!(with(2, &|rule| rule.min_out_per_in_wad = U256::ZERO), "Rule activate (kind 11) has no price floor.");
    assert_eq!(with(3, &|rule| rule.max_deadline_delay = 0), "Rule sell (kind 12) has an unbounded deadline.");
    assert_eq!(with(2, &|rule| rule.max_deadline_delay = 3601), "Rule activate (kind 11) has an unbounded deadline.");
    // Deadline-only (silence) and no-deadline kinds.
    assert_eq!(with(6, &|rule| rule.max_deadline_delay = 0), "Rule silence (kind 25) has an unbounded deadline.");
    assert_eq!(with(6, &|rule| rule.min_out_per_in_wad = U256::from(1)), "Rule silence (kind 25) carries an unexpected price field.");
    assert_eq!(with(7, &|rule| rule.max_deadline_delay = 60), "Rule redeemSilence (kind 26) carries an unexpected deadline field.");
    // The activation DAI cap: required for kind 11, refused elsewhere.
    assert_eq!(with(2, &|rule| rule.max_secondary = U256::ZERO), "Activation rule activate (kind 11) has no DAI cap.");
    assert_eq!(with(1, &|rule| rule.max_secondary = U256::from(1)), "Rule participate (kind 10) carries an unexpected secondary cap.");
    // Counted kinds: one per call, the daily cap counts calls.
    let counted = "Rule claim (kind 14) counts calls: its per-call cap must be 1 and its daily cap the number of calls per UTC day.";
    assert_eq!(with(4, &|rule| rule.max_amount = U256::from(2)), counted);
    assert_eq!(
        with(7, &|rule| {
            rule.max_amount = U256::from(3);
            rule.max_daily = U256::from(3);
        }),
        "Rule redeemSilence (kind 26) counts calls: its per-call cap must be 1 and its daily cap the number of calls per UTC day."
    );
    assert_eq!(with(4, &|rule| rule.max_daily = U256::ZERO), "Rule claim (kind 14) has an invalid per-call or daily cap.");
    // Usage counters and kinds past the enum.
    assert_eq!(with(5, &|rule| rule.usage_day = 1), "A rule arrives with non-zero usage counters.");
    assert_eq!(refusal(vec![rule(27, c::ORIGIN_TURBINE, 1)]), "Unknown rule kind 27.");
    // HELIX messages are unchanged.
    let mut swap = rule(4, c::ROCKETSWAP_ROUTER, 1);
    swap.token_in = Address::constant(c::DAI);
    swap.counterparty = Address::constant(c::LGNS);
    swap.max_deadline_delay = 60;
    assert_eq!(refusal(vec![swap]), "Swap rule swapExactTokensForTokensSupportingFeeOnTransferTokens has no price floor.");
    let mut activate = rule(5, c::TURBINE, 1);
    activate.max_deadline_delay = 60;
    assert_eq!(refusal(vec![activate]), "Activation rule has no DAI cap.");
}

#[test]
fn a_grant_plan_must_name_the_version_2_diamond() {
    let mut plan_value = grant_plan(&owner(), origin_rules(), 7 * 86400, 256);
    plan_value["implementation"] = json!(c::IMPLEMENTATION_V1);
    let error = verify(&plan_value).unwrap_err();
    assert!(error.message().starts_with(&format!("Wrong delegate {}: that is the version 1 Helix7702 Diamond", c::IMPLEMENTATION_V1)), "{error}");
    plan_value["implementation"] = json!(format!("0x{}", "66".repeat(20)));
    let error = verify(&plan_value).unwrap_err();
    assert_eq!(error.message(), format!("Wrong delegate 0x{}: only Helix7702 implementation {} is accepted.", "66".repeat(20), c::IMPLEMENTATION));
}

#[test]
fn revoke_plans_may_name_either_diamond_but_must_match_the_wallet() {
    let grant = format!("0x{}", "ab".repeat(32));
    for implementation in [c::IMPLEMENTATION, c::IMPLEMENTATION_V1] {
        let verified = plan::verify_revoke_plan(&revoke_plan_naming(&owner(), &grant, GrantKind::Policy, implementation), &constants()).unwrap();
        assert_eq!(verified.implementation, Address::constant(implementation));
    }
    let other = format!("0x{}", "66".repeat(20));
    let error = plan::verify_revoke_plan(&revoke_plan_naming(&owner(), &grant, GrantKind::Policy, &other), &constants()).unwrap_err();
    assert_eq!(error.message(), format!("Wrong delegate {other}: only Helix7702 implementation {} or {} is accepted.", c::IMPLEMENTATION, c::IMPLEMENTATION_V1));
    // Bound to the wallet's Diamond: a plan naming version 2 for a wallet on version 1 is refused.
    let mut named_v2 = plan::verify_revoke_plan(&revoke_plan(&owner(), &grant, GrantKind::Policy), &constants()).unwrap();
    let error = plan::bind_revoke_delegate(&mut named_v2, Address::constant(c::IMPLEMENTATION_V1)).unwrap_err();
    assert!(error.message().starts_with(&format!("Wrong delegate {}: this account's grants run on the Helix7702 implementation {}", c::IMPLEMENTATION, c::IMPLEMENTATION_V1)), "{error}");
    // A plan naming no Diamond takes the wallet's.
    let mut unnamed = plan::offline_revoke(&owner().to_checksum(), &grant, "policy", &constants()).unwrap();
    plan::bind_revoke_delegate(&mut unnamed, Address::constant(c::IMPLEMENTATION_V1)).unwrap();
    assert_eq!(unnamed.implementation, Address::constant(c::IMPLEMENTATION_V1));
}

#[test]
fn the_preview_is_matched_by_kind_and_target() {
    let original = grant_plan(&owner(), origin_rules(), 7 * 86400, 256);
    verify(&original).unwrap();
    let preview_error = "The website's rule preview does not match the calldata.";
    // participate (kind 10) shown as kind 1, or without its kind.
    let mut wrong_kind = original.clone();
    wrong_kind["rules"][1]["kind"] = json!(1);
    assert_eq!(verify(&wrong_kind).unwrap_err().message(), preview_error);
    let mut no_kind = original.clone();
    no_kind["rules"][1].as_object_mut().unwrap().remove("kind");
    assert_eq!(verify(&no_kind).unwrap_err().message(), preview_error);
    let mut boolean = original.clone();
    boolean["rules"][4]["kind"] = json!(true);
    assert_eq!(verify(&boolean).unwrap_err().message(), preview_error);
    // claim (kind 18) on Burn Fixed shown on the distributor.
    let mut wrong_target = original.clone();
    wrong_target["rules"][5]["target"] = json!(c::COMMUNITY_DISTRIBUTOR);
    assert_eq!(verify(&wrong_target).unwrap_err().message(), preview_error);
    // A HELIX rule's preview may omit its kind (older websites).
    let mut helix = grant_plan(&owner(), dai_power(), 7 * 86400, 256);
    for item in helix["rules"].as_array_mut().unwrap() {
        item.as_object_mut().unwrap().remove("kind");
    }
    verify(&helix).unwrap();
}

#[test]
fn cap_names_are_kind_aware() {
    let mut rules = origin_rules();
    let mut participate = rule(1, c::LEDGER, 10);
    participate.max_daily = U256::from(10);
    rules.push(participate);
    let verified = verify(&grant_plan(&owner(), rules, 7 * 86400, 256)).unwrap();
    let rules = &verified.rules;
    let index = |text: &str| custom::parse_cap(&format!("{text}=,1"), rules).map(|cap| cap.0);
    assert_eq!(index("claim").unwrap_err().message(), "Several rules are claim; use a rule number (5, 6).");
    assert_eq!(index("claim@14").unwrap(), 4);
    assert_eq!(index("claim@18").unwrap(), 5);
    assert_eq!(index("CLAIM@burn fixed").unwrap(), 5);
    assert_eq!(index(&format!("claim@{}", c::COMMUNITY_DISTRIBUTOR.to_lowercase())).unwrap(), 4);
    assert_eq!(index("participate@10").unwrap(), 1);
    assert_eq!(index("participate@1").unwrap(), 8);
    assert_eq!(index("participate").unwrap_err().message(), "Several rules are participate; use a rule number (2, 9).");
    assert_eq!(index("claim@19").unwrap_err().message(), "No rule is called 'claim@19'; use a rule number from the summary.");
    assert_eq!(index("redeemSilence").unwrap(), 7);
    // A counted rule's per-call cap stays 1; its daily cap counts calls.
    let error = custom::with_changes(&verified, None, None, &[(4, Some("2".into()), None)]).unwrap_err();
    assert_eq!(error.message(), "Rule 5 (claim (kind 14)) counts calls: its per-call cap is always 1; change its per-day cap (calls per UTC day).");
    let request = custom::with_changes(&verified, None, None, &[(4, Some("1".into()), Some("3".into()))]).unwrap();
    assert_eq!((request.rules[4].max_per_call.as_deref(), request.rules[4].max_per_day.as_deref()), (Some("1"), Some("3")));
    // LGNS caps have 9 decimals.
    let request = custom::with_changes(&verified, None, None, &[(2, Some("600".into()), None)]).unwrap();
    assert_eq!(request.rules[2].max_per_day.as_deref(), Some("600"));
}

#[test]
fn origin_summary_names_contracts_units_floors_and_the_recipient() {
    let verified = verify(&grant_plan(&owner(), origin_rules(), 7 * 86400, 256)).unwrap();
    let shown = summary::grant_summary(&verified, &state(AccountKind::V2), Some(c::DEFAULT_API), c::DEFAULT_RPC, &constants());
    let text = shown.text();
    let expected = [
        "Transaction: ordinary self-call installing the grant (already delegated to Helix)",
        "Rules (decoded from the calldata; every target is on the pinned HELIX and Origin allow-list):",
        "  1. approve on DAI (0x83fd06F0846d9D90B3016bF670Efe2E0B11cDe14)",
        "     spender: New Turbo 2.5x (0x0664F1369209677FEcb279F5EC3Df1E53a22212e) (the only address the allowance may go to)",
        "     limit: 100 DAI per call, 100 DAI per UTC day",
        "  2. participate on New Turbo 2.5x (0x0664F1369209677FEcb279F5EC3Df1E53a22212e)",
        "     price floor: at least 10 LGNS per 1 DAI",
        "     deadline: at most 600 s ahead",
        "  3. activate on New Turbo 2.5x (0x0664F1369209677FEcb279F5EC3Df1E53a22212e)",
        "     DAI back: at least 0.9 DAI back per 1 DAI paid",
        "     limit: 500 LGNS per call, 500 LGNS per UTC day",
        "     activation DAI: at most 50 DAI per call",
        "  4. sell on New Turbo 2.5x (0x0664F1369209677FEcb279F5EC3Df1E53a22212e)",
        "     price floor: at least 0.5 DAI per 1 LGNS",
        "  5. claim on Community Distributor (0x71B514b8d08F61e39e24442c2Fc83297584C1Dd6)",
        "     limit: at most 2 calls per UTC day",
        "  6. claim on Burn Fixed (0x3f403751975e1EB06d95901f7FF246513444E71F)",
        "     limit: at most 24 calls per UTC day",
        "  7. silence on Origin Turbine (0x92B53785090F6FE0717Ca3cF5dB8f8040d3B070b)",
        "     limit: 10 DAI per call, 10 DAI per UTC day",
        "     deadline: at most 300 s ahead",
        "     recipient: always your own account (the contract refuses any other)",
        "  8. redeemSilence on Origin Turbine (0x92B53785090F6FE0717Ca3cF5dB8f8040d3B070b)",
        "     limit: at most 4 calls per UTC day",
    ];
    for line in expected {
        assert!(text.lines().any(|shown| shown == line), "missing {line:?} in\n{text}");
    }
    assert!(!text.contains("swap:"), "{text}");
    assert_eq!(text.matches("recipient: always your own account").count(), 2);
    let data = serde_json::to_value(&shown).unwrap();
    let rules = &data["grant"]["rules"];
    assert_eq!(rules[1]["floor"]["priceFloor"], "10");
    assert_eq!((rules[1]["floor"]["tokenInName"].as_str(), rules[1]["floor"]["tokenOutName"].as_str()), (Some("DAI"), Some("LGNS")));
    assert_eq!(rules[2]["activationDai"], "50");
    assert_eq!((rules[4]["unit"].as_str(), rules[4]["counted"].as_bool()), (Some("calls"), Some(true)));
    assert_eq!(rules[6]["paysOwner"], true);
    assert_eq!(rules[1]["swap"], Value::Null);
    assert_eq!(data["grant"]["originRules"], true);
    assert_eq!(data["grant"]["movesFrom"], Value::Null);
}

#[test]
fn the_grant_summary_says_how_the_wallet_reaches_version_2() {
    let verified = verify(&grant_plan(&owner(), dai_power(), 7 * 86400, 256)).unwrap();
    let text = |kind| summary::grant_summary(&verified, &state(kind), None, c::DEFAULT_RPC, &constants()).text();
    let moving = text(AccountKind::V1);
    assert!(moving.contains("Transaction: ONE EIP-7702 type-4 transaction from the owner to itself: move the account from the version 1 to the version 2 Helix Diamond and install the grant"), "{moving}");
    assert!(moving.contains(&format!("Moves from:  {} (the version 1 Diamond; the grants stored in the account are kept)", c::IMPLEMENTATION_V1)), "{moving}");
    assert!(moving.contains(&format!("Delegate:    {} (Helix7702 implementation, pinned, code hash verified)", c::IMPLEMENTATION)), "{moving}");
    // A HELIX-only grant keeps the former wording.
    assert!(moving.contains("every target is on the pinned HELIX allow-list"), "{moving}");
    assert!(text(AccountKind::Plain).contains("delegate the account and install the grant"));
    assert!(!text(AccountKind::Plain).contains("Moves from"));
    assert!(text(AccountKind::V2).contains("ordinary self-call installing the grant"));
    // A revocation on version 1 stays on version 1.
    let grant = format!("0x{}", "ab".repeat(32));
    let revoke = plan::offline_revoke(&owner().to_checksum(), &grant, "policy", &constants()).unwrap();
    let shown = summary::revoke_summary(&revoke, &state(AccountKind::V1), None, c::DEFAULT_RPC, &constants());
    assert!(shown.text().contains("Transaction: ordinary self-call revokePolicyGrant(bytes32)"));
    assert!(shown.text().contains(&format!("Delegation:  {} (stays in place; only the grant is revoked)", c::IMPLEMENTATION_V1.to_lowercase())));
    assert_eq!(shown.revoke.unwrap().delegate, Address::constant(c::IMPLEMENTATION_V1));
}
