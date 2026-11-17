//! The command layer against a mock core: what each command allows, what it
//! wipes, and how a revocation sequence is confirmed, cancelled or refused.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use helix_signer_app_lib::backend::{Core, KeyInput, LinkInfo, Log, RevokeDone};
use helix_signer_app_lib::controller::{Controller, Events, IDLE_WIPE};
use helix_signer_app_lib::views::{
    CommandError, EditorBounds, EditorPlan, GrantRowView, KeyView, ListingView, PingView, SessionView, SignResult,
};
use helix_signer_core::{Address, Message, PlanKind, Summary};
use serde_json::{json, Value};

fn refused(text: &str) -> CommandError {
    CommandError::refused(Message::plain("plan", text))
}

fn line(text: &str) -> Message {
    Message::plain("log", text)
}

fn summary(kind: PlanKind) -> Summary {
    Summary {
        kind,
        signer_version: "0.5.2".into(),
        website: Some(API.into()),
        official_website: true,
        chain_id: 6714,
        rpc_url: "https://rpc.anubispace.org".into(),
        development: false,
        owner: Address::constant(OWNER),
        transaction: String::new(),
        balance: "1 DAI".into(),
        grant: None,
        revoke: None,
    }
}

const OWNER: &str = "0x814CEceE4ab7a2c37ED2F2C67bef5B325Ac53bDF";
const API: &str = "https://anubis.sivilization.com";

/// A key whose wipe is observable. Like `KeyMaterial`, a clone is an
/// independent copy: wiping the copy leaves the original alone.
struct Key {
    wiped: Arc<AtomicBool>,
}

impl Clone for Key {
    fn clone(&self) -> Self {
        Key { wiped: Arc::new(AtomicBool::new(self.wiped.load(Ordering::SeqCst))) }
    }
}

#[derive(Clone, Debug)]
struct Session {
    kind: &'static str,
    calls: u64,
    grant: String,
}

struct Site {
    signed_in: AtomicBool,
}

type Hook = Box<dyn Fn(usize) + Send + Sync>;

#[derive(Default)]
struct Mock {
    keys: Mutex<Vec<Arc<AtomicBool>>>,
    calls: Mutex<Vec<String>>,
    fail_prepare: AtomicBool,
    revoked: Mutex<Vec<String>>,
    executed: AtomicUsize,
    fail_revoke_at: Mutex<Option<usize>>,
    /// Set while the second revocation runs: the test cancels then.
    on_revoke: Mutex<Option<Hook>>,
    /// Rows listed after the three default ones.
    extra: Mutex<Vec<GrantRowView>>,
}

impl Mock {
    fn record(&self, call: impl Into<String>) {
        self.calls.lock().unwrap().push(call.into());
    }
    fn called(&self, prefix: &str) -> usize {
        self.calls.lock().unwrap().iter().filter(|call| call.starts_with(prefix)).count()
    }
    fn live_keys(&self) -> usize {
        self.keys.lock().unwrap().iter().filter(|flag| !flag.load(Ordering::SeqCst)).count()
    }
    fn listing(&self) -> ListingView {
        let revoked = self.revoked.lock().unwrap().clone();
        let row = |id: &str, status: &str| GrantRowView {
            grant_id: id.into(),
            kind: "policy".into(),
            status: if revoked.iter().any(|item| item == id) { "revoked".into() } else { status.into() },
            key: "0xkey".into(),
            key_origin: "hosted".into(),
            bot: "dai-power #12 (running)".into(),
            bot_state: "running".into(),
            bot_script: "dai-power".into(),
            bot_id: "12".into(),
            valid_until: Some(1),
            remaining_calls: Some(3),
            revocable: !revoked.iter().any(|item| item == id),
            active: !revoked.iter().any(|item| item == id) && status == "active",
            delegation: "helix".into(),
            not_revocable_reason: String::new(),
        };
        let mut rows = vec![row("0xa1", "active"), row("0xb2", "active"), row("0xc3", "expired")];
        rows.extend(self.extra.lock().unwrap().iter().cloned());
        ListingView {
            owner: OWNER.to_lowercase(),
            rows,
            scan_complete: true,
            scan_percent: 100,
            truncated: false,
        }
    }
}

struct MockCore(Arc<Mock>);

impl Core for MockCore {
    type Key = Key;
    type Session = Session;
    type Site = Site;

    fn development(&self) -> bool {
        false
    }
    fn rpc_url(&self) -> String {
        "https://rpc.anubispace.org".into()
    }
    fn default_api(&self) -> String {
        API.into()
    }
    fn chain_id(&self) -> u64 {
        6714
    }
    fn official(&self, api: &str) -> bool {
        api == API
    }
    fn parse_link(&self, url: &str) -> Result<LinkInfo, CommandError> {
        let action = url.strip_prefix("awakehelix://").and_then(|rest| rest.split('?').next()).unwrap_or_default();
        if !["sign", "revoke", "ping", "grants"].contains(&action) {
            return Err(refused("Not an awakehelix:// link."));
        }
        let api = if url.contains("api=http://127.0.0.1") { "http://127.0.0.1:9".to_string() } else { API.to_string() };
        Ok(LinkInfo { action: action.into(), token: "T".repeat(32), api })
    }
    fn load_key(&self, input: KeyInput) -> Result<Key, CommandError> {
        if let KeyInput::PrivateKey { secret } = &input {
            if secret.0.as_str() != "good" {
                return Err(refused("The private key must be 64 hexadecimal characters."));
            }
        }
        let wiped = Arc::new(AtomicBool::new(false));
        self.0.keys.lock().unwrap().push(Arc::clone(&wiped));
        Ok(Key { wiped })
    }
    fn key_view(&self, _: &Key) -> KeyView {
        KeyView { address: OWNER.into(), source: "privateKey".into(), derivation_path: None }
    }
    fn wipe(&self, key: &mut Key) {
        key.wiped.store(true, Ordering::SeqCst);
    }
    fn export_keystore(&self, key: &Key, password: &str) -> Result<String, CommandError> {
        assert!(!key.wiped.load(Ordering::SeqCst));
        Ok(json!({ "version": 3, "address": OWNER, "password-length": password.len() }).to_string())
    }
    fn prepare(&self, link: &LinkInfo, key: &Key, log: Log) -> Result<Session, CommandError> {
        assert!(!key.wiped.load(Ordering::SeqCst), "prepare got a wiped key");
        self.0.record(format!("prepare {}", link.action));
        log(&line("Fetching plan ..."));
        if self.0.fail_prepare.load(Ordering::SeqCst) {
            return Err(refused("The plan's delegate is not the pinned Helix7702 implementation."));
        }
        Ok(Session { kind: if link.action == "sign" { "grant" } else { "revoke" }, calls: 256, grant: "0xg".into() })
    }
    fn customize(&self, session: &Session, request: &Value, _: Log) -> Result<Session, CommandError> {
        self.0.record(format!("customize {request}"));
        let calls = request.get("remainingCalls").and_then(Value::as_u64).unwrap_or(256);
        if calls > 4096 {
            return Err(CommandError::new("customize", Message::plain("customizeRefused", "The call count must be between 2 and 4096.")));
        }
        if calls == 13 {
            return Err(refused("The website's new plan changes owner, which an edit may never change."));
        }
        Ok(Session { calls, ..session.clone() })
    }
    fn session_view(&self, session: &Session) -> SessionView {
        SessionView {
            kind: session.kind.into(),
            confirm_word: if session.kind == "grant" { "AUTHORIZE" } else { "REVOKE" }.into(),
            summary: format!("Calls: at most {} bot operations in total", session.calls),
            summary_data: summary(if session.kind == "grant" { PlanKind::Grant } else { PlanKind::Revoke }),
            editor: (session.kind == "grant").then(|| EditorPlan {
                valid_until: 1,
                remaining_calls: session.calls,
                bounds: EditorBounds::default(),
                rules: Vec::new(),
            }),
        }
    }
    fn execute(&self, session: &Session, mut key: Key, log: Log) -> Result<SignResult, CommandError> {
        assert!(!key.wiped.load(Ordering::SeqCst));
        self.0.record(format!("execute {}", session.calls));
        log(&line("Broadcasting ..."));
        self.wipe(&mut key);
        Ok(SignResult { tx_hash: "0xtx".into(), block: 101, reported: true, report_message: String::new() })
    }
    fn website(&self, api: &str) -> Result<Site, CommandError> {
        self.0.record(format!("website {api}"));
        Ok(Site { signed_in: AtomicBool::new(false) })
    }
    fn signed_in(&self, site: &Site) -> bool {
        site.signed_in.load(Ordering::SeqCst)
    }
    fn login(&self, site: &Site, _: &Key, log: Log) -> Result<(), CommandError> {
        self.0.record("login");
        log(&line("Signing in (a signature only; no transaction) ..."));
        site.signed_in.store(true, Ordering::SeqCst);
        Ok(())
    }
    fn logout(&self, site: &Site) {
        self.0.record("logout");
        site.signed_in.store(false, Ordering::SeqCst);
    }
    fn grants(&self, _: &Site) -> Result<ListingView, CommandError> {
        self.0.record("grants");
        Ok(self.0.listing())
    }
    fn prepare_grant_revoke(&self, _: &Site, grant_id: &str, _: &Key, _: Log) -> Result<Option<Session>, CommandError> {
        self.0.record(format!("prepare-revoke {grant_id}"));
        Ok((grant_id != "0xc3").then(|| Session { kind: "revoke", calls: 0, grant: grant_id.into() }))
    }
    fn grant_of(&self, session: &Session) -> String {
        session.grant.clone()
    }
    fn execute_grant_revoke(&self, session: &Session, key: &Key, _: &Site, _: Log) -> Result<RevokeDone, CommandError> {
        assert!(!key.wiped.load(Ordering::SeqCst));
        let number = self.0.executed.fetch_add(1, Ordering::SeqCst);
        if let Some(hook) = self.0.on_revoke.lock().unwrap().as_ref() {
            hook(number);
        }
        if *self.0.fail_revoke_at.lock().unwrap() == Some(number) {
            return Err(refused("The chain refused the transaction."));
        }
        self.0.revoked.lock().unwrap().push(session.grant.clone());
        Ok(RevokeDone { tx_hash: format!("0x{number}"), block: 200 + number as u64, stopped_bots: vec!["7".into()] })
    }
    fn ping(&self, link: &LinkInfo) -> Result<PingView, CommandError> {
        Ok(PingView { version: "0.5.2".into(), os: "linux".into(), arch: "x86_64".into(), api: link.api.clone() })
    }
}

#[derive(Default)]
struct Recorder {
    lines: Mutex<Vec<(String, String)>>,
    progress: Mutex<Vec<(usize, usize)>>,
    wiped: AtomicUsize,
}
impl Events for Recorder {
    fn log(&self, scope: &'static str, line: &Message) {
        self.lines.lock().unwrap().push((scope.into(), line.text.clone()));
    }
    fn progress(&self, done: usize, total: usize) {
        self.progress.lock().unwrap().push((done, total));
    }
    fn key_wiped(&self) {
        self.wiped.fetch_add(1, Ordering::SeqCst);
    }
}

fn setup() -> (Arc<Controller<MockCore>>, Arc<Mock>, Arc<Recorder>) {
    let mock = Arc::new(Mock::default());
    let events = Arc::new(Recorder::default());
    (Arc::new(Controller::new(MockCore(Arc::clone(&mock)), events.clone())), mock, events)
}

fn private_key(secret: &str) -> KeyInput {
    serde_json::from_value(json!({ "kind": "privateKey", "secret": secret })).unwrap()
}

fn sign_link(controller: &Controller<MockCore>) {
    controller.open_link(&format!("awakehelix://sign?plan={}", "T".repeat(32))).unwrap();
}

#[test]
fn key_input_deserializes_every_source() {
    let keystore: KeyInput = serde_json::from_value(json!({ "kind": "keystore", "path": "/k.json", "password": "pw" })).unwrap();
    assert!(matches!(keystore, KeyInput::Keystore { path: Some(_), json: None, .. }));
    let mobile: KeyInput = serde_json::from_value(json!({ "kind": "keystore", "json": "{}", "password": "pw" })).unwrap();
    assert!(matches!(mobile, KeyInput::Keystore { path: None, json: Some(_), .. }));
    let mnemonic: KeyInput = serde_json::from_value(json!({ "kind": "mnemonic", "phrase": "abandon", "index": 3 })).unwrap();
    assert!(matches!(mnemonic, KeyInput::Mnemonic { index: 3, .. }));
    // The secret never shows in Debug output.
    assert!(!format!("{:?}", private_key("0xdeadbeef")).contains("deadbeef"));
    assert!(serde_json::from_value::<KeyInput>(json!({ "kind": "seed", "x": 1 })).is_err());
}

#[test]
fn authorize_flow_verifies_edits_signs_and_wipes() {
    let (controller, mock, events) = setup();
    sign_link(&controller);
    // No key yet: nothing is fetched.
    assert_eq!(controller.prepare_request().unwrap_err().kind, "nokey");
    let key = controller.load_key(private_key("good")).unwrap();
    assert_eq!(key.address, OWNER);
    let session = controller.prepare_request().unwrap();
    assert_eq!(session.confirm_word, "AUTHORIZE");
    assert!(session.editor.is_some());
    assert!(events.lines.lock().unwrap().iter().any(|(scope, line)| scope == "request" && line == "Fetching plan ..."));

    let edited = controller.customize(&json!({ "remainingCalls": 200 })).unwrap();
    assert!(edited.summary.contains("at most 200"));
    // Out of bounds: refused as "customize" and the verified plan stays signable.
    let refused = controller.customize(&json!({ "remainingCalls": 5000 })).unwrap_err();
    assert_eq!(refused.kind, "customize");
    assert_eq!(controller.key_status().map(|key| key.address), Some(OWNER.to_string()));

    // A wrong word is refused; full-width / lower case (input methods) count.
    assert!(controller.sign("AUTHORIZ").unwrap_err().message.contains("Type AUTHORIZE exactly"));
    let result = controller.sign(" ａｕｔｈｏｒｉｚｅ ").unwrap();
    assert_eq!(result.block, 101);
    assert_eq!(mock.called("execute 200"), 1, "the edited plan was signed");
    // The key is gone after signing; a second sign has nothing to sign.
    assert!(controller.key_status().is_none());
    assert_eq!(mock.live_keys(), 0);
    assert!(controller.sign("AUTHORIZE").is_err());
}

#[test]
fn a_refused_plan_or_answer_ends_the_request_and_wipes_the_key() {
    let (controller, mock, _) = setup();
    sign_link(&controller);
    controller.load_key(private_key("good")).unwrap();
    mock.fail_prepare.store(true, Ordering::SeqCst);
    let error = controller.prepare_request().unwrap_err();
    assert_eq!(error.kind, "refused");
    assert!(error.message.contains("pinned Helix7702"));
    assert!(controller.key_status().is_none());
    assert_eq!(mock.live_keys(), 0);

    mock.fail_prepare.store(false, Ordering::SeqCst);
    controller.load_key(private_key("good")).unwrap();
    controller.prepare_request().unwrap();
    // A tampered customize answer (not an out-of-bounds refusal) ends it too.
    let error = controller.customize(&json!({ "remainingCalls": 13 })).unwrap_err();
    assert_eq!(error.kind, "refused");
    assert!(controller.key_status().is_none());
    assert!(controller.sign("AUTHORIZE").is_err());
}

#[test]
fn bad_key_is_refused_and_nothing_is_kept() {
    let (controller, mock, _) = setup();
    let error = controller.load_key(private_key("0x12")).unwrap_err();
    assert_eq!(error.kind, "refused");
    assert!(controller.key_status().is_none());
    assert_eq!(mock.keys.lock().unwrap().len(), 0);
}

#[test]
fn revoke_link_and_grant_edit_rules() {
    let (controller, _, _) = setup();
    controller.open_link(&format!("awakehelix://revoke?plan={}", "R".repeat(32))).unwrap();
    controller.load_key(private_key("good")).unwrap();
    let session = controller.prepare_request().unwrap();
    assert_eq!(session.confirm_word, "REVOKE");
    assert!(session.editor.is_none());
    assert!(controller.customize(&json!({})).unwrap_err().message.contains("Only a grant"));
    assert!(controller.sign("AUTHORIZE").is_err());
    assert_eq!(controller.sign("REVOKE").unwrap().tx_hash, "0xtx");
}

#[test]
fn links_set_the_website_and_ping_is_separate() {
    let (controller, mock, _) = setup();
    let view = controller.open_link("awakehelix://grants").unwrap();
    assert_eq!((view.action.as_str(), view.official), ("grants", true));
    assert!(controller.open_link("https://evil.example").is_err());
    let ping = controller.ping(&format!("awakehelix://ping?token={}", "P".repeat(32))).unwrap();
    assert_eq!(ping.version, "0.5.2");
    assert!(controller.ping("awakehelix://grants").is_err());

    // Signed in to one website, a link to another drops that session.
    controller.load_key(private_key("good")).unwrap();
    controller.grants_load().unwrap();
    assert_eq!(mock.called("login"), 1);
    let other = controller.open_link("awakehelix://grants?api=http://127.0.0.1:9").unwrap();
    assert!(!other.official);
    assert_eq!(mock.called("logout"), 1);
    assert_eq!(controller.api(), "http://127.0.0.1:9");
    controller.grants_load().unwrap();
    assert_eq!(mock.called("login"), 2);
    assert_eq!(mock.called("website http://127.0.0.1:9"), 1);
}

#[test]
fn grants_sign_in_once_list_and_revoke_one() {
    let (controller, mock, events) = setup();
    assert_eq!(controller.grants_load().unwrap_err().kind, "nokey");
    controller.load_key(private_key("good")).unwrap();
    let listing = controller.grants_load().unwrap();
    assert_eq!(listing.rows.len(), 3);
    controller.grants_load().unwrap();
    assert_eq!(mock.called("login"), 1, "the website session is reused");

    // Only revocable grants of this listing can be chosen.
    assert!(controller.grants_prepare(Some(vec!["0xzz".into()])).is_err());
    let pending = controller.grants_prepare(Some(vec!["0xa1".into()])).unwrap();
    assert_eq!(pending.count, 1);
    assert!(controller.grants_confirm("REVOK").unwrap_err().message.contains("Type REVOKE exactly"));
    let outcome = controller.grants_confirm("ＲＥＶＯＫＥ").unwrap();
    assert_eq!((outcome.done, outcome.total, outcome.cancelled), (1, 1, false));
    assert_eq!(outcome.lines.iter().map(|line| line.text.as_str()).collect::<Vec<_>>(), vec!["Revoked 0xa1 in transaction 0x0 (block 200); bot(s) stopped: 7."]);
    assert_eq!((outcome.lines[0].code, outcome.lines[0].param("bots")), ("app.revokedStopped", Some("7")));
    assert_eq!(outcome.listing.rows[0].status, "revoked");
    assert_eq!(*events.progress.lock().unwrap(), vec![(0, 1), (1, 1)]);
    // The key stays for more work; nothing is pending any more.
    assert!(controller.key_status().is_some());
    assert!(controller.grants_confirm("REVOKE").is_err());
}

fn extra_row(id: &str, status: &str, revocable: bool, active: bool, reason: &str) -> GrantRowView {
    GrantRowView {
        grant_id: id.into(),
        kind: "policy".into(),
        status: status.into(),
        key: "0xkey".into(),
        key_origin: "hosted".into(),
        bot: "no linked bot".into(),
        bot_state: "none".into(),
        bot_script: String::new(),
        bot_id: String::new(),
        valid_until: Some(1),
        remaining_calls: Some(3),
        revocable,
        active,
        delegation: if reason.is_empty() { "none".into() } else { "other".into() },
        not_revocable_reason: reason.into(),
    }
}

#[test]
fn only_revocable_rows_can_be_revoked_and_revoke_all_includes_dormant_grants() {
    let (controller, mock, _) = setup();
    mock.extra.lock().unwrap().extend([
        extra_row("0xd4", "inactive", true, true, ""),
        extra_row("0xe5", "inactive", false, false, "otherDelegation"),
        extra_row("0xf6", "unavailable", false, false, ""),
        extra_row("0x07", "missing", false, false, ""),
        extra_row("0x08", "some_future_status", false, false, ""),
    ]);
    controller.load_key(private_key("good")).unwrap();
    let listing = controller.grants_load().unwrap();
    assert_eq!(listing.rows.len(), 8);
    assert_eq!(listing.rows[4].not_revocable_reason, "otherDelegation");
    for id in ["0xe5", "0xf6", "0x07", "0x08"] {
        let error = controller.grants_prepare(Some(vec![id.into()])).unwrap_err();
        assert!(error.message.contains("is not a revocable grant"), "{id}: {}", error.message);
    }
    assert_eq!(mock.called("prepare-revoke"), 0);
    // A dormant grant of an account without code can be chosen, and is in "revoke all".
    assert_eq!(controller.grants_prepare(Some(vec!["0xd4".into()])).unwrap().count, 1);
    controller.grants_cancel();
    assert_eq!(controller.grants_prepare(None).unwrap().count, 3, "two active grants and the dormant one");
    assert_eq!(mock.called("prepare-revoke 0xd4"), 2);
    assert_eq!(mock.called("prepare-revoke 0xe5"), 0);
}

#[test]
fn revoke_all_skips_gone_grants_and_cancel_discards() {
    let (controller, mock, _) = setup();
    controller.load_key(private_key("good")).unwrap();
    controller.grants_load().unwrap();
    let pending = controller.grants_prepare(None).unwrap();
    assert_eq!(pending.count, 2, "both active grants");
    assert_eq!(mock.called("prepare-revoke"), 2);
    controller.grants_cancel();
    assert!(controller.grants_confirm("REVOKE").unwrap_err().message.contains("Nothing is waiting"));
    assert_eq!(mock.executed.load(Ordering::SeqCst), 0);
}

#[test]
fn cancel_stops_after_the_current_transaction() {
    let (controller, mock, _) = setup();
    controller.load_key(private_key("good")).unwrap();
    controller.grants_load().unwrap();
    controller.grants_prepare(None).unwrap();
    let canceller = Arc::clone(&controller);
    *mock.on_revoke.lock().unwrap() = Some(Box::new(move |number| {
        if number == 0 {
            canceller.grants_cancel();
        }
    }));
    let outcome = controller.grants_confirm("REVOKE").unwrap();
    assert_eq!((outcome.done, outcome.total, outcome.cancelled), (1, 2, true));
    assert_eq!(mock.executed.load(Ordering::SeqCst), 1);
}

#[test]
fn a_failed_revocation_reports_how_many_were_done() {
    let (controller, mock, _) = setup();
    controller.load_key(private_key("good")).unwrap();
    controller.grants_load().unwrap();
    controller.grants_prepare(None).unwrap();
    *mock.fail_revoke_at.lock().unwrap() = Some(1);
    let error = controller.grants_confirm("REVOKE").unwrap_err();
    assert!(error.message.contains("revoked 1 of 2 before this"), "{}", error.message);
    // The page translates the wrapper and the cause on their own.
    assert_eq!((error.msg.code, error.msg.param("done"), error.msg.param("total")), ("app.revokedBefore", Some("1"), Some("2")));
    assert_eq!(serde_json::to_value(&error.msg).unwrap()["params"]["cause"]["text"], "The chain refused the transaction.");
    // Unlike a refused signing request, the key stays so the user can retry.
    assert!(controller.key_status().is_some());
}

#[test]
fn forget_wipes_key_logs_out_and_drops_pending() {
    let (controller, mock, _) = setup();
    controller.load_key(private_key("good")).unwrap();
    controller.grants_load().unwrap();
    controller.grants_prepare(None).unwrap();
    controller.forget_key();
    assert!(controller.key_status().is_none());
    assert_eq!(mock.live_keys(), 0);
    assert_eq!(mock.called("logout"), 1);
    assert_eq!(controller.grants_confirm("REVOKE").unwrap_err().kind, "refused");
    // Loading again signs in again.
    controller.load_key(private_key("good")).unwrap();
    controller.grants_load().unwrap();
    assert_eq!(mock.called("login"), 2);
}

#[test]
fn idle_key_is_wiped_after_ten_minutes() {
    let (controller, mock, events) = setup();
    controller.load_key(private_key("good")).unwrap();
    assert!(!controller.idle_check(Instant::now() + IDLE_WIPE - Duration::from_secs(5)));
    assert!(controller.key_status().is_some());
    assert!(controller.idle_check(Instant::now() + IDLE_WIPE + Duration::from_secs(1)));
    assert!(controller.key_status().is_none());
    assert_eq!(mock.live_keys(), 0);
    assert_eq!(events.wiped.load(Ordering::SeqCst), 1);
    assert!(!controller.idle_check(Instant::now() + IDLE_WIPE * 2), "nothing left to wipe");
}

#[test]
fn one_long_command_at_a_time() {
    let (controller, mock, _) = setup();
    controller.load_key(private_key("good")).unwrap();
    controller.grants_load().unwrap();
    controller.grants_prepare(Some(vec!["0xa1".into()])).unwrap();
    let inner = Arc::clone(&controller);
    let seen = Arc::new(Mutex::new(None));
    let seen_inner = Arc::clone(&seen);
    *mock.on_revoke.lock().unwrap() = Some(Box::new(move |_| {
        *seen_inner.lock().unwrap() = Some((inner.is_busy(), inner.grants_load().map(|_| ()), inner.open_link("awakehelix://grants").map(|_| ())));
    }));
    controller.grants_confirm("REVOKE").unwrap();
    let (busy, load, open) = seen.lock().unwrap().take().unwrap();
    assert!(busy);
    assert_eq!(load.unwrap_err().kind, "busy");
    assert_eq!(open.unwrap_err().kind, "busy");
    assert!(!controller.is_busy());
}

#[test]
fn export_keystore_needs_a_key_and_a_real_password() {
    let (controller, mock, _) = setup();
    assert_eq!(controller.export_keystore("long enough").unwrap_err().kind, "nokey");
    controller.load_key(private_key("good")).unwrap();
    assert!(controller.export_keystore("short").unwrap_err().message.contains("at least 8"));
    let json: Value = serde_json::from_str(&controller.export_keystore("long enough").unwrap()).unwrap();
    assert_eq!(json["address"], OWNER);
    // The copy used for export is wiped; the loaded key stays.
    assert_eq!(mock.live_keys(), 1);
}

#[test]
fn close_request_keeps_the_website() {
    let (controller, _, _) = setup();
    controller.open_link("awakehelix://sign?plan=x&api=http://127.0.0.1:9").unwrap();
    controller.close_request().unwrap();
    assert_eq!(controller.api(), "http://127.0.0.1:9");
    controller.load_key(private_key("good")).unwrap();
    assert!(controller.prepare_request().unwrap_err().message.contains("Open a request"));
}

#[test]
fn errors_carry_codes_for_the_page() {
    let (controller, _, _) = setup();
    let error = controller.prepare_request().unwrap_err();
    assert_eq!((error.kind, error.msg.code), ("refused", "app.noRequest"));
    assert_eq!(error.message, error.msg.text);
    sign_link(&controller);
    controller.load_key(private_key("good")).unwrap();
    controller.prepare_request().unwrap();
    let error = controller.sign("AUTHORIZ").unwrap_err();
    assert_eq!((error.msg.code, error.msg.param("word")), ("app.mustType", Some("AUTHORIZE")));
    let json = serde_json::to_value(&error).unwrap();
    assert_eq!(json["msg"]["code"], "app.mustType");
    assert_eq!(json["message"], "Type AUTHORIZE exactly to sign.");
    assert_eq!(CommandError::busy().msg.code, "app.busy");
    assert_eq!(CommandError::no_key().msg.code, "app.noKey");
}
