//! The command layer with the real core library against the fake website and
//! chain of the signer test fakes (tests/py/fakes.py, served over
//! HTTP by app/e2e/fake_server.py): open link -> load key -> verify -> edit ->
//! authorize, and My grants -> revoke one -> revoke all.
//!
//! Needs a Python with eth-account: set HELIX_FAKES_PYTHON (the Linux build
//! image has /opt/fakes/bin/python; `build.sh test` sets it). Skipped otherwise.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use helix_signer_app_lib::backend::{KeyInput, RealCore};
use helix_signer_app_lib::controller::{Controller, NoEvents};
use serde_json::{json, Value};

struct Fake {
    child: Child,
    config: Value,
    _dir: tempfile::TempDir,
}

impl Drop for Fake {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Fake {
    fn start() -> Option<Fake> {
        let python = std::env::var_os("HELIX_FAKES_PYTHON")?;
        let script = std::env::var_os("HELIX_FAKE_SERVER")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../e2e/fake_server.py"));
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        let mut child = Command::new(python)
            .arg("-I")
            .arg(&script)
            .arg(&config_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start the fake server");
        // The server prints its (pretty) config once it listens; it ends with "}".
        let mut text = String::new();
        let mut lines = BufReader::new(child.stdout.take().unwrap());
        loop {
            let mut line = String::new();
            if lines.read_line(&mut line).unwrap() == 0 {
                panic!("fake server exited: {text}");
            }
            text.push_str(&line);
            if line.trim_end() == "}" {
                break;
            }
        }
        let config: Value = serde_json::from_str(&text).expect("fake server config");
        Some(Fake { child, config, _dir: dir })
    }

    fn api(&self) -> &str {
        self.config["api"].as_str().unwrap()
    }

    /// GET/POST a control endpoint of the fake server.
    fn control(&self, method: &str, path: &str) -> Value {
        let address = self.api().trim_start_matches("http://");
        let mut stream = TcpStream::connect(address).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        write!(stream, "{method} {path} HTTP/1.1\r\nHost: {address}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        let mut raw = String::new();
        stream.read_to_string(&mut raw).unwrap();
        let body = raw.split("\r\n\r\n").nth(1).unwrap_or_default();
        serde_json::from_str(body).unwrap()
    }

    fn controller(&self) -> Arc<Controller<RealCore>> {
        let core = RealCore::development(
            std::path::Path::new(self.config["constants"].as_str().unwrap()),
            self.config["rpc"].as_str().unwrap(),
            Some(self.api()),
        )
        .expect("development constants on a loopback RPC");
        Arc::new(Controller::new(core, Arc::new(NoEvents)))
    }

    fn key(&self) -> KeyInput {
        serde_json::from_value(json!({ "kind": "privateKey", "secret": self.config["privateKey"] })).unwrap()
    }
}

macro_rules! fake_or_skip {
    () => {
        match Fake::start() {
            Some(fake) => fake,
            None => {
                eprintln!("skipped: set HELIX_FAKES_PYTHON to a Python with eth-account");
                return;
            }
        }
    };
}

fn editor_calls(session: &helix_signer_app_lib::views::SessionView) -> u64 {
    session.editor.as_ref().map(|editor| editor.remaining_calls).unwrap_or_default()
}

#[test]
fn development_constants_need_a_loopback_rpc() {
    let fake = fake_or_skip!();
    let error = RealCore::development(
        std::path::Path::new(fake.config["constants"].as_str().unwrap()),
        "https://rpc.anubispace.org",
        None,
    )
    .err()
    .expect("refused");
    assert!(error.message.contains("loopback"), "{}", error.message);
}

#[test]
fn open_link_verify_edit_authorize() {
    let fake = fake_or_skip!();
    let controller = fake.controller();
    let token = fake.config["signToken"].as_str().unwrap();

    // A loopback website is accepted only with development constants.
    let link = controller.open_link(&format!("anubisauto://sign?plan={token}&api={}", fake.api())).unwrap();
    assert_eq!(link.action, "sign");
    assert!(!link.official);
    let key = controller.load_key(fake.key()).unwrap();
    assert_eq!(key.address, fake.config["owner"].as_str().unwrap());

    let session = controller.prepare_request().unwrap();
    assert_eq!(session.kind, "grant");
    assert_eq!(session.confirm_word, "AUTHORIZE");
    assert!(session.summary.contains(fake.config["owner"].as_str().unwrap()), "{}", session.summary);
    // The same summary as data, for the page to render in its language.
    let data = serde_json::to_value(&session.summary_data).unwrap();
    assert_eq!(data["owner"].as_str().unwrap().to_lowercase(), fake.config["owner"].as_str().unwrap().to_lowercase());
    assert_eq!(data["grant"]["remainingCalls"], editor_calls(&session));
    let editor = session.editor.clone().expect("a grant has an editor");
    assert_eq!(editor.rules.len(), 2);
    assert_eq!(editor.rules[0].max_per_call, "10");
    assert_eq!(editor.rules[0].decimals, 18);
    // Rules are named by kind and target (method names repeat across kinds).
    assert_eq!((editor.rules[0].kind, editor.rules[0].target_name.as_str()), (0, "DAI"));
    assert_eq!((editor.rules[1].kind, editor.rules[1].method.as_str(), editor.rules[1].target_name.as_str()), (1, "participate", "PowerLedger"));
    assert!(!editor.rules[1].counted);

    // Out of the website's bounds: refused, the verified plan stays.
    let refused = controller.customize(&json!({ "validUntil": editor.valid_until, "remainingCalls": 999999, "rules": [] })).unwrap_err();
    assert_eq!(refused.kind, "customize", "{}", refused.message);
    // The website's answer travels with its code, Chinese and English texts.
    assert_eq!(refused.msg.code, "website", "{:?}", refused.msg);

    let until = editor.valid_until - 86400;
    let edited = controller
        .customize(&json!({
            "validUntil": until,
            "remainingCalls": 200,
            "rules": [
                { "index": 0, "maxPerCall": "15", "maxPerDay": "30" },
                { "index": 1, "maxPerCall": "10", "maxPerDay": "10" }
            ]
        }))
        .unwrap();
    let edited_plan = edited.editor.clone().unwrap();
    assert_eq!(edited_plan.remaining_calls, 200);
    assert_eq!(edited_plan.valid_until, until);
    assert_eq!(edited_plan.rules[0].max_per_call, "15");
    assert_eq!(edited_plan.rules[0].max_per_day, "30");

    assert!(controller.sign("AUTHORISE").is_err());
    let result = controller.sign("AUTHORIZE").unwrap();
    assert!(result.tx_hash.starts_with("0x") && result.tx_hash.len() == 66, "{}", result.tx_hash);
    assert!(result.reported, "the website was told: {}", result.report_message);
    assert!(controller.key_status().is_none(), "the key is wiped after signing");

    let state = fake.control("GET", "/__state");
    let sent = state["sent"].as_array().unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["sender"].as_str().unwrap(), fake.config["owner"].as_str().unwrap().to_lowercase());
    assert_eq!(state["reports"][0][0].as_str().unwrap(), token);
    assert_eq!(state["customized"].as_array().unwrap().len(), 2);
}

#[test]
fn grants_list_revoke_one_then_all() {
    let fake = fake_or_skip!();
    let controller = fake.controller();
    controller.open_link(&format!("anubisauto://grants?api={}", fake.api())).unwrap();
    controller.load_key(fake.key()).unwrap();
    let listing = controller.grants_load().unwrap();
    assert_eq!(listing.owner, fake.config["owner"].as_str().unwrap().to_lowercase());
    assert_eq!(listing.rows.len(), 4);
    let active: Vec<_> = listing.rows.iter().filter(|row| row.active).map(|row| row.grant_id.clone()).collect();
    assert_eq!(active.len(), 2);

    let pending = controller.grants_prepare(Some(vec![active[0].clone()])).unwrap();
    assert_eq!(pending.count, 1);
    assert!(pending.summaries[0].contains(&active[0][2..10]) || pending.summaries[0].to_lowercase().contains(&active[0][2..10]), "{}", pending.summaries[0]);
    let outcome = controller.grants_confirm("REVOKE").unwrap();
    assert_eq!((outcome.done, outcome.total), (1, 1));
    let row = outcome.listing.rows.iter().find(|row| row.grant_id == active[0]).unwrap();
    assert_eq!(row.status, "revoked");

    // Revoke all: the remaining active grant (the expired one is not "active").
    let pending = controller.grants_prepare(None).unwrap();
    assert_eq!(pending.count, 1);
    let outcome = controller.grants_confirm("REVOKE").unwrap();
    assert_eq!(outcome.done, 1);
    assert!(outcome.listing.rows.iter().all(|row| !row.active));

    let state = fake.control("GET", "/__state");
    assert_eq!(state["confirmations"].as_array().unwrap().len(), 2);
    let owner = fake.config["owner"].as_str().unwrap().to_lowercase();
    let left: Vec<&str> = state["policy"][owner.as_str()].as_array().unwrap().iter().map(|id| id.as_str().unwrap()).collect();
    assert_eq!(left.len(), 1, "only the expired grant stays on chain: {left:?}");
    controller.forget_key();
    assert_eq!(fake.control("GET", "/__state")["loggedOut"], 1);
}

#[test]
fn export_keystore_round_trips() {
    let controller = Controller::new(RealCore::production(), Arc::new(NoEvents));
    let secret = format!("0x{}", "11".repeat(32));
    let input: KeyInput = serde_json::from_value(json!({ "kind": "privateKey", "secret": secret })).unwrap();
    let address = controller.load_key(input).unwrap().address;
    let json = controller.export_keystore("correct horse battery").unwrap();
    let document: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(document["version"], 3);
    assert!(!json.contains(&"11".repeat(32)), "the keystore is encrypted");
    // The page writes it to a file; loading that file gives back the same key.
    controller.forget_key();
    let reload: KeyInput = serde_json::from_value(json!({ "kind": "keystore", "json": json, "password": "correct horse battery" })).unwrap();
    assert_eq!(controller.load_key(reload).unwrap().address, address);
    let wrong: KeyInput = serde_json::from_value(json!({ "kind": "keystore", "json": json, "password": "wrong password" })).unwrap();
    controller.forget_key();
    assert_eq!(controller.load_key(wrong).unwrap_err().kind, "refused");
}

#[test]
fn foreign_website_is_refused_in_production() {
    let core = RealCore::production();
    let controller = Controller::new(core, Arc::new(NoEvents));
    for scheme in ["anubisauto", "awakehelix"] {
        let error = controller.open_link(&format!("{scheme}://sign?plan={}&api=https://evil.example", "A".repeat(32))).unwrap_err();
        assert!(error.message.contains("not the official Anubis Automation website"), "{}", error.message);
        let error = controller.open_link(&format!("{scheme}://sign?plan={}&api=http://127.0.0.1:9", "A".repeat(32))).unwrap_err();
        assert_eq!(error.kind, "refused");
        // The legacy scheme of the signers before 0.7.0 opens the same request.
        let ok = controller.open_link(&format!("{scheme}://sign?plan={}", "A".repeat(32))).unwrap();
        assert!(ok.official);
        assert_eq!(ok.action, "sign");
    }
    for other in ["anubisautox", "awake-helix", "anubis"] {
        let error = controller.open_link(&format!("{other}://sign?plan={}", "A".repeat(32))).unwrap_err();
        assert!(error.message.contains("Not an anubisauto:// link."), "{other}: {}", error.message);
    }
}
