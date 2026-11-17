//! ``awake-helix-signer``: sign | revoke | grants | ping | open | serve |
//! keystore | register | unregister | install-cli | uninstall-cli | status | gui.
//!
//! The same commands, options, prompts, messages and exit codes as the Python
//! signer's command line (0 success, 1 cancelled, 2 refused or failed).

mod console;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::{ArgGroup, Args, CommandFactory, Parser, Subcommand};
use helix_signer_core::companion::{self, CompanionConfig, KeyHolder, Pairings};
use helix_signer_core::custom::{self, CustomizeRequest};
use helix_signer_core::flow::{self, Confirmer, RevokeSource, Session};
use helix_signer_core::keys::{is_password_error, Kdf, KeySource, KeyMaterial};
use helix_signer_core::register::{self, UrlSchemeRegistrar};
use helix_signer_core::{
    constants as c, integrate, net, plan::amount, summary::when, Error, ErrorKind, GrantKind, LinkAction, Listing, Result,
    Transport, Website,
};
use serde_json::Value;

use console::Console;

const PASSWORD_ATTEMPTS: usize = 3;
const EDIT_WORD: &str = "EDIT";
const SCAN_POLLS: usize = 20;
const SCAN_POLL_SECONDS: u64 = 3;
/// Reads of the list while the website refreshes its cached copy from the chain.
const REFRESH_POLLS: usize = 5;
const REFRESH_POLL_SECONDS: u64 = 3;

#[derive(Parser, Debug)]
#[command(
    name = "awake-helix-signer",
    version,
    about = "Verify an Awake Helix hosted-bot plan against constants compiled into this program, sign it with your key on this computer and broadcast it to Anubis Chain 6714. Your key never leaves this computer."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args, Debug, Clone, Default)]
#[command(group(ArgGroup::new("source").args(["keystore", "private_key", "mnemonic"]).multiple(false)))]
struct KeyOptions {
    /// Encrypted keystore JSON (recommended).
    #[arg(long, value_name = "FILE")]
    keystore: Option<PathBuf>,
    /// Type the private key at a hidden prompt.
    #[arg(long)]
    private_key: bool,
    /// Type the mnemonic at a hidden prompt (controls every account of the wallet!).
    #[arg(long)]
    mnemonic: bool,
    /// Mnemonic path m/44'/60'/0'/0/N (default 0).
    #[arg(long, value_name = "N", default_value_t = 0, allow_negative_numbers = true, hide_default_value = true)]
    account_index: i64,
    /// Also ask for a BIP-39 passphrase.
    #[arg(long)]
    mnemonic_passphrase: bool,
    /// Anubis RPC (default https://rpc.anubispace.org).
    #[arg(long, value_name = "URL", default_value = c::DEFAULT_RPC, hide_default_value = true)]
    rpc: String,
    /// Developer/test override of the pinned delegate and session key; refused unless --rpc is loopback.
    #[arg(long, value_name = "FILE")]
    dev_constants: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Authorize a hosted bot (EIP-7702 delegation + grant).
    Sign {
        /// One-time plan token from the dashboard.
        #[arg(long, value_name = "TOKEN")]
        plan: String,
        /// Website API (default https://anubis.sivilization.com).
        #[arg(long, value_name = "URL", default_value = c::DEFAULT_API, hide_default_value = true)]
        api: String,
        /// New expiry: "YYYY-MM-DD HH:MM [zone]" (default: local time), ISO 8601, Unix seconds, or a length like 30d.
        #[arg(long, value_name = "WHEN")]
        expires: Option<String>,
        /// New total number of bot operations the grant allows.
        #[arg(long, value_name = "N")]
        calls: Option<String>,
        /// New caps of one rule (its number in the summary, or its method name), e.g. 1=15,40. Repeatable.
        #[arg(long, value_name = "RULE=PER_CALL,PER_DAY")]
        cap: Vec<String>,
        #[command(flatten)]
        key: KeyOptions,
    },
    /// Revoke a hosted-bot grant (self-call from the owner).
    Revoke {
        /// One-time revoke token from the dashboard.
        #[arg(long, value_name = "TOKEN")]
        plan: Option<String>,
        /// Website API (default https://anubis.sivilization.com).
        #[arg(long, value_name = "URL", default_value = c::DEFAULT_API, hide_default_value = true)]
        api: String,
        /// Grant ID to revoke without the website.
        #[arg(long, value_name = "ID")]
        grant: Option<String>,
        /// Owner address (with --grant).
        #[arg(long, value_name = "ADDRESS")]
        owner: Option<String>,
        /// Grant kind (detected on chain by default).
        #[arg(long, value_parser = ["policy", "session"])]
        kind: Option<String>,
        #[command(flatten)]
        key: KeyOptions,
    },
    /// List and revoke every grant on your account (signs in to the website with a signature).
    Grants {
        #[command(subcommand)]
        command: GrantsCommand,
    },
    /// Answer the website's install check (its “I have installed it, verify” button).
    Ping {
        /// Install-check token from the website.
        #[arg(long, value_name = "TOKEN")]
        token: String,
        /// Website API (default https://anubis.sivilization.com).
        #[arg(long, value_name = "URL", default_value = c::DEFAULT_API, hide_default_value = true)]
        api: String,
    },
    /// Handle an awakehelix:// link in the terminal.
    Open {
        /// awakehelix://sign?plan=..., awakehelix://revoke?plan=..., awakehelix://grants or awakehelix://ping?token=...
        link: String,
        /// Also trust this website origin.
        #[arg(long, value_name = "ORIGIN")]
        allow_api: Vec<String>,
        #[command(flatten)]
        key: KeyOptions,
    },
    /// Create an encrypted keystore file from a private key.
    Keystore {
        #[command(subcommand)]
        command: KeystoreCommand,
    },
    /// Run a loopback companion the dashboard can send plans to (confirmed in this terminal).
    Serve {
        /// Loopback port (default 17702).
        #[arg(long, default_value_t = 17702, hide_default_value = true)]
        port: i64,
        /// Sign revocations without typing REVOKE (they only remove permissions). Authorizations always need AUTHORIZE.
        #[arg(long)]
        auto_confirm_revoke: bool,
        /// Also accept this loopback website origin (development and tests only).
        #[arg(long, value_name = "ORIGIN")]
        allow_origin: Vec<String>,
        /// Website API (default https://anubis.sivilization.com).
        #[arg(long, value_name = "URL", default_value = c::DEFAULT_API, hide_default_value = true)]
        api: String,
        /// Wipe the key after this idle time (default 900).
        #[arg(long, value_name = "SECONDS", default_value_t = 900, allow_negative_numbers = true, hide_default_value = true)]
        idle_timeout: i64,
        /// Where paired browsers are stored (default: the signer config directory).
        #[arg(long, value_name = "FILE")]
        pairing_file: Option<PathBuf>,
        #[command(flatten)]
        key: KeyOptions,
    },
    /// Register the desktop handler for awakehelix:// links.
    Register,
    /// Remove the awakehelix:// registration.
    Unregister,
    /// macOS/Linux app: add an awake-helix-signer command symlink (default ~/.local/bin).
    InstallCli {
        /// Directory for the symlink.
        #[arg(long, value_name = "DIR")]
        dir: Option<PathBuf>,
    },
    /// Remove the awake-helix-signer command symlink.
    UninstallCli,
    /// Show the version, the awakehelix:// handler and the command symlink.
    Status,
    /// Open the desktop window (the Awake Helix Signer app).
    Gui {
        /// Optional awakehelix:// link.
        link: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum GrantsCommand {
    /// List every grant with its status, key, bot, expiry and calls.
    List {
        /// Website API (default https://anubis.sivilization.com).
        #[arg(long, value_name = "URL", default_value = c::DEFAULT_API, hide_default_value = true)]
        api: String,
        #[command(flatten)]
        key: KeyOptions,
    },
    /// Revoke one grant, or every active grant one after another.
    #[command(group(ArgGroup::new("which").args(["grant", "all"]).required(true).multiple(false)))]
    Revoke {
        /// The grant ID to revoke.
        #[arg(long, value_name = "ID")]
        grant: Option<String>,
        /// Revoke every active grant.
        #[arg(long)]
        all: bool,
        /// Website API (default https://anubis.sivilization.com).
        #[arg(long, value_name = "URL", default_value = c::DEFAULT_API, hide_default_value = true)]
        api: String,
        #[command(flatten)]
        key: KeyOptions,
    },
}

#[derive(Subcommand, Debug)]
enum KeystoreCommand {
    /// Encrypt a private key (typed hidden) into a keystore JSON.
    Create {
        /// New keystore file.
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
    },
}

/// ``~`` expansion (``Path.expanduser``).
fn expand_user(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if text == "~" || text.starts_with("~/") || text.starts_with("~\\") {
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            return PathBuf::from(home).join(text.get(2..).unwrap_or(""));
        }
    }
    path.to_path_buf()
}

fn source(options: &KeyOptions, console: &Console) -> Result<Option<KeySource>> {
    if let Some(path) = &options.keystore {
        return Ok(Some(KeySource::Keystore(path.clone())));
    }
    if options.private_key {
        return Ok(Some(KeySource::PrivateKey));
    }
    let mnemonic = KeySource::Mnemonic { index: options.account_index, passphrase: options.mnemonic_passphrase };
    if options.mnemonic {
        return Ok(Some(mnemonic));
    }
    console.out("Key source: [1] keystore file (recommended)  [2] private key  [3] mnemonic");
    let choice = console.ask("Choose 1, 2 or 3: ")?;
    Ok(match choice.trim() {
        "1" => Some(KeySource::Keystore(expand_user(Path::new(console.ask("Keystore file path: ")?.trim())))),
        "2" => Some(KeySource::PrivateKey),
        "3" => Some(mnemonic),
        _ => None,
    })
}

/// Load the owner key, retrying a wrong keystore password.
fn load(options: &KeyOptions, console: &Console) -> Result<KeyMaterial> {
    let Some(chosen) = source(options, console)? else { return Err(Error::key("No key source chosen.")) };
    for attempt in 0..PASSWORD_ATTEMPTS {
        match helix_signer_core::load_key(&chosen, console) {
            Ok(material) => {
                let path = if material.path().is_empty() { String::new() } else { format!(" ({})", material.path()) };
                console.out(&format!("Key loaded from {}: {}{path}", material.source(), material.address()));
                return Ok(material);
            }
            Err(error) => {
                if !matches!(chosen, KeySource::Keystore(_)) || !is_password_error(&error) || attempt + 1 == PASSWORD_ATTEMPTS {
                    return Err(error);
                }
                console.out(error.message());
            }
        }
    }
    Err(Error::key("No key loaded."))
}

fn banner(console: &Console, session: &Session) {
    console.out("");
    console.out(&"=".repeat(72));
    console.out(&session.summary_text());
    console.out(&"=".repeat(72));
}

fn confirm(session: &Session, console: &Console) -> Result<bool> {
    banner(console, session);
    let word = session.confirm_word();
    let answer = console.ask(&format!("Type {word} to sign and broadcast, anything else to cancel: "))?;
    Ok(answer.trim() == word)
}

fn bound_text(bound: Option<&Value>, unit: &str) -> String {
    let Some(Value::Object(bound)) = bound else { return String::new() };
    match (bound.get("min"), bound.get("max")) {
        (Some(min), Some(max)) if !min.is_null() && !max.is_null() => {
            format!("; allowed {} to {}{unit}", helix_signer_core::pyfmt::py_str(min), helix_signer_core::pyfmt::py_str(max))
        }
        _ => String::new(),
    }
}

fn int_value(value: Option<&Value>) -> Option<u64> {
    match value {
        Some(Value::Number(number)) if number.is_u64() => number.as_u64(),
        Some(Value::Bool(flag)) => Some(*flag as u64),
        _ => None,
    }
}

/// Ask for new values, field by field; Enter keeps a value.
fn edit_request(session: &Session, console: &Console) -> Result<CustomizeRequest> {
    let plan = session.grant().ok_or_else(|| Error::flow("Only a website grant plan can be edited."))?;
    let bounds = plan.plan.get("bounds").and_then(Value::as_object).cloned().unwrap_or_default();
    let limit = bounds.get("validUntil").and_then(Value::as_object).cloned().unwrap_or_default();
    let allowed = match (int_value(limit.get("min")), int_value(limit.get("max"))) {
        (Some(min), Some(max)) => format!("; allowed {} to {}", when(min), when(max)),
        _ => String::new(),
    };
    console.out("Press Enter to keep a value.");
    let typed = console.ask(&format!(
        "Expiry [{}{allowed}]\n  (YYYY-MM-DD HH:MM [zone], or a length like 30d): ",
        when(plan.valid_until)
    ))?;
    let typed = typed.trim();
    let expires = if typed.is_empty() { None } else { Some(custom::parse_expiry(typed, None)?) };
    let typed = console.ask(&format!("Calls [{}{}]: ", plan.remaining_calls, bound_text(bounds.get("remainingCalls"), "")))?;
    let typed = typed.trim();
    let calls = if typed.is_empty() { None } else { Some(custom::parse_calls(typed)?) };
    let rule_bounds = bounds.get("rules").and_then(Value::as_array).cloned().unwrap_or_default();
    let mut caps = Vec::new();
    for (index, rule) in plan.rules.iter().enumerate() {
        let (unit, decimals) = rule.unit();
        let bound = rule_bounds.get(index).and_then(Value::as_object).cloned().unwrap_or_default();
        console.out(&format!("Rule {}: {}", index + 1, rule.method()));
        let per_call = console.ask(&format!(
            "  per call [{} {unit}{}]: ",
            amount(&rule.max_amount, decimals),
            bound_text(bound.get("maxPerCall"), "")
        ))?;
        let per_day = console.ask(&format!(
            "  per UTC day [{} {unit}{}]: ",
            amount(&rule.max_daily, decimals),
            bound_text(bound.get("maxPerDay"), "")
        ))?;
        let (per_call, per_day) = (per_call.trim().to_string(), per_day.trim().to_string());
        if !per_call.is_empty() || !per_day.is_empty() {
            caps.push((index, (!per_call.is_empty()).then_some(per_call), (!per_day.is_empty()).then_some(per_day)));
        }
    }
    custom::with_changes(plan, expires, calls, &caps)
}

/// Show a grant's summary; sign, edit its limits, or cancel (None).
fn confirm_or_edit(mut session: Session, console: &Console) -> Result<Option<Session>> {
    loop {
        banner(console, &session);
        let word = session.confirm_word();
        let answer =
            console.ask(&format!("Type {word} to sign and broadcast, {EDIT_WORD} to change the limits, anything else to cancel: "))?;
        let answer = answer.trim();
        if answer == word {
            return Ok(Some(session));
        }
        if answer.to_uppercase() != EDIT_WORD {
            return Ok(None);
        }
        match edit_request(&session, console).and_then(|request| flow::customize(&session, &request, &|line: &helix_signer_core::Message| console.out(&line.text))) {
            Ok(next) => session = next,
            Err(error) if matches!(error.kind(), ErrorKind::CustomizeRefused | ErrorKind::Plan) => {
                console.out(&format!("Not changed: {error}"))
            }
            Err(error) => return Err(error),
        }
    }
}

struct SignArgs<'a> {
    plan: &'a str,
    api: &'a str,
    expires: Option<&'a str>,
    calls: Option<&'a str>,
    cap: &'a [String],
    key: &'a KeyOptions,
}

fn flag_changes(args: &SignArgs, session: &Session) -> Result<Option<CustomizeRequest>> {
    if args.expires.is_none() && args.calls.is_none() && args.cap.is_empty() {
        return Ok(None);
    }
    let plan = session.grant().ok_or_else(|| Error::flow("Only a website grant plan can be edited."))?;
    let expires = args.expires.map(|text| custom::parse_expiry(text, None)).transpose()?;
    let calls = args.calls.map(custom::parse_calls).transpose()?;
    let caps = args.cap.iter().map(|item| custom::parse_cap(item, &plan.rules)).collect::<Result<Vec<_>>>()?;
    custom::with_changes(plan, expires, calls, &caps).map(Some)
}

fn run_sign(args: SignArgs, console: &Console, transport: &Transport) -> Result<u8> {
    let constants = flow::load_constants(args.key.dev_constants.as_deref(), &args.key.rpc)?;
    let mut material = load(args.key, console)?;
    let log = |line: &helix_signer_core::Message| console.out(&line.text);
    let result = (|| -> Result<Option<flow::Outcome>> {
        let mut session = flow::prepare_sign(args.plan, args.api, &args.key.rpc, &constants, Some(&material), transport, &log)?;
        if let Some(request) = flag_changes(&args, &session)? {
            // A refused value stops here: signing other limits than were asked is never right.
            session = flow::customize(&session, &request, &log)?;
        }
        let Some(session) = confirm_or_edit(session, console)? else { return Ok(None) };
        flow::execute_sign(&session, material.clone(), &log).map(Some)
    })();
    material.wipe();
    let Some(outcome) = result? else {
        console.out("Cancelled; nothing was signed.");
        return Ok(1);
    };
    console.out(&format!("Done. Transaction {} (type {}, block {}).", outcome.tx_hash, outcome.tx_type, outcome.block));
    console.out(if outcome.reported {
        "The website was notified; the dashboard continues automatically."
    } else {
        "The dashboard detects the transaction on chain and continues; keep it open."
    });
    Ok(0)
}

struct RevokeArgs<'a> {
    plan: Option<&'a str>,
    api: &'a str,
    grant: Option<&'a str>,
    owner: Option<&'a str>,
    kind: Option<&'a str>,
    key: &'a KeyOptions,
}

fn run_revoke(args: RevokeArgs, console: &Console, transport: &Transport) -> Result<u8> {
    if args.plan.is_none() && (args.grant.is_none() || args.owner.is_none()) {
        return Err(Error::flow("Pass --plan TOKEN, or --grant ID and --owner ADDRESS."));
    }
    let constants = flow::load_constants(args.key.dev_constants.as_deref(), &args.key.rpc)?;
    let mut material = load(args.key, console)?;
    let log = |line: &helix_signer_core::Message| console.out(&line.text);
    let source = match args.plan {
        Some(token) => RevokeSource::Plan { token: token.to_string(), api: args.api.to_string() },
        None => RevokeSource::Offline {
            owner: args.owner.unwrap_or_default().to_string(),
            grant_id: args.grant.unwrap_or_default().to_string(),
            kind: args.kind.and_then(GrantKind::parse),
        },
    };
    let result = (|| -> Result<Option<flow::Outcome>> {
        let session = flow::prepare_revoke(&args.key.rpc, &constants, source, Some(&material), transport, &log)?;
        if !confirm(&session, console)? {
            return Ok(None);
        }
        flow::execute_revoke(&session, material.clone(), &log).map(Some)
    })();
    material.wipe();
    let Some(outcome) = result? else {
        console.out("Cancelled; nothing was signed.");
        return Ok(1);
    };
    console.out(&format!("Done. Grant revoked in transaction {} (block {}).", outcome.tx_hash, outcome.block));
    Ok(0)
}

fn print_listing(listing: &Listing, console: &Console) {
    if listing.rows.is_empty() {
        console.out(&format!("No grants on {}.", listing.owner));
    }
    for row in &listing.rows {
        console.out(&row.describe());
    }
    if !listing.scan_complete {
        console.out(&format!(
            "The website is still scanning the install history ({}%); run this again for older grants.",
            listing.scan_percent
        ));
    }
    if listing.truncated {
        console.out("Only the newest 100 grants are listed.");
    }
    if listing.refreshing {
        console.out("The website is still updating these statuses from the chain; they may be a few seconds old. Run this again in a moment.");
    }
}

fn full_listing(site: &Website, console: &Console) -> Result<Listing> {
    poll_listing(&mut || site.grants(), &mut |line| console.out(line), &mut |seconds| std::thread::sleep(Duration::from_secs(seconds)))
}

/// Read the list again while the website scans the install history (up to
/// `SCAN_POLLS` times) or answers from its cached copy while it refreshes
/// the statuses from the chain (up to `REFRESH_POLLS` times).
fn poll_listing(fetch: &mut dyn FnMut() -> Result<Listing>, out: &mut dyn FnMut(&str), sleep: &mut dyn FnMut(u64)) -> Result<Listing> {
    let mut listing = fetch()?;
    let (mut scans, mut refreshes) = (0, 0);
    loop {
        if !listing.scan_complete && scans < SCAN_POLLS {
            scans += 1;
            out(&format!("The website is scanning the install history ({}%) ...", listing.scan_percent));
            sleep(SCAN_POLL_SECONDS);
        } else if listing.scan_complete && listing.refreshing && refreshes < REFRESH_POLLS {
            refreshes += 1;
            out("The website is updating the grant statuses from the chain ...");
            sleep(REFRESH_POLL_SECONDS);
        } else {
            return Ok(listing);
        }
        listing = fetch()?;
    }
}

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

fn run_grants(list: bool, grant: Option<&str>, all: bool, api: &str, key: &KeyOptions, console: &Console, transport: &Transport) -> Result<u8> {
    let constants = flow::load_constants(key.dev_constants.as_deref(), &key.rpc)?;
    let site = Website::new(api, transport.website.clone()).map_err(|error| error.into_kind(ErrorKind::Flow))?;
    if api.trim_end_matches('/') != c::DEFAULT_API {
        console.out(&format!("Website: {api}   <-- NOT the official site; continue only if you trust it"));
    }
    let mut material = load(key, console)?;
    let log = |line: &helix_signer_core::Message| console.out(&line.text);
    let result = (|| -> Result<u8> {
        site.login(&material, &log)?;
        if list {
            print_listing(&full_listing(&site, console)?, console);
            return Ok(0);
        }
        let listing = full_listing(&site, console)?;
        print_listing(&listing, console);
        let targets: Vec<String> = if all {
            listing.active().iter().map(|row| row.grant_id.clone()).collect()
        } else {
            vec![grant.unwrap_or_default().trim().to_lowercase()]
        };
        if targets.is_empty() {
            console.out("There are no active grants to revoke.");
            return Ok(0);
        }
        let mut sessions = Vec::new();
        for grant_id in &targets {
            if let Some(session) = flow::prepare_grant_revoke(&site, grant_id, &key.rpc, &constants, &material, transport, &log)? {
                console.out(&"=".repeat(72));
                console.out(&session.summary_text());
                sessions.push(session);
            }
        }
        console.out(&"=".repeat(72));
        if sessions.is_empty() {
            console.out("Nothing to revoke: the chain shows these grants are already gone.");
            return Ok(0);
        }
        let answer = console.ask(&format!(
            "Type REVOKE to sign and broadcast {} revocation(s), anything else to cancel: ",
            sessions.len()
        ))?;
        if answer.trim() != "REVOKE" {
            console.out("Cancelled; nothing was signed.");
            return Ok(1);
        }
        let mut done = 0;
        for (index, session) in sessions.iter().enumerate() {
            if INTERRUPTED.load(Ordering::SeqCst) {
                console.out(&format!("\nStopped after {done} of {}; the others were not touched.", sessions.len()));
                return Ok(1);
            }
            console.out(&format!("Revoking {} of {}: {}", index + 1, sessions.len(), session.plan.grant_id()));
            let outcome = flow::execute_grant_revoke(session, &material, &site, &log)?;
            done = index + 1;
            console.out(&format!("Done. Grant revoked in transaction {} (block {}).", outcome.tx_hash, outcome.block));
            if !outcome.stopped_bots.is_empty() {
                let names: Vec<String> = outcome.stopped_bots.iter().map(helix_signer_core::pyfmt::py_str).collect();
                console.out(&format!("The website stopped bot(s): {}.", names.join(", ")));
            }
        }
        console.out(&format!("Revoked {done} of {} grant(s).", sessions.len()));
        Ok(0)
    })()
    .map_err(|error| match error.kind() {
        ErrorKind::Login | ErrorKind::Network | ErrorKind::HttpStatus => error.into_kind(ErrorKind::Flow),
        _ => error,
    });
    site.logout();
    material.wipe();
    result
}

fn run_ping(api: &str, token: &str, console: &Console, transport: &Transport) -> u8 {
    match helix_signer_core::send_ping(api, token, transport.website.as_ref()) {
        Ok(result) => {
            console.out(&result.message());
            0
        }
        Err(error) => {
            console.out(&format!("Refused: {error}"));
            2
        }
    }
}

fn run_open(link: &str, allow_api: &[String], key: &KeyOptions, console: &Console, transport: &Transport) -> Result<u8> {
    let link = helix_signer_core::parse_link(link, allow_api, key.dev_constants.is_some())?;
    match link.action {
        LinkAction::Ping => Ok(run_ping(&link.api, &link.token, console, transport)),
        LinkAction::Grants => run_grants(true, None, false, &link.api, key, console, transport),
        LinkAction::Sign => run_sign(SignArgs { plan: &link.token, api: &link.api, expires: None, calls: None, cap: &[], key }, console, transport),
        LinkAction::Revoke => run_revoke(
            RevokeArgs { plan: Some(&link.token), api: &link.api, grant: None, owner: None, kind: None, key },
            console,
            transport,
        ),
    }
}

/// Types the confirmation word in the terminal for the companion.
struct TerminalConfirmer {
    console: Console,
}

impl Confirmer for TerminalConfirmer {
    fn confirm(&self, _session: &Session, word: &str) -> Result<bool> {
        let answer = self.console.ask(&format!("Type {word} to sign and broadcast, anything else to cancel: "))?;
        Ok(answer.trim() == word)
    }
}

#[allow(clippy::too_many_arguments)]
fn run_serve(
    port: i64,
    auto_confirm_revoke: bool,
    allow_origin: &[String],
    api: &str,
    idle_timeout: i64,
    pairing_file: Option<&Path>,
    key: &KeyOptions,
    console: &Console,
    transport: &Transport,
) -> Result<u8> {
    let constants = flow::load_constants(key.dev_constants.as_deref(), &key.rpc)?;
    if !(1024..=65535).contains(&port) {
        return Err(Error::flow("--port must be between 1024 and 65535."));
    }
    if idle_timeout < 30 {
        return Err(Error::flow("--idle-timeout must be at least 30 seconds."));
    }
    let api = net::validate_url(api, "Website API").map_err(|error| error.into_kind(ErrorKind::Flow))?;
    let loader_console = *console;
    let loader_key = key.clone();
    let holder = KeyHolder::new(Box::new(move || load(&loader_key, &loader_console)), Duration::from_secs(idle_timeout as u64), None);
    holder.unlock()?;
    let pairings = Pairings::load(Some(pairing_file.map(Path::to_path_buf).unwrap_or_else(|| integrate::config_dir().join("pairings.json"))));
    let out_console = *console;
    let config = CompanionConfig {
        api,
        rpc_url: key.rpc.clone(),
        constants,
        origins: allow_origin.to_vec(),
        auto_confirm_revoke,
        port: port as u16,
        transport: transport.clone(),
    };
    let confirmer = Arc::new(TerminalConfirmer { console: *console });
    let companion = companion::Companion::new(config, holder, pairings, Arc::new(move |line: &str| out_console.out(line)), confirmer)?;
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let _ = ctrlc::set_handler(move || flag.store(true, Ordering::SeqCst));
    let result = companion::serve(companion.clone(), stop);
    companion.keys().wipe();
    result.map(|_| 0)
}

fn run_keystore(out: &Path, console: &Console) -> Result<u8> {
    console.out("The private key is read with hidden input; the keystore is encrypted with your password.");
    let mut material = KeyMaterial::from_private_key(&helix_signer_core::Prompter::secret(console, "Private key (hidden): ")?)?;
    let result = (|| -> Result<PathBuf> {
        let password = helix_signer_core::Prompter::secret(console, "New keystore password (hidden, 8+ characters): ")?;
        if *helix_signer_core::Prompter::secret(console, "Repeat the password: ")? != *password {
            return Err(Error::key("The passwords differ; nothing was written."));
        }
        helix_signer_core::create_keystore(&material, &password, &expand_user(out), Kdf::Scrypt, None)
    })();
    let address = material.address();
    material.wipe();
    let path = result?;
    console.out(&format!("Wrote encrypted keystore for {address} to {}.", path.display()));
    console.out("Keep the file and the password apart; use it with --keystore.");
    Ok(0)
}

/// The Awake Helix Signer app next to this program, if installed there.
fn app_next_to_cli() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?.canonicalize().ok()?;
    let dir = exe.parent()?;
    let names: &[&str] = if cfg!(windows) {
        &["AwakeHelixSigner.exe", "awake-helix-signer-app.exe"]
    } else {
        &["awake-helix-signer-app", "Awake Helix Signer"]
    };
    names.iter().map(|name| dir.join(name)).find(|path| path.is_file())
}

/// The handler of awakehelix:// links: the app when it is installed next to
/// this program, else this program's ``open`` in a terminal.
fn handler() -> (Vec<String>, bool) {
    match app_next_to_cli() {
        Some(app) => (vec![app.display().to_string()], false),
        None => (vec![register::program().display().to_string(), "open".to_string()], true),
    }
}

fn registrar() -> Box<dyn UrlSchemeRegistrar> {
    let (command, terminal) = handler();
    register::for_this_os(command, terminal)
}

fn run(cli: Cli, console: &Console, transport: &Transport) -> Result<u8> {
    match cli.command {
        Command::Sign { plan, api, expires, calls, cap, key } => run_sign(
            SignArgs { plan: &plan, api: &api, expires: expires.as_deref(), calls: calls.as_deref(), cap: &cap, key: &key },
            console,
            transport,
        ),
        Command::Revoke { plan, api, grant, owner, kind, key } => run_revoke(
            RevokeArgs { plan: plan.as_deref(), api: &api, grant: grant.as_deref(), owner: owner.as_deref(), kind: kind.as_deref(), key: &key },
            console,
            transport,
        ),
        Command::Grants { command: GrantsCommand::List { api, key } } => run_grants(true, None, false, &api, &key, console, transport),
        Command::Grants { command: GrantsCommand::Revoke { grant, all, api, key } } => {
            let _ = ctrlc::set_handler(|| INTERRUPTED.store(true, Ordering::SeqCst));
            run_grants(false, grant.as_deref(), all, &api, &key, console, transport)
        }
        Command::Ping { token, api } => Ok(run_ping(&api, &token, console, transport)),
        Command::Open { link, allow_api, key } => run_open(&link, &allow_api, &key, console, transport),
        Command::Keystore { command: KeystoreCommand::Create { out } } => run_keystore(&out, console),
        Command::Serve { port, auto_confirm_revoke, allow_origin, api, idle_timeout, pairing_file, key } => run_serve(
            port,
            auto_confirm_revoke,
            &allow_origin,
            &api,
            idle_timeout,
            pairing_file.as_deref(),
            &key,
            console,
            transport,
        ),
        Command::Register => {
            console.out(&registrar().register()?);
            Ok(0)
        }
        Command::Unregister => {
            console.out(&registrar().unregister()?);
            Ok(0)
        }
        Command::InstallCli { dir } => {
            console.out(&integrate::install_cli(dir.as_deref(), None, &register::program())?);
            Ok(0)
        }
        Command::UninstallCli => {
            console.out(&integrate::uninstall_cli(&register::program(), None));
            Ok(0)
        }
        Command::Status => {
            let program = register::program();
            console.out(&format!("awake-helix-signer {}", helix_signer_core::VERSION));
            console.out(&format!("program: {}", program.display()));
            console.out(&format!("awakehelix:// handler: {}", registrar().registration().unwrap_or_else(|| "not registered".into())));
            let link = integrate::cli_link(&program, None).map(|link| link.display().to_string());
            console.out(&format!("terminal command: {}", link.unwrap_or_else(|| "no symlink (installer PATH or pip install)".into())));
            Ok(0)
        }
        Command::Gui { link } => match app_next_to_cli() {
            Some(app) => {
                let mut command = std::process::Command::new(app);
                command.args(link);
                command.spawn().map_err(|error| Error::io(error.to_string()))?;
                Ok(0)
            }
            None => {
                console.out("The signer window cannot open here (the Awake Helix Signer app is not installed next to this program). Use the terminal instead, e.g. awake-helix-signer sign --plan <token> (awake-helix-signer --help lists every command).");
                Ok(2)
            }
        },
    }
}

/// Window-style arguments of the Python entry point: a bare link opens it in
/// the terminal, ``--register``/``--unregister`` register, ``--selftest`` checks.
fn rewrite(args: Vec<String>) -> Vec<String> {
    let mut args: Vec<String> = args.into_iter().enumerate().filter(|(index, arg)| *index == 0 || !arg.starts_with("-psn_")).map(|(_, arg)| arg).collect();
    if let Some(first) = args.get(1).cloned() {
        if first.to_lowercase().starts_with("awakehelix:") {
            args.insert(1, "open".into());
        } else if first == "--register" && args.len() == 2 {
            args[1] = "register".into();
        } else if first == "--unregister" && args.len() == 2 {
            args[1] = "unregister".into();
        }
    }
    args
}

fn selftest(console: &Console) -> u8 {
    let constants = helix_signer_core::production();
    let words = helix_signer_core::keys::bip39::LANGUAGES.iter().all(|(name, _)| helix_signer_core::keys::bip39::wordlist(name).len() == 2048);
    let key = KeyMaterial::from_mnemonic("test test test test test test test test test test test junk", 0, "")
        .map(|material| material.address().to_checksum())
        .unwrap_or_default();
    let ok = words && key == "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
    console.out(&format!(
        "awake-helix-signer {} selftest {}: chain {}, delegate {}, attestation {}, constants {}",
        helix_signer_core::VERSION,
        if ok { "ok" } else { "FAILED" },
        constants.chain_id,
        constants.implementation,
        constants.attestation_address,
        companion::constants_hash(&constants)
    ));
    if ok {
        0
    } else {
        2
    }
}

fn main() -> ExitCode {
    let args = rewrite(std::env::args().collect());
    let console = Console::terminal();
    if args.len() == 1 {
        let _ = Cli::command().print_help();
        println!();
        return ExitCode::from(2);
    }
    if args.len() == 2 && args[1] == "--selftest" {
        return ExitCode::from(selftest(&console));
    }
    let cli = match Cli::try_parse_from(&args) {
        Ok(cli) => cli,
        Err(error) => error.exit(),
    };
    let transport = Transport::system();
    let status = match run(cli, &console, &transport) {
        Ok(status) => status,
        Err(error) => match error.kind() {
            ErrorKind::Io => {
                console.out(&format!("Failed: {error}"));
                2
            }
            ErrorKind::Cancelled => {
                console.out("\nCancelled; nothing was signed.");
                1
            }
            _ => {
                console.out(&format!("Refused: {error}"));
                2
            }
        },
    };
    ExitCode::from(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listing(scan_complete: bool, refreshing: bool) -> Listing {
        Listing {
            owner: String::new(),
            rows: Vec::new(),
            scan_complete,
            scan_percent: if scan_complete { 100 } else { 40 },
            truncated: false,
            delegation: serde_json::json!({}),
            refreshing,
            generated_at: String::new(),
        }
    }

    fn polls(answers: Vec<Listing>) -> (Listing, usize, Vec<String>, Vec<u64>) {
        let mut queue = answers;
        let mut fetched = 0;
        let mut lines = Vec::new();
        let mut slept = Vec::new();
        let last = poll_listing(
            &mut || {
                fetched += 1;
                Ok(if queue.len() > 1 { queue.remove(0) } else { queue[0].clone() })
            },
            &mut |line| lines.push(line.to_string()),
            &mut |seconds| slept.push(seconds),
        )
        .unwrap();
        (last, fetched, lines, slept)
    }

    #[test]
    fn reads_again_while_the_website_refreshes() {
        // Fresh after two cached answers.
        let (last, fetched, lines, slept) = polls(vec![listing(true, true), listing(true, true), listing(true, false)]);
        assert!(!last.refreshing);
        assert_eq!(fetched, 3);
        assert_eq!(slept, [REFRESH_POLL_SECONDS; 2]);
        assert!(lines.iter().all(|line| line.contains("updating the grant statuses from the chain")));
        // Still cached: at most REFRESH_POLLS more reads, then the cached list.
        let (last, fetched, _, _) = polls(vec![listing(true, true)]);
        assert!(last.refreshing);
        assert_eq!(fetched, 1 + REFRESH_POLLS);
        // Fresh at once: one read.
        assert_eq!(polls(vec![listing(true, false)]).1, 1);
        // Scanning first, then refreshing.
        let (_, fetched, lines, _) = polls(vec![listing(false, true), listing(true, true), listing(true, false)]);
        assert_eq!(fetched, 3);
        assert!(lines[0].contains("scanning") && lines[1].contains("updating"), "{lines:?}");
    }
}
