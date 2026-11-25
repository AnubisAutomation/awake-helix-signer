# helix-signer-core API

The core of the Anubis Automation Script Signer, shared by the `anubisauto-signer` CLI
(`crates/helix-signer-cli`) and the Tauri app (`app/src-tauri`). It is a port
of the former Python signer with the same checks,
messages and wire formats; nothing in it depends on a GUI or a terminal.

* **Blocking API.** Network calls block (ureq + rustls). Call them from a
  worker thread (`tauri::async_runtime::spawn_blocking`, `std::thread`),
  never from the UI thread. Public types that cross threads are `Send + Sync`.
* **One error type.** `Error` with `kind()` (`ErrorKind::{Plan, Key, Flow,
  CustomizeRefused, Chain, Network, HttpStatus, Login, Ping, Io, Cancelled}`,
  serializes kebab-case), `message()` / `Display` = the user-facing English
  text (identical to the Python signer), `status()` and `body()` for HTTP
  errors, `is_network()`, and `msg()`: the same message as a `Message`
  (below). `Result<T> = std::result::Result<T, Error>`.
  The CLI maps `Io` to `Failed: …`, `Cancelled` to exit 1, everything else to
  `Refused: …` exit 2.
* **Secrets** live only in `KeyMaterial` (a `Zeroizing<[u8; 32]>`, zeroed on
  `wipe()` and on drop) and in `Zeroizing<String>` prompt answers. They never
  appear in an error, a `Debug` output or a progress line.
* **Messages have codes.** A `Message { code, params, text, site }` is what
  the user reads: a stable `code` (`flow.wrongKey`, `log.gas`, …), the values
  it names (`params`: a text, or a nested `Message` such as a cause or a
  website answer) and the English `text` the CLI prints. Messages are built
  with `msg!("code", "English {name}", name = value)`. An error without a code
  of its own has its kind as the code (`plan`, `network`, …). A website error
  answer has the code `website` and carries `SiteText { status, code, params,
  zh, en }` (the website's own code and its Chinese and English texts). The
  app translates `core.<code>` / `site.<code>` and falls back to the text.
* **Progress** is a callback `&dyn Fn(&Message)` (`flow::Log`) that receives
  the same lines the Python signer printed as `line.text` ("Fetching plan
  from …", "Plan verified …", "Gas limit 385000 (…); maximum fee … DAI.",
  "Broadcasting type-4 transaction 0x… to … ...", "Waiting for the receipt
  ...", "Confirmed in block N: …"), each with its code. Pass `&|_| {}` to
  ignore them.
* Most structs derive `serde::Serialize` (camelCase) so the app can hand them
  to its web view as JSON: `Summary`, `GrantPlan`, `RevokePlan`, `Rule`,
  `Outcome`, `Listing`, `GrantRow`, `Link`, `PingResult`, `Constants`,
  `AccountState`, `CustomizeRequest` (also `Deserialize`).

Everything below is re-exported at the crate root unless a module path is
shown. Runnable examples of every call are in `tests/flows.rs` and
`tests/companion.rs` (with an in-memory chain and website, `tests/common`).

## Version and constants

```rust
pub const VERSION: &str;                         // "0.7.0"
pub const CHAIN_ID: u64;                         // 6714
pub const DEFAULT_RPC: &str;                     // https://rpc.anubispace.org
pub const DEFAULT_API: &str;                     // https://anubis.sivilization.com
pub fn production() -> Constants;                // pinned values; attestation address from
                                                 // attestation_address.txt at build time
pub struct Constants {                           // Clone, Debug, PartialEq, Serialize
    pub chain_id: u64,
    pub implementation: Address,                 // the version 2 Diamond: every grant installs with it
    pub implementation_code_hash: Option<String>,// lowercase 0x hash; None = not checked (dev only)
    pub implementation_v1: Address,              // the version 1 Diamond (JSON "implementationV1"):
                                                 // revocations in place; a grant moves the wallet to v2
    pub implementation_v1_code_hash: Option<String>, // "implementationV1CodeHash"
    pub entry_point: Address,
    pub attestation_address: Address,
    pub legacy_session_key: Address,
    pub development: bool,                       // true when loaded from --dev-constants
}
impl Constants { pub fn with_overrides(&self, values: &serde_json::Value) -> Result<Constants>; }
pub fn load_constants(dev_file: Option<&Path>, rpc_url: &str) -> Result<Constants>;
        // --dev-constants FILE: refused unless rpc_url is loopback
        // --dev-constants: implementationV1 / implementationV1CodeHash are optional (default: the
        // pinned version 1 Diamond and its hash; named without a hash: not checked)
pub mod constants;   // IMPLEMENTATION (v2), IMPLEMENTATION_V1, RULE_ALLOWLIST, RULE_METHODS (27 kinds:
                     // HELIX 0-9, Origin 10-26), RULE_UNITS, SWAP_KINDS / DEADLINE_KINDS / SECONDARY_KINDS /
                     // COUNTED_KINDS, MAX_* bounds, GrantKind, contract_name(), install_selector(),
                     // revoke_selector(kind), policy_installed_topic(), ...
```

`build.rs` reads `attestation_address.txt` at the repository root (or
`AWAKE_HELIX_ATTESTATION_FILE`) and fails the build unless it holds one
checksummed, non-zero address; with `AWAKE_HELIX_RELEASE=1` it also refuses
the placeholder address (`constants::ATTESTATION_PLACEHOLDER`).

`Address` (20 bytes): `Address::parse(&str)` accepts `0x`/`0X`/no prefix and
any case (like `eth_utils.is_address`), `to_checksum()`/`Display` give EIP-55,
`to_lower()` gives `0x…` lowercase; it serializes as the checksummed string.

## Links (`anubisauto://`)

```rust
pub enum LinkAction { Sign, Revoke, Ping, Grants }   // as_str(); serializes "sign" | ...
pub struct Link { pub action: LinkAction, pub token: String, pub api: String }
pub fn parse_link(url: &str, allowed_apis: &[String], development: bool) -> Result<Link>;
pub mod links { pub const SCHEME: &str;              // "anubisauto": every link made uses it
    pub const LEGACY_SCHEME: &str;                    // "awakehelix" (signers before 0.7.0): accepted, never made
    pub const SCHEMES: [&str; 2];                     // both, the primary one first
    pub fn has_scheme(text: &str) -> bool; }          // starts with one of SCHEMES and ":" (any case)
```

Both schemes parse alike (old links and QR codes still open the app); any
other scheme is refused (`link.notOurs`). The API origin must be the official
site, one in `allowed_apis` (`--allow-api`), or loopback when `development` is
set (dev constants); tokens match `^[A-Za-z0-9_-]{22,128}$`.

## HTTP transport

```rust
pub trait HttpClient: Send + Sync {
    fn send(&self, request: &HttpRequest) -> std::result::Result<HttpResponse, TransportError>;
}
pub struct HttpRequest { pub method: String, pub url: String, pub headers: Vec<(String, String)>,
                         pub body: Option<Vec<u8>>, pub timeout: Duration }
pub struct HttpResponse { pub status: u16, pub headers: Vec<(String, String)>, pub body: Vec<u8> }
pub struct TransportError(pub String);          // "Cannot reach <origin>: <this text>"
pub struct Transport { pub website: Arc<dyn HttpClient>, pub rpc: Arc<dyn HttpClient> }
impl Transport { pub fn system() -> Transport; pub fn single(client: Arc<dyn HttpClient>) -> Transport; }
pub mod net { validate_url, is_loopback, origin, urlsplit, http_json, Rpc, ... }
```

`Transport::system()` (ureq + rustls/ring + bundled webpki roots, gzip off,
no redirects at the transport) is what the CLI and the app use. Plan, report,
customize and ping requests follow redirects like `urllib` did (GET any
3xx, POST only 301–303 as a GET); the logged-in website session never follows
one. Plain HTTP is allowed only for loopback hosts; credentials in URLs are
refused.

## Keys

```rust
pub struct KeyMaterial;                          // Clone = an explicit copy; Debug hides the key
impl KeyMaterial {
    pub fn from_private_key(text: &str) -> Result<KeyMaterial>;               // 64 hex, optional 0x
    pub fn from_keystore(path: &Path, password: &str) -> Result<KeyMaterial>;  // V3, scrypt or pbkdf2
    pub fn from_keystore_json(text: &str, label: &str, password: &str) -> Result<KeyMaterial>;
    pub fn from_mnemonic(phrase: &str, index: i64, passphrase: &str) -> Result<KeyMaterial>;
        // BIP-39 in eth-account's nine languages (english, chinese_simplified, chinese_traditional,
        // czech, french, italian, japanese, korean, spanish), NFKD, m/44'/60'/0'/0/<index>
    pub fn address(&self) -> Address;
    pub fn source(&self) -> &'static str;        // "keystore" | "private-key" | "mnemonic"
    pub fn path(&self) -> &str;                  // derivation path for a mnemonic, else ""
    pub fn sign_message(&self, message: &str) -> Result<String>;  // EIP-191, 0x + 130 hex
    pub fn wipe(&mut self); pub fn is_wiped(&self) -> bool;
}
pub fn derivation_path(index: i64) -> Result<String>;
pub enum Kdf { Scrypt /* n=262144 r=8 p=1 */, Pbkdf2 /* 1,000,000 */ }
pub fn create_keystore(material: &KeyMaterial, password: &str, out: &Path, kdf: Kdf,
                       work_factor: Option<u32>) -> Result<PathBuf>;     // new file, mode 0600
pub fn keystore_json(material: &KeyMaterial, password: &str) -> Result<String>;
        // the same V3 document (scrypt, default work factor) as text, no file: the app's
        // "save keystore" hands it to a save dialog / the Android document picker
pub const MNEMONIC_WARNING: &str;

pub trait Prompter {                             // the CLI reads the terminal; the app shows fields
    fn say(&self, text: &str);
    fn secret(&self, prompt: &str) -> Result<Zeroizing<String>>;  // hidden; Err(Cancelled) on EOF
    fn ask(&self, prompt: &str) -> Result<String>;                // visible
}
pub enum KeySource { Keystore(PathBuf), PrivateKey, Mnemonic { index: i64, passphrase: bool } }
pub fn load_key(source: &KeySource, prompter: &dyn Prompter) -> Result<KeyMaterial>;
        // the Python prompts; a mnemonic asks "Derived <path> -> <address>. Is this the right address? [y/N]"
pub fn keys::is_password_error(error: &Error) -> bool;   // the CLI retries a wrong password 3 times
```

## Plans (pure verification)

```rust
pub struct Rule { pub kind: u8, pub target: Address, pub token_in: Address, pub counterparty: Address,
                  pub max_amount: U256, pub max_secondary: U256, pub max_daily: U256,
                  pub min_out_per_in_wad: U256, pub max_deadline_delay: u64 }
impl Rule { pub fn method(&self) -> &'static str;   // names repeat: participate 1/10, activate 5/11, claim 14/18
            pub fn label(&self) -> String;       // "participate (kind 10)" for an Origin kind, else the method
            pub fn unit(&self) -> (&'static str, u32);   // rule_kinds.py: DAI 18, LGNS 9, "calls" 0, ...
            pub fn is_origin(&self) -> bool; pub fn is_counted(&self) -> bool;
            pub fn floor_tokens(&self) -> Option<(Address, Address)>; }   // kinds 3, 4, 10, 11, 12
pub struct GrantPlan { pub owner: Address, pub grant_id: String, pub session_key: Address,
                       pub bot_id: String, pub valid_after: u64, pub valid_until: u64,
                       pub remaining_calls: u64, pub rules: Vec<Rule>, pub data: String,
                       pub implementation: Address, pub plan: Value /* raw: bounds, bot, customization */ }
pub struct RevokePlan { pub owner: Address, pub grant_id: String, pub grant_kind: GrantKind,
                        pub data: String, pub implementation: Address /* the wallet's Diamond, v1 or v2 */,
                        pub named_implementation: Option<Address> /* not serialized */, pub plan: Value }
pub fn verify_grant_plan(plan: &Value, constants: &Constants, now: Option<u64>) -> Result<GrantPlan>;
        // schema "anubisauto-signer-plan/2" (constants::PLAN_SCHEMA) only;
        // names the version 2 Diamond; rules checked like Helix7702AccountV2 (floors, deadlines, the
        // activation DAI cap, counted kinds); the website's preview matched by kind, method and target
pub fn verify_revoke_plan(plan: &Value, constants: &Constants) -> Result<RevokePlan>;   // v1 or v2 named
        // schema "anubisauto-signer-plan/1" or "/2", or the legacy "awake-helix-signer-plan/1" or "/2"
        // (constants::REVOKE_PLAN_SCHEMAS), so grants made with the old app can still be revoked
pub fn bind_revoke_delegate(plan: &mut RevokePlan, delegate: Address) -> Result<()>;   // the wallet's own
pub fn verify_attestation(attestation: Option<&Value>, owner: &Address, bot: &[u8; 16],
                          session_key: &Address, constants: &Constants) -> Result<()>;
pub fn attestation_digest(chain_id: u64, owner: &Address, bot: &[u8; 16], session_key: &Address) -> [u8; 32];
        // EIP-712 domain {name: "Anubis Automation Session Key Attestation", version: "1", chainId}
pub fn offline_revoke(owner: &str, grant_id: &str, kind: &str, constants: &Constants) -> Result<RevokePlan>;
pub fn check_token(token: &str) -> Result<()>;
pub fn amount(value: &U256, decimals: u32) -> String;     // Python Decimal formatting: "1.5", "10"
```

## Summary (structured data + text)

```rust
pub enum PlanKind { Grant, Revoke }              // "grant" | "revoke"
pub struct Summary {
    pub kind: PlanKind, pub signer_version: String,
    pub website: Option<String>, pub official_website: bool,   // show a warning when not official
    pub chain_id: u64, pub rpc_url: String, pub development: bool,
    pub owner: Address, pub transaction: String, pub balance: String,   // "1 DAI"
    pub grant: Option<GrantSummary>, pub revoke: Option<RevokeSummary>,
}
pub struct GrantSummary { pub delegates: bool /* type-4 */, pub delegate: Address /* v2 */,
    pub moves_from: Option<Address> /* the v1 Diamond the same tx moves the wallet from */,
    pub origin_rules: bool, pub code_hash_verified: bool,
    pub session_key: Address, pub bot_script: Option<String>, pub bot_id: String, pub grant_id: String,
    pub valid_after: u64, pub valid_after_text: String, pub valid_until: u64, pub valid_until_text: String,
    pub remaining_calls: u64, pub rules: Vec<RuleSummary>, pub customized: Vec<String> }
pub struct RuleSummary { pub index: usize /* 1-based, for --cap */, pub kind: u8, pub method: String,
    pub target: Address, pub target_name: String, pub spender: Option<Address>, pub swap: Option<SwapSummary>,
    pub floor: Option<SwapSummary> /* kinds 10-12: LGNS per DAI, DAI back per DAI paid, DAI per LGNS */,
    pub unit: String, pub decimals: u32, pub max_per_call: String, pub max_per_day: String,
    pub counted: bool /* caps count calls */, pub activation_dai: Option<String> /* kinds 5 and 11 */,
    pub deadline_seconds: Option<u64>, pub pays_owner: bool /* kinds 25, 26 */ }
pub struct SwapSummary { pub token_in, pub token_in_name, pub token_out, pub token_out_name, pub price_floor: String }
pub struct RevokeSummary { pub method: String, pub grant_id: String, pub grant_kind: GrantKind, pub delegation: String,
                           pub redelegates: bool /* plain account: the type-4 tx re-delegates to v2 */,
                           pub delegate: Address /* the Diamond the wallet uses: v1 stays v1 */ }
impl Summary { pub fn text(&self) -> String; pub fn lines(&self) -> Vec<String>; }  // = Python summary.py
pub fn when(seconds: u64) -> String;             // "2026-11-10 12:00:00 UTC (local 2026-11-10 13:00:00 CET)"
pub mod summary { grant_summary(), revoke_summary(), dai(), named() }
```

## Customize (expiry, calls, caps)

```rust
pub struct CustomizeRequest { pub valid_until: Option<i64>, pub remaining_calls: Option<u64>,
                              pub rules: Vec<RuleChange> }   // JSON {"validUntil","remainingCalls","rules"}
pub struct RuleChange { pub index: usize, pub max_per_call: Option<String>, pub max_per_day: Option<String> }
pub mod custom {
    pub const ZONES: [&str; 17];                 // "Local", "UTC", "Asia/Taipei", ... for a zone picker
    pub fn parse_expiry(text: &str, now: Option<i64>) -> Result<i64>;
        // "2026-12-31 16:30 Asia/Taipei", "… +08:00", ISO 8601 ("2026-12-31T08:30:00Z"), Unix seconds, "30d", "12h"
    pub fn combine_expiry(date: &str, clock: &str, zone: &str) -> Result<i64>;   // the editor's three fields
    pub fn expiry_parts(seconds: i64, zone: &str) -> Result<(String, String)>;   // back into the fields
    pub fn parse_calls(text: &str) -> Result<u64>;
    pub type Cap = (usize, Option<String>, Option<String>);
    pub fn parse_cap(text: &str, rules: &[Rule]) -> Result<Cap>;                 // "1=15,40", "approve=15", "2=,40",
        // "claim@18=,4" / "claimInterest@Energy Staking=5" (method@kind or method@contract when names repeat)
    pub fn base_units(text: &str, decimals: u32, label: &str) -> Result<String>; // exact digits
    pub fn request_of(plan: &GrantPlan) -> CustomizeRequest;
    pub fn with_changes(plan: &GrantPlan, expires: Option<i64>, calls: Option<u64>, caps: &[Cap]) -> Result<CustomizeRequest>;
    pub fn check_answer(before: &GrantPlan, after: &GrantPlan, request: &CustomizeRequest) -> Result<()>;
}
```

## Flows

```rust
pub enum VerifiedPlan { Grant(GrantPlan), Revoke(RevokePlan) }  // owner(), grant_id(), data()
pub struct Session {                             // Clone; nothing is signed yet
    pub kind: PlanKind, pub plan: VerifiedPlan, pub rpc: net::Rpc, pub constants: Constants,
    pub state: AccountState, pub summary: Summary, pub api: Option<String>, pub token: Option<String>,
    pub transport: Transport, pub polling: chain::Polling /* receipt wait */, pub report_delay: Duration,
}
impl Session { pub fn confirm_word(&self) -> &'static str;   // "AUTHORIZE" | "REVOKE"
               pub fn owner(&self) -> Address; pub fn grant(&self) -> Option<&GrantPlan>;
               pub fn summary_text(&self) -> String; }
pub struct Outcome { pub tx_hash: String, pub tx_type: u8, pub block: u64, pub reported: bool,
                     pub report_message: String, pub gas_used: u64, pub stopped_bots: Vec<Value> }

pub fn prepare_sign(token: &str, api: &str, rpc_url: &str, constants: &Constants,
                    material: Option<&KeyMaterial>, transport: &Transport, log: Log) -> Result<Session>;
pub fn customize(session: &Session, request: &CustomizeRequest, log: Log) -> Result<Session>;
        // ErrorKind::CustomizeRefused: out of bounds / rate limited, the old session can still be signed;
        // ErrorKind::Flow: plan gone, or the answer failed verification ("The website's new plan was refused: …")
pub enum RevokeSource { Plan { token: String, api: String },
                        Offline { owner: String, grant_id: String, kind: Option<GrantKind> /* None: detect */ } }
pub fn prepare_revoke(rpc_url: &str, constants: &Constants, source: RevokeSource,
                      material: Option<&KeyMaterial>, transport: &Transport, log: Log) -> Result<Session>;
pub fn execute_sign(session: &Session, material: KeyMaterial, log: Log) -> Result<Outcome>;
pub fn execute_revoke(session: &Session, material: KeyMaterial, log: Log) -> Result<Outcome>;
        // consume and wipe the key. Plain EOA: one type-4 tx (authorization nonce = account nonce + 1),
        // for an install and for revoking a dormant grant still stored in an un-delegated account (the
        // grant is found with eth_getStorageAt at Helix7702Account's slots; the tx re-delegates, then
        // revokes), always authorizing the version 2 Diamond; delegated to the version 1 Diamond: an install
        // is the same type-4 tx moving the wallet to v2 (grants kept), a revocation a type-2 self-call on v1
        // (whose code hash is checked); delegated to v2: type-2 self-call; elsewhere / contract: refused.
        // Gas: eth_estimateGas with authorizationList, else with a delegation state override, else a
        // fixed fallback; the DAI balance must cover gas x maxFeePerGas. Then receipt, on-chain checks
        // (code = 0xef0100||v2 after installs, v1 or v2 after revocations, PolicyGrantInstalled, policyGrants /
        // key cleared), report (3 tries).
pub fn flow::revoke_call_plan(call: &Value, owner: &Address, grant_id: &str, constants: &Constants) -> Result<RevokePlan>;
pub fn prepare_grant_revoke(site: &Website, grant_id: &str, rpc_url: &str, constants: &Constants,
                            material: &KeyMaterial, transport: &Transport, log: Log) -> Result<Option<Session>>;
        // None: already revoked (409) or not on chain; Err(Flow) for a 409 with reason otherDelegation
pub fn execute_grant_revoke(session: &Session, material: &KeyMaterial, site: &Website, log: Log) -> Result<Outcome>;
        // signs with a copy (the key stays for the next grant), then POST revoke-confirm

pub trait Confirmer: Send + Sync {               // the CLI reads the typed word; the app shows a dialog
    fn confirm(&self, session: &Session, word: &str) -> Result<bool>;   // Err(Cancelled): input closed
}
```

## Website login and grants

```rust
pub struct Website;                              // Send + Sync; cookies only in memory, never printed
impl Website {
    pub fn new(api: &str, client: Arc<dyn HttpClient>) -> Result<Website>;
    pub fn api(&self) -> &str; pub fn owner(&self) -> Option<Address>; pub fn has_session(&self) -> bool;
    pub fn login(&self, material: &KeyMaterial, log: &dyn Fn(&Message)) -> Result<Address>;  // csrf, challenge, personal_sign, verify
    pub fn logout(&self);                        // best effort; forgets the cookies
    pub fn grants(&self) -> Result<Listing>;
    pub fn revoke_call(&self, grant_id: &str) -> Result<Map<String, Value>>;
    pub fn revoke_confirm(&self, grant_id: &str, tx_hash: &str) -> Result<Map<String, Value>>;
}
pub struct Listing { pub owner: String, pub rows: Vec<GrantRow>, pub scan_complete: bool,
                     pub scan_percent: i64, pub truncated: bool, pub delegation: Value }
impl Listing { pub fn active(&self) -> Vec<&GrantRow>; }        // what "revoke all active" handles
pub struct GrantRow { pub grant_id: String, pub kind: String, pub status: String, pub key: String,
                      pub key_origin: String, pub bot: String, // English, for the CLI
                      pub bot_state: String, pub bot_script: String, pub bot_id: String, // for the app
                      pub valid_until: Option<i64>,
                      pub remaining_calls: Option<i64>, pub revocable: bool,
                      pub delegation: String /* helix | none | other */, pub not_revocable_reason: String }
impl GrantRow { pub fn active(&self) -> bool; pub fn describe(&self) -> String; }
        // active(): revocable and active | not_yet_valid | inactive
pub fn website::status_text(status: &str, not_revocable_reason: &str) -> String;  // grants list label;
        // an unknown status is shown as it is
pub fn check_challenge(message: Option<&str>, owner: &Address, api: &str, chain_id: u64) -> Result<String>;
```

## Install check (`anubisauto://ping`)

```rust
pub struct PingResult { pub version: String, pub os: String, pub arch: String, pub api: String }
impl PingResult { pub fn message(&self) -> String; }     // "Anubis Automation Script Signer is installed and linked — …"
pub fn send_ping(api: &str, token: &str, client: &dyn HttpClient) -> Result<PingResult>;
        // sends only {version, os ("windows"|"macos"|"linux"|"android"|"ios"), arch ("x86_64"|"arm64")}
pub mod ping { pub fn system_name() -> &'static str; pub fn cpu_name() -> &'static str; }
```

## Companion (`serve`)

```rust
pub mod companion {
    pub const DEFAULT_PORT: u16 = 17702;
    pub const SITE_ORIGIN: &str = "https://anubis.sivilization.com";
    pub type Clock = Arc<dyn Fn() -> f64 + Send + Sync>;           // monotonic seconds (tests)
    pub struct KeyHolder;   // new(loader: Box<dyn Fn() -> Result<KeyMaterial> + Send + Sync>, idle: Duration,
                            //     clock: Option<Clock>); unlock(), loaded(), address(), expire_if_idle(), wipe()
    pub struct Pairings;    // load(Option<PathBuf>) (pairings.json, written 0600 on POSIX); add(), get()
    pub struct PairingCode; // "K7Q2-M9XD": single use, 10 minutes, 5 attempts
    pub struct CompanionConfig { pub api: String, pub rpc_url: String, pub constants: Constants,
                                 pub origins: Vec<String> /* loopback only */, pub auto_confirm_revoke: bool,
                                 pub port: u16 /* 0 = free */, pub transport: Transport }
    pub type Output = Arc<dyn Fn(&str) + Send + Sync>;
    pub struct Companion;
    impl Companion {
        pub fn new(config: CompanionConfig, keys: KeyHolder, pairings: Pairings, out: Output,
                   confirmer: Arc<dyn Confirmer>) -> Result<Arc<Companion>>;
        pub fn bind(self: &Arc<Self>) -> Result<Server>;            // 127.0.0.1 only
        pub fn work(&self, stop: &AtomicBool);                      // the job worker thread
        pub fn code(&self) -> String; pub fn new_code(&self) -> String; pub fn port(&self) -> u16;
        pub fn health(&self, paired: bool) -> Value; pub fn job_state(&self, id: &str) -> Option<Job>;
        pub fn handle(&self, method: &str, target: &str, header: &dyn Fn(&str) -> Option<String>,
                      body: Option<&[u8]>) -> Answer;               // transport-free request handler
    }
    pub struct Server; impl Server { pub fn port(&self) -> u16; pub fn run(&self, stop: &AtomicBool); }
    pub fn serve(companion: Arc<Companion>, stop: Arc<AtomicBool>) -> Result<()>;   // prints like Python
    pub fn constants_hash(constants: &Constants) -> String;    // byte-identical to the Python companion
    pub fn sign_request(secret_hex: &str, method: &str, path: &str, body: &[u8], now_ms: Option<i64>)
        -> Vec<(String, String)>;                                // client side
}
```

Protocol (unchanged): Host must be `127.0.0.1:<port>` or `localhost:<port>`;
Origin must be the official site or an `--allow-origin` loopback origin (else
403 without CORS headers); preflight 204 with
`Access-Control-Allow-Private-Network: true` when requested; `POST /pair
{code}` → `{pairingId, secret}`; later requests carry `X-Helix-Pairing`,
`X-Helix-Timestamp` (ms, ±60 s), `X-Helix-Nonce` (16–128 chars, single use)
and `X-Helix-Signature = hex(HMAC-SHA256(secret, METHOD\nPATH\nTIMESTAMP\nNONCE\nhex(SHA256(body))))`;
`POST /sign {planToken}` / `POST /revoke {revokeToken}` → 202 job, `GET
/jobs/<id>` (`queued`, `unlocking`, `awaiting-confirmation`, `broadcasting`,
`done`, `failed`, `cancelled`), `GET /health`. Every authorization goes
through the `Confirmer`; revocations too unless `auto_confirm_revoke`.

## URL scheme registration and desktop integration

```rust
pub mod register {
    pub trait UrlSchemeRegistrar: Send + Sync { fn register(&self) -> Result<String>;
        fn unregister(&self) -> Result<String>; fn registration(&self) -> Option<String>; }
    pub struct LinuxRegistrar { pub command: Vec<String>, pub home: Option<PathBuf>, pub terminal: bool }
        // ~/.local/share/applications/anubisauto-signer.desktop (MimeType: both schemes) + icon + xdg-mime default
    pub struct WindowsRegistrar { pub command: Vec<String> }    // HKCU\Software\Classes\<scheme>, both schemes
    pub struct MacosRegistrar { pub bundle: Option<PathBuf> }   // Info.plist declares it; lsregister -f
    pub struct ManifestRegistrar;                               // Android/iOS: the app manifest
    pub fn for_this_os(command: Vec<String>, terminal: bool) -> Box<dyn UrlSchemeRegistrar>;
    pub fn desktop_entry(command: &[String], terminal: bool) -> String;
    pub fn program() -> PathBuf;                                // $APPIMAGE, else this executable
}
pub mod integrate { pub const COMMAND: &str;                   // "anubisauto-signer"
    pub fn config_dir() -> PathBuf;   // AWAKE_HELIX_SIGNER_HOME wins; else %APPDATA%\AnubisAutoSigner,
                                      // ~/Library/Application Support/AnubisAutoSigner, $XDG_CONFIG_HOME/anubisauto-signer
    pub fn install_cli(dir: Option<&Path>, home: Option<&Path>, target: &Path) -> Result<String>;
    pub fn uninstall_cli(target: &Path, home: Option<&Path>) -> String;
    pub fn cli_link(target: &Path, home: Option<&Path>) -> Option<PathBuf>; }
pub mod icon { pub fn png(size: u32) -> Vec<u8>; pub fn ico(sizes: &[u32]) -> Vec<u8>; }
```

## Differences from the Python signer (deliberate)

* The version is 0.7.0.
* `Local` in an expiry uses the system time zone with its DST rules for that
  date (Python used the current UTC offset for every date).
* Inputs on which the Python signer crashed with a traceback (a plan
  `schema` that is a list or object, an unparsable IPv6 URL in `is_loopback`)
  are refused or treated as not loopback instead.
* Regex `$` in Python accepted a trailing newline in tokens, grant IDs and
  signatures; the Rust signer does not.
* Unicode (non-ASCII) digits are not accepted in amounts, calls or expiries.
* `gui` starts the Anubis Automation Script Signer app next to the CLI when
  present; a bare `anubisauto://` (or legacy `awakehelix://`) link argument
  runs `open` in the terminal, `--register` /
  `--unregister` / `--selftest` work as before.
