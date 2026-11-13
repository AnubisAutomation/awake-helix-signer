//! Awake Helix Signer core: verify hosted-bot plans against pinned constants,
//! show exactly what will be signed, sign EIP-7702 authorizations and grant
//! transactions with the owner's key on this device, broadcast them to Anubis
//! Chain 6714, and talk to the website (plans, reports, login, grants) and to
//! the dashboard (the loopback companion).
//!
//! The API is blocking; see `API.md` for the overview the CLI and the app
//! build on.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod abi;
pub mod address;
pub mod chain;
pub mod companion;
pub mod constants;
pub mod custom;
pub mod error;
pub mod flow;
pub mod icon;
pub mod integrate;
pub mod keys;
pub mod links;
pub mod net;
pub mod ping;
pub mod plan;
pub mod pyfmt;
pub mod pyjson;
pub mod register;
pub mod secp;
pub mod summary;
pub mod tx;
pub mod website;

/// Version of the signer (``awake-helix-signer --version``).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use address::Address;
pub use chain::{AccountKind, AccountState};
pub use constants::{production, Constants, GrantKind, CHAIN_ID, DEFAULT_API, DEFAULT_RPC};
pub use custom::{CustomizeRequest, RuleChange};
pub use error::{Error, ErrorKind, Result};
pub use flow::{
    customize, execute_grant_revoke, execute_revoke, execute_sign, load_constants, prepare_grant_revoke, prepare_revoke,
    prepare_sign, Confirmer, Outcome, RevokeSource, Session, VerifiedPlan,
};
pub use keys::{create_keystore, derivation_path, keystore_json, load_key, Kdf, KeyMaterial, KeySource, Prompter, MNEMONIC_WARNING};
pub use links::{parse_link, Link, LinkAction};
pub use net::{HttpClient, HttpRequest, HttpResponse, Transport, TransportError};
pub use ping::{send_ping, PingResult};
pub use plan::{
    amount, attestation_digest, check_token, offline_revoke, verify_attestation, verify_grant_plan, verify_revoke_plan,
    GrantPlan, RevokePlan, Rule,
};
pub use ruint::aliases::U256;
pub use summary::{when, PlanKind, Summary};
pub use website::{check_challenge, GrantRow, Listing, Website};
pub use zeroize::Zeroizing;
