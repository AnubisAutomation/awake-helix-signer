//! The command layer: one `Controller` holds the link, the unlocked key, the
//! verified plan, the website session and the verified revocations, and
//! implements every command. It is generic over `Core` so the unit tests run
//! it against a mock; the app uses `Controller<RealCore>`.
//!
//! Rules kept from the former Python desktop window:
//! * the key is kept only in memory, wiped on Forget, after a signed request,
//!   on a refused request and after 10 minutes without use;
//! * signing needs the verified plan and the exact confirmation word;
//! * a refused edit keeps the verified plan (it can still be signed);
//! * revocations are verified first, then signed one by one after REVOKE,
//!   and Cancel stops after the current transaction.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::backend::{Core, KeyInput, LinkInfo};
use crate::views::{CommandError, CommandResult, KeyView, LinkView, ListingView, PendingView, PingView, RevokeOutcome, SessionView, SignResult};

/// An unlocked key is wiped after this long without use.
pub const IDLE_WIPE: Duration = Duration::from_secs(600);

/// Where the controller reports progress (Tauri events in the app).
pub trait Events: Send + Sync {
    fn log(&self, scope: &'static str, line: &str);
    fn progress(&self, done: usize, total: usize);
    fn key_wiped(&self);
}

/// Discards everything (tests that do not look at events).
pub struct NoEvents;
impl Events for NoEvents {
    fn log(&self, _: &'static str, _: &str) {}
    fn progress(&self, _: usize, _: usize) {}
    fn key_wiped(&self) {}
}

struct State<C: Core> {
    link: Option<LinkInfo>,
    key: Option<C::Key>,
    session: Option<C::Session>,
    site: Option<Arc<C::Site>>,
    listing: Option<ListingView>,
    pending: Vec<C::Session>,
    busy: bool,
    used: Instant,
}

pub struct Controller<C: Core> {
    pub core: C,
    events: Arc<dyn Events>,
    state: Mutex<State<C>>,
    cancel: AtomicBool,
}

/// Clears the busy flag however a command ends.
struct Busy<'a, C: Core>(&'a Controller<C>);
impl<C: Core> Drop for Busy<'_, C> {
    fn drop(&mut self) {
        let mut state = self.0.lock();
        state.busy = false;
        state.used = Instant::now();
    }
}

impl<C: Core> Controller<C> {
    pub fn new(core: C, events: Arc<dyn Events>) -> Self {
        Self {
            core,
            events,
            state: Mutex::new(State {
                link: None,
                key: None,
                session: None,
                site: None,
                listing: None,
                pending: Vec::new(),
                busy: false,
                used: Instant::now(),
            }),
            cancel: AtomicBool::new(false),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State<C>> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Mark a long command as running (refused when another one runs).
    fn begin(&self) -> CommandResult<Busy<'_, C>> {
        let mut state = self.lock();
        if state.busy {
            return Err(CommandError::busy());
        }
        state.busy = true;
        state.used = Instant::now();
        Ok(Busy(self))
    }

    fn log_to(&self, scope: &'static str) -> impl Fn(&str) + Sync + '_ {
        move |line: &str| self.events.log(scope, line)
    }

    pub fn is_busy(&self) -> bool {
        self.lock().busy
    }

    // ------------------------------------------------------------- links

    /// Validate a link and make it the current request (or website).
    pub fn open_link(&self, url: &str) -> CommandResult<LinkView> {
        let link = self.core.parse_link(url)?;
        let mut state = self.lock();
        if state.busy && link.action != "ping" {
            return Err(CommandError::busy());
        }
        let view = LinkView { action: link.action.clone(), api: link.api.clone(), official: self.core.official(&link.api) };
        if link.action == "ping" {
            return Ok(view);
        }
        // Another website: its session (if any) does not apply.
        if state.link.as_ref().map(|old| old.api != link.api).unwrap_or(link.api != self.core.default_api()) {
            if let Some(site) = state.site.take() {
                let core = &self.core;
                core.logout(&site);
            }
            state.listing = None;
            state.pending.clear();
        }
        state.session = None;
        state.link = Some(link);
        state.used = Instant::now();
        Ok(view)
    }

    pub fn close_request(&self) -> CommandResult<()> {
        let mut state = self.lock();
        if state.busy {
            return Err(CommandError::busy());
        }
        state.session = None;
        if state.link.as_ref().map(|link| link.action == "sign" || link.action == "revoke").unwrap_or(false) {
            let api = state.link.as_ref().map(|link| link.api.clone()).unwrap_or_default();
            state.link = Some(LinkInfo { action: "grants".into(), token: String::new(), api });
        }
        Ok(())
    }

    /// The website this window talks to (the link's, else the default).
    pub fn api(&self) -> String {
        self.lock().link.as_ref().map(|link| link.api.clone()).unwrap_or_else(|| self.core.default_api())
    }

    // --------------------------------------------------------------- key

    pub fn load_key(&self, input: KeyInput) -> CommandResult<KeyView> {
        let _busy = self.begin()?;
        if let Some(key) = self.lock().key.as_ref() {
            return Ok(self.core.key_view(key));
        }
        let key = self.core.load_key(input)?;
        let view = self.core.key_view(&key);
        self.lock().key = Some(key);
        Ok(view)
    }

    pub fn key_status(&self) -> Option<KeyView> {
        self.lock().key.as_ref().map(|key| self.core.key_view(key))
    }

    /// Wipe the key, end the website session and drop verified revocations.
    pub fn forget_key(&self) {
        let site = {
            let mut state = self.lock();
            if let Some(mut key) = state.key.take() {
                self.core.wipe(&mut key);
            }
            state.pending.clear();
            state.listing = None;
            if !state.busy {
                state.session = None;
            }
            state.site.take()
        };
        if let Some(site) = site {
            self.core.logout(&site);
        }
    }

    pub fn export_keystore(&self, password: &str) -> CommandResult<String> {
        if password.chars().count() < 8 {
            return Err(CommandError::refused("Use a password of at least 8 characters."));
        }
        let key = self.lock().key.clone().ok_or_else(CommandError::no_key)?;
        let mut copy = key;
        let result = self.core.export_keystore(&copy, password);
        self.core.wipe(&mut copy);
        result
    }

    /// Wipe an idle key; true when it was wiped now.
    pub fn idle_check(&self, now: Instant) -> bool {
        let idle = {
            let state = self.lock();
            state.key.is_some() && !state.busy && now.saturating_duration_since(state.used) > IDLE_WIPE
        };
        if idle {
            self.forget_key();
            self.events.key_wiped();
        }
        idle
    }

    pub fn touch(&self) {
        self.lock().used = Instant::now();
    }

    /// A refused request ends it and wipes the key (as the Python app does).
    fn end_request(&self) {
        self.forget_key();
        self.lock().session = None;
    }

    // ----------------------------------------------------------- request

    pub fn prepare_request(&self) -> CommandResult<SessionView> {
        let busy = self.begin()?;
        let (link, key) = {
            let state = self.lock();
            let link = state.link.clone().filter(|link| link.action == "sign" || link.action == "revoke");
            (link, state.key.clone())
        };
        let link = link.ok_or_else(|| CommandError::refused("Open a request from the website first."))?;
        let mut key = key.ok_or_else(CommandError::no_key)?;
        let log = self.log_to("request");
        let result = self.core.prepare(&link, &key, &log);
        self.core.wipe(&mut key);
        match result {
            Ok(session) => {
                let view = self.core.session_view(&session);
                self.lock().session = Some(session);
                Ok(view)
            }
            Err(error) => {
                drop(busy);
                self.end_request();
                Err(error)
            }
        }
    }

    /// Ask the website to re-plan the grant; `{}` restores the defaults.
    pub fn customize(&self, request: &Value) -> CommandResult<SessionView> {
        let busy = self.begin()?;
        let session = self.lock().session.clone().ok_or_else(|| CommandError::refused("There is no verified plan to edit."))?;
        if self.core.session_view(&session).editor.is_none() {
            return Err(CommandError::refused("Only a grant can be edited."));
        }
        let log = self.log_to("request");
        match self.core.customize(&session, request, &log) {
            Ok(updated) => {
                let view = self.core.session_view(&updated);
                self.lock().session = Some(updated);
                Ok(view)
            }
            // Out of bounds: the verified plan stays and can still be signed.
            Err(error) if error.kind == "customize" => Err(error),
            Err(error) => {
                drop(busy);
                self.end_request();
                Err(error)
            }
        }
    }

    /// Sign and broadcast the verified plan after the typed word.
    pub fn sign(&self, word: &str) -> CommandResult<SignResult> {
        let busy = self.begin()?;
        let (session, key) = {
            let mut state = self.lock();
            let session = state.session.clone().ok_or_else(|| CommandError::refused("There is no verified plan to sign."))?;
            let expected = self.core.session_view(&session).confirm_word;
            if word.trim() != expected {
                return Err(CommandError::refused(format!("Type {expected} exactly to sign.")));
            }
            let key = state.key.take().ok_or_else(CommandError::no_key)?;
            state.session = None;
            (session, key)
        };
        let log = self.log_to("request");
        let result = self.core.execute(&session, key, &log);
        drop(busy);
        // Done or refused, the request ends and the key is gone.
        self.end_request();
        result
    }

    // ------------------------------------------------------------ grants

    fn site(&self, key: &C::Key, log: &(dyn Fn(&str) + Sync)) -> CommandResult<Arc<C::Site>> {
        if let Some(site) = self.lock().site.clone() {
            if self.core.signed_in(&site) {
                return Ok(site);
            }
        }
        let site = Arc::new(self.core.website(&self.api())?);
        self.core.login(&site, key, log)?;
        self.lock().site = Some(Arc::clone(&site));
        Ok(site)
    }

    /// Sign in (a signature only) when needed and read every grant.
    pub fn grants_load(&self) -> CommandResult<ListingView> {
        let _busy = self.begin()?;
        let mut key = self.lock().key.clone().ok_or_else(CommandError::no_key)?;
        let log = self.log_to("grants");
        let result = self.site(&key, &log).and_then(|site| self.core.grants(&site));
        self.core.wipe(&mut key);
        let listing = result?;
        let mut state = self.lock();
        state.listing = Some(listing.clone());
        state.pending.clear();
        Ok(listing)
    }

    /// Get and verify each revocation (`None` = every active grant); nothing is signed.
    pub fn grants_prepare(&self, grant_ids: Option<Vec<String>>) -> CommandResult<PendingView> {
        let _busy = self.begin()?;
        let (key, site, listing) = {
            let state = self.lock();
            (state.key.clone(), state.site.clone(), state.listing.clone())
        };
        let mut key = key.ok_or_else(CommandError::no_key)?;
        let site = site.filter(|site| self.core.signed_in(site)).ok_or_else(CommandError::no_key)?;
        let listing = listing.ok_or_else(|| CommandError::refused("Load the grants first."))?;
        let ids: Vec<String> = match grant_ids {
            Some(ids) => {
                for id in &ids {
                    let known = listing.rows.iter().any(|row| row.grant_id.eq_ignore_ascii_case(id) && row.revocable);
                    if !known {
                        return Err(CommandError::refused(format!("{id} is not a revocable grant of this account.")));
                    }
                }
                ids
            }
            None => listing.rows.iter().filter(|row| row.active).map(|row| row.grant_id.clone()).collect(),
        };
        self.cancel.store(false, Ordering::SeqCst);
        let log = self.log_to("grants");
        let mut sessions = Vec::new();
        let mut summaries = Vec::new();
        let mut failure = None;
        for id in &ids {
            match self.core.prepare_grant_revoke(&site, id, &key, &log) {
                Ok(Some(session)) => {
                    summaries.push(self.core.session_view(&session).summary);
                    sessions.push(session);
                }
                Ok(None) => {}
                Err(error) => {
                    failure = Some(error);
                    break;
                }
            }
        }
        self.core.wipe(&mut key);
        if let Some(error) = failure {
            return Err(error);
        }
        let count = sessions.len();
        self.lock().pending = sessions;
        Ok(PendingView { count, summaries })
    }

    /// Sign, broadcast and confirm the verified revocations one by one.
    pub fn grants_confirm(&self, word: &str) -> CommandResult<RevokeOutcome> {
        let _busy = self.begin()?;
        if word.trim() != "REVOKE" {
            return Err(CommandError::refused("Type REVOKE exactly to sign."));
        }
        let (sessions, key, site) = {
            let mut state = self.lock();
            let sessions = std::mem::take(&mut state.pending);
            (sessions, state.key.clone(), state.site.clone())
        };
        if sessions.is_empty() {
            return Err(CommandError::refused("Nothing is waiting to be revoked."));
        }
        let mut key = key.ok_or_else(CommandError::no_key)?;
        let site = site.ok_or_else(CommandError::no_key)?;
        self.cancel.store(false, Ordering::SeqCst);
        let log = self.log_to("grants");
        let total = sessions.len();
        let mut done = 0;
        let mut lines = Vec::new();
        let mut failure = None;
        self.events.progress(0, total);
        for session in &sessions {
            if self.cancel.load(Ordering::SeqCst) {
                break;
            }
            match self.core.execute_grant_revoke(session, &key, &site, &log) {
                Ok(result) => {
                    done += 1;
                    let note = if result.stopped_bots.is_empty() {
                        String::new()
                    } else {
                        format!("; bot(s) stopped: {}", result.stopped_bots.join(", "))
                    };
                    let line = format!(
                        "Revoked {} in transaction {} (block {}){note}.",
                        self.core.grant_of(session),
                        result.tx_hash,
                        result.block
                    );
                    self.events.log("grants", &line);
                    lines.push(line);
                    self.events.progress(done, total);
                }
                Err(error) => {
                    failure = Some(error);
                    break;
                }
            }
            self.touch();
        }
        self.core.wipe(&mut key);
        let cancelled = done < total && failure.is_none();
        if let Some(error) = failure {
            return Err(CommandError { kind: error.kind, message: format!("{} (revoked {done} of {total} before this)", error.message) });
        }
        let listing = self.core.grants(&site)?;
        self.lock().listing = Some(listing.clone());
        Ok(RevokeOutcome { done, total, cancelled, listing, lines })
    }

    /// Discard verified revocations, or stop after the current transaction.
    pub fn grants_cancel(&self) {
        let mut state = self.lock();
        if !state.pending.is_empty() {
            state.pending.clear();
        } else if state.busy {
            self.cancel.store(true, Ordering::SeqCst);
        }
    }

    // -------------------------------------------------------------- ping

    pub fn ping(&self, url: &str) -> CommandResult<PingView> {
        let link = self.core.parse_link(url)?;
        if link.action != "ping" {
            return Err(CommandError::refused("This is not an install-check link."));
        }
        self.core.ping(&link)
    }
}
