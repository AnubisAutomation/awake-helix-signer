//! Tauri commands: thin wrappers that run the controller off the UI thread.

use std::sync::Arc;

use helix_signer_core::{msg, Message};
use serde_json::Value;
use tauri::{AppHandle, Manager, State};

use crate::backend::{Core, KeyInput, Secret};
use crate::controller::Controller;
use crate::desktop;
use crate::views::{
    AppInfo, CommandError, CommandResult, KeyView, LinkView, ListingView, PendingView, PingView, RevokeOutcome, SessionView, SetupView,
    SignResult,
};
use crate::AppState;

type Shared = Arc<Controller<crate::backend::RealCore>>;

/// Run blocking controller work on a worker thread.
async fn work<T: Send + 'static>(controller: Shared, job: impl FnOnce(&Controller<crate::backend::RealCore>) -> CommandResult<T> + Send + 'static) -> CommandResult<T> {
    tauri::async_runtime::spawn_blocking(move || job(&controller))
        .await
        .map_err(|error| CommandError::io(format!("worker failed: {error}")))?
}

#[tauri::command]
pub fn app_info(state: State<'_, AppState>) -> AppInfo {
    let core = &state.controller.core;
    AppInfo {
        version: helix_signer_core::VERSION.to_string(),
        os: desktop::os_name(),
        arch: desktop::arch_name(),
        mobile: desktop::mobile(),
        chain_id: core.chain_id(),
        rpc: core.rpc_url(),
        default_api: core.default_api(),
        development: core.development(),
        selftest: state.options.selftest,
        launched_for_ping: state.options.launched_for_ping(),
    }
}

/// The link the app was opened with (or one that arrived before the page
/// listened); from now on links arrive as `signer://link` events.
#[tauri::command]
pub fn initial_link(state: State<'_, AppState>) -> Option<String> {
    let mut inbox = state.inbox.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let first = !inbox.ready;
    inbox.ready = true;
    let pending = inbox.pending.take();
    pending.or_else(|| if first { state.options.link.clone() } else { None })
}

#[tauri::command]
pub fn open_link(state: State<'_, AppState>, url: String) -> CommandResult<LinkView> {
    state.controller.open_link(&url)
}

#[tauri::command]
pub fn close_request(state: State<'_, AppState>) -> CommandResult<()> {
    state.controller.close_request()
}

#[tauri::command]
pub async fn load_key(state: State<'_, AppState>, source: KeyInput) -> CommandResult<KeyView> {
    work(Arc::clone(&state.controller), move |controller| controller.load_key(source)).await
}

#[tauri::command]
pub fn key_status(state: State<'_, AppState>) -> Option<KeyView> {
    state.controller.key_status()
}

#[tauri::command]
pub async fn forget_key(state: State<'_, AppState>) -> CommandResult<()> {
    work(Arc::clone(&state.controller), |controller| {
        controller.forget_key();
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn export_keystore(state: State<'_, AppState>, password: Secret) -> CommandResult<String> {
    work(Arc::clone(&state.controller), move |controller| controller.export_keystore(&password.0)).await
}

#[tauri::command]
pub async fn prepare_request(state: State<'_, AppState>) -> CommandResult<SessionView> {
    work(Arc::clone(&state.controller), |controller| controller.prepare_request()).await
}

#[tauri::command]
pub async fn customize(state: State<'_, AppState>, request: Value) -> CommandResult<SessionView> {
    work(Arc::clone(&state.controller), move |controller| controller.customize(&request)).await
}

#[tauri::command]
pub async fn sign(state: State<'_, AppState>, word: String) -> CommandResult<SignResult> {
    work(Arc::clone(&state.controller), move |controller| controller.sign(&word)).await
}

#[tauri::command]
pub async fn grants_load(state: State<'_, AppState>) -> CommandResult<ListingView> {
    work(Arc::clone(&state.controller), |controller| controller.grants_load()).await
}

#[tauri::command]
pub async fn grants_prepare(state: State<'_, AppState>, grant_ids: Option<Vec<String>>) -> CommandResult<PendingView> {
    work(Arc::clone(&state.controller), move |controller| controller.grants_prepare(grant_ids)).await
}

#[tauri::command]
pub async fn grants_confirm(state: State<'_, AppState>, word: String) -> CommandResult<RevokeOutcome> {
    work(Arc::clone(&state.controller), move |controller| controller.grants_confirm(&word)).await
}

#[tauri::command]
pub fn grants_cancel(state: State<'_, AppState>) {
    state.controller.grants_cancel();
}

#[tauri::command]
pub fn setup_status(app: AppHandle) -> SetupView {
    #[cfg(desktop)]
    let registered = {
        use tauri_plugin_deep_link::DeepLinkExt;
        app.deep_link().is_registered(desktop::SCHEME).ok()
    };
    #[cfg(mobile)]
    let registered = {
        let _ = &app;
        Some(true)
    };
    desktop::setup(registered)
}

#[tauri::command]
pub fn register_links(app: AppHandle) -> CommandResult<Message> {
    if desktop::mobile() || cfg!(target_os = "macos") {
        return Err(CommandError::refused(msg!("app.linksAtInstall", "The system registers awakehelix:// links for this app at install.")));
    }
    #[cfg(desktop)]
    {
        use tauri_plugin_deep_link::DeepLinkExt;
        app.deep_link()
            .register(desktop::SCHEME)
            .map_err(|error| CommandError::error(msg!("app.registerFailed", "Registration failed: {detail}", detail = error.to_string())))?;
    }
    let _ = &app;
    Ok(msg!("app.linksRegistered", "awakehelix:// links now open this app."))
}

#[tauri::command]
pub fn install_cli() -> CommandResult<Message> {
    desktop::install_cli()
}

#[tauri::command]
pub fn mark_first_run() -> CommandResult<()> {
    desktop::mark_first_run()
}

#[tauri::command]
pub async fn ping(state: State<'_, AppState>, url: String) -> CommandResult<PingView> {
    work(Arc::clone(&state.controller), move |controller| controller.ping(&url)).await
}

#[tauri::command]
pub fn touch(state: State<'_, AppState>) {
    state.controller.touch();
}

/// The page finished `--selftest`: print the result and exit.
#[tauri::command]
pub fn selftest_done(app: AppHandle, ok: bool, detail: String) {
    if !app.state::<AppState>().options.selftest {
        return;
    }
    if ok {
        println!("app selftest ok: {detail}");
    } else {
        eprintln!("app selftest FAILED: {detail}");
    }
    app.exit(if ok { 0 } else { 1 });
}

/// The window title in the page's language (the page calls it when the language changes).
#[tauri::command]
pub fn set_title(app: AppHandle, title: String) {
    #[cfg(desktop)]
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.set_title(&title);
    }
    let _ = (&app, &title);
}

#[tauri::command]
pub fn quit(app: AppHandle) {
    app.state::<AppState>().controller.forget_key();
    app.exit(0);
}
