//! Awake Helix Signer, the Tauri 2 app: the window's commands on top of
//! helix-signer-core. `controller` holds all state and logic (unit-tested
//! with a mock core); `commands` is the thin Tauri glue; `desktop` is the
//! link/CLI integration of the desktop systems.

pub mod backend;
pub mod controller;
pub mod desktop;
pub mod options;
pub mod views;

mod commands;

use std::sync::Arc;
use std::time::{Duration, Instant};

use tauri::{Emitter, Manager};

use crate::backend::RealCore;
use crate::controller::{Controller, Events};
use crate::options::Options;
use crate::views::{LogEvent, ProgressEvent};

/// Tauri events for the page.
struct WindowEvents(tauri::AppHandle);

impl Events for WindowEvents {
    fn log(&self, scope: &'static str, line: &str) {
        let _ = self.0.emit("signer://log", LogEvent { scope, line: line.to_string() });
    }
    fn progress(&self, done: usize, total: usize) {
        let _ = self.0.emit("signer://progress", ProgressEvent { done, total });
    }
    fn key_wiped(&self) {
        let _ = self.0.emit("signer://key-wiped", ());
    }
}

/// Links that arrive before the page listens, and whether it listens yet.
#[derive(Default)]
pub struct Inbox {
    pub ready: bool,
    pub pending: Option<String>,
}

pub struct AppState {
    pub controller: Arc<Controller<RealCore>>,
    pub options: Options,
    pub inbox: std::sync::Mutex<Inbox>,
}

/// Deliver a link to the page (or keep it until the page asks for it).
fn deliver(app: &tauri::AppHandle, url: String) {
    let Some(state) = app.try_state::<AppState>() else {
        return; // the window is not set up yet (a link this early is dropped)
    };
    let mut inbox = state.inbox.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if inbox.ready {
        let _ = app.emit("signer://link", url);
    } else {
        inbox.pending = Some(url);
    }
    drop(inbox);
    #[cfg(desktop)]
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// The desktop entry point: `--version`, `--selftest` and the link argument.
pub fn main_desktop() {
    let options = Options::from_args(std::env::args().skip(1));
    if options.version {
        println!("awake-helix-signer-app {}", helix_signer_core::VERSION);
        return;
    }
    run_with(options);
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    run_with(Options::default());
}

fn run_with(options: Options) {
    let core = match options.core() {
        Ok(core) => core,
        Err(error) => {
            eprintln!("Refused: {error}");
            std::process::exit(2);
        }
    };
    let builder = tauri::Builder::default();
    #[cfg(desktop)]
    let builder = builder.plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
        // A link clicked while the app runs starts a second instance with
        // the link as its argument; it hands the link over and exits.
        match crate::options::link_in(argv.iter().skip(1).map(String::as_str)) {
            Some(url) => deliver(app, url),
            None => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.unminimize();
                    let _ = window.set_focus();
                }
            }
        }
    }));
    let selftest = options.selftest;
    builder
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .setup(move |app| {
            use tauri_plugin_deep_link::DeepLinkExt;
            let handle = app.handle().clone();
            let controller = Arc::new(Controller::new(core, Arc::new(WindowEvents(handle.clone()))));
            let mut options = options.clone();
            if options.link.is_none() {
                // macOS, Android and iOS: the link that launched the app.
                if let Ok(Some(urls)) = app.deep_link().get_current() {
                    options.link = crate::options::link_in(urls.iter().map(|url| url.as_str()));
                }
            }
            app.manage(AppState { controller: Arc::clone(&controller), options, inbox: Default::default() });
            let links = handle.clone();
            app.deep_link().on_open_url(move |event| {
                if let Some(url) = crate::options::link_in(event.urls().iter().map(|url| url.as_str())) {
                    deliver(&links, url);
                }
            });
            #[cfg(desktop)]
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_title(&format!("Awake Helix Signer {}", helix_signer_core::VERSION));
            }
            // Wipe an unlocked key after 10 minutes without use.
            let idle = Arc::clone(&controller);
            std::thread::spawn(move || loop {
                std::thread::sleep(Duration::from_secs(5));
                idle.idle_check(Instant::now());
            });
            if selftest {
                std::thread::spawn(|| {
                    std::thread::sleep(Duration::from_secs(90));
                    eprintln!("app selftest: timed out (the page never reported)");
                    std::process::exit(3);
                });
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::initial_link,
            commands::open_link,
            commands::close_request,
            commands::load_key,
            commands::key_status,
            commands::forget_key,
            commands::export_keystore,
            commands::prepare_request,
            commands::customize,
            commands::sign,
            commands::grants_load,
            commands::grants_prepare,
            commands::grants_confirm,
            commands::grants_cancel,
            commands::setup_status,
            commands::register_links,
            commands::install_cli,
            commands::mark_first_run,
            commands::ping,
            commands::touch,
            commands::selftest_done,
            commands::quit,
        ])
        .build(tauri::generate_context!())
        .expect("error while building the Awake Helix Signer app")
        .run(|app, event| {
            if let tauri::RunEvent::Exit = event {
                // Wipe the key and end the website session on the way out.
                app.state::<AppState>().controller.forget_key();
            }
        });
}
