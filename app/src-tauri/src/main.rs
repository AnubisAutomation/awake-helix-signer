// The desktop entry point; Android and iOS start `run` through the mobile
// entry point in lib.rs. Release builds on Windows have no console window.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    helix_signer_app_lib::main_desktop();
}
