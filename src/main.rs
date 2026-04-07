//! NullMagnet Live v2 - main.rs
//! Jupiter Labs
//!
//! Entry point: loads config, detects devices, starts engine, launches egui GUI.
//! Single binary, pure Rust, no web stack.
//!
//! Build:  cargo build --release
//! Run:    ./target/release/nullmagnet-live

mod config;
mod engine;
mod entropy;
mod harvesters;
mod vault;
mod ui;

use config::{NullMagnetConfig, detect_devices};
use engine::ChaosEngine;
use std::sync::Arc;

fn main() {
    println!("╔══════════════════════════════════════════════╗");
    println!("║   NullMagnet Live v2.0 — Jupiter Labs        ║");
    println!("║   NIST SP 800-90B · ML-KEM-1024 · Falcon-512 ║");
    println!("╚══════════════════════════════════════════════╝");

    // Load config (or create default on first run)
    let config = NullMagnetConfig::load();
    println!("[BOOT] Config loaded from {}", config::config_path().display());

    // Auto-detect all hardware devices
    println!("[BOOT] Detecting devices...");
    let detected = detect_devices();
    println!("[BOOT] Audio inputs:  {}", detected.audio_inputs.len());
    println!("[BOOT] Cameras:       {}", detected.cameras.len());
    println!("[BOOT] Serial ports:  {}", detected.serial_ports.len());
    println!("[BOOT] WiFi ifaces:   {}", detected.wifi_interfaces.len());
    println!("[BOOT] BT adapters:   {}", detected.bt_adapters.len());

    // Start the entropy engine
    println!("[BOOT] Starting ChaosEngine...");
    let engine = Arc::new(ChaosEngine::new(config));
    println!("[BOOT] Engine running — all harvester threads spawned");

    // Launch egui GUI
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("NullMagnet Live v2 — Jupiter Labs")
            .with_inner_size([1280.0, 800.0])
            .with_min_inner_size([900.0, 600.0]),
        ..Default::default()
    };

    let engine_clone = engine.clone();
    let detected_clone = detected;

    if let Err(e) = eframe::run_native(
        "NullMagnet Live v2",
        native_options,
        Box::new(move |cc| {
            // Set dark theme
            let mut visuals = egui::Visuals::dark();
            visuals.panel_fill = egui::Color32::from_rgb(10, 10, 15);
            visuals.window_fill = egui::Color32::from_rgb(17, 17, 24);
            visuals.extreme_bg_color = egui::Color32::from_rgb(10, 10, 22);
            visuals.faint_bg_color = egui::Color32::from_rgb(22, 22, 31);
            visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(18, 18, 30);
            visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(22, 22, 35);
            visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(30, 30, 50);
            visuals.widgets.active.bg_fill = egui::Color32::from_rgb(0, 180, 200);
            visuals.selection.bg_fill = egui::Color32::from_rgb(0, 140, 180);
            cc.egui_ctx.set_visuals(visuals);

            // Request repaint at 4 FPS for live updates (not 60 — saves CPU)
            cc.egui_ctx.request_repaint_after(std::time::Duration::from_millis(250));

            Ok(Box::new(ui::NullMagnetApp::new(engine_clone, detected_clone)))
        }),
    ) {
        eprintln!("FATAL: Failed to launch GUI: {}", e);
    }

    // GUI closed — shutdown engine
    println!("[SHUTDOWN] Saving config and zeroizing keys...");
    engine.shutdown();
    println!("[SHUTDOWN] Complete.");
}
