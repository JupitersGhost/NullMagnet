//! NullMagnet Live v2 - ui/mod.rs
//! Jupiter Labs - egui GUI
//!
//! RENDERING: Capped at 15fps max to prevent GPU saturation.
//! Data polling rate is separate and controlled by graph_fps setting.

use std::sync::Arc;
use std::time::Instant;
use egui::{self, Color32, RichText, Ui, ScrollArea};
use egui_plot::{Plot, Line, PlotPoints};

use crate::engine::{ChaosEngine, MetricsSnapshot};
use crate::config::DetectedDevices;
use crate::vault;

const CYAN: Color32 = Color32::from_rgb(0, 229, 255);
const MAGENTA: Color32 = Color32::from_rgb(224, 64, 251);
const GREEN: Color32 = Color32::from_rgb(0, 230, 118);
const AMBER: Color32 = Color32::from_rgb(255, 171, 0);
const RED: Color32 = Color32::from_rgb(255, 23, 68);
const DIM: Color32 = Color32::from_rgb(106, 106, 128);
const MID: Color32 = Color32::from_rgb(154, 154, 176);
const BG_PANEL: Color32 = Color32::from_rgb(18, 18, 30);
const TEXT_BRIGHT: Color32 = Color32::from_rgb(232, 232, 240);

/// Maximum UI render rate in FPS. Prevents GPU saturation.
/// Data polling can be faster than this.
const MAX_RENDER_FPS: u64 = 15;

#[derive(Clone, Copy, PartialEq)]
enum Tab { Dashboard, Settings, Vault }

pub struct NullMagnetApp {
    engine: Arc<ChaosEngine>,
    detected: DetectedDevices,
    metrics: Option<MetricsSnapshot>,
    last_refresh: Instant,
    active_tab: Tab,
    /// Data polling rate (how often we read from engine)
    data_poll_ms: u64,
    /// Graph/waveform update rate (user-configurable)
    graph_fps: u32,

    // Settings state
    selected_audio: String,
    selected_camera: String,
    selected_serial: String,
    selected_wifi: String,
    audio_gain: f32,

    // Vault UI state
    vault_password: String,
    vault_password_visible: bool,
    vault_files: Vec<(String, u64, String)>,
    vault_status: String,
    vault_decrypt_target: String,
    vault_decrypt_result: String,

    // Add headscale target
    new_hs_name: String,
    new_hs_ip: String,
    new_hs_port: String,

    // P2P
    new_peer_addr: String,
    new_hmac_key: String,

    // Mint result
    mint_result: String,
    log_scroll_to_bottom: bool,
}

impl NullMagnetApp {
    pub fn new(engine: Arc<ChaosEngine>, detected: DetectedDevices) -> Self {
        let config = engine.config.lock().clone();
        let graph_fps = config.general.graph_fps.clamp(1, 30);
        Self {
            engine, detected, metrics: None,
            last_refresh: Instant::now(),
            active_tab: Tab::Dashboard,
            data_poll_ms: if graph_fps > 0 { 1000 / graph_fps as u64 } else { 250 },
            graph_fps,
            selected_audio: config.devices.audio_device.clone(),
            selected_camera: config.devices.camera_device.clone(),
            selected_serial: config.devices.usb_serial_port.clone(),
            selected_wifi: config.devices.wifi_interface.clone(),
            audio_gain: config.devices.audio_gain as f32,
            vault_password: String::new(), vault_password_visible: false,
            vault_files: Vec::new(), vault_status: String::new(),
            vault_decrypt_target: String::new(), vault_decrypt_result: String::new(),
            new_hs_name: String::new(), new_hs_ip: String::new(), new_hs_port: "8100".into(),
            new_peer_addr: String::new(), new_hmac_key: String::new(),
            mint_result: String::new(), log_scroll_to_bottom: true,
        }
    }

    fn refresh_metrics(&mut self) {
        if self.last_refresh.elapsed().as_millis() >= self.data_poll_ms as u128 {
            self.metrics = Some(self.engine.get_metrics());
            self.last_refresh = Instant::now();
        }
    }
}

impl eframe::App for NullMagnetApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.refresh_metrics();

        // CRITICAL: Cap render rate at MAX_RENDER_FPS to prevent GPU saturation.
        // Data polling rate is separate (controlled by graph_fps).
        let render_ms = 1000 / MAX_RENDER_FPS;
        ctx.request_repaint_after(std::time::Duration::from_millis(render_ms));

        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("⚡ NullMagnet Live v2").color(CYAN).strong().size(16.0));
                ui.label(RichText::new("Jupiter Labs").color(DIM).size(10.0));
                ui.separator();
                let tab_btn = |ui: &mut Ui, label: &str, tab: Tab, active: &mut Tab| {
                    let is_active = *active == tab;
                    let color = if is_active { CYAN } else { MID };
                    if ui.selectable_label(is_active, RichText::new(label).color(color).size(12.0)).clicked() {
                        *active = tab;
                    }
                };
                tab_btn(ui, "Dashboard", Tab::Dashboard, &mut self.active_tab);
                tab_btn(ui, "Settings", Tab::Settings, &mut self.active_tab);
                tab_btn(ui, "Vault", Tab::Vault, &mut self.active_tab);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if let Some(ref m) = self.metrics {
                        let live_color = if m.live_mode { GREEN } else { DIM };
                        if ui.button(RichText::new(if m.live_mode { "⏸ LIVE" } else { "▶ LIVE" })
                            .color(live_color).size(12.0)).clicked() {
                            self.engine.set_live_mode(!m.live_mode);
                        }
                        let nist_color = if m.pqc_active { GREEN } else { RED };
                        ui.label(RichText::new("● NIST 800-90B").color(nist_color).size(10.0));
                        ui.label(RichText::new(format!("data:{}fps render:{}fps",
                            self.graph_fps, MAX_RENDER_FPS)).color(DIM).size(9.0));
                    }
                });
            });
        });

        egui::SidePanel::left("sidebar").min_width(175.0).max_width(210.0).show(ctx, |ui| {
            self.draw_sidebar(ui);
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            match self.active_tab {
                Tab::Dashboard => self.draw_dashboard(ui),
                Tab::Settings => self.draw_settings(ui),
                Tab::Vault => self.draw_vault(ui),
            }
        });
    }
}

impl NullMagnetApp {
    fn draw_sidebar(&mut self, ui: &mut Ui) {
        let metrics = match &self.metrics { Some(m) => m.clone(), None => return };
        ui.label(RichText::new("ENTROPY SOURCES").color(CYAN).size(10.0));
        ui.separator();
        ScrollArea::vertical().show(ui, |ui| {
            let sources: Vec<(&str, &str, bool, &str)> = vec![
                ("TRNG", "TRNG", metrics.harvester_states.trng, "TRNG"),
                ("Audio", "AUDIO", metrics.harvester_states.audio, "AUDIO"),
                ("System", "SYSTEM", metrics.harvester_states.system, "SYSTEM"),
                ("Mouse", "MOUSE", metrics.harvester_states.mouse, "MOUSE"),
                ("Video", "VIDEO", metrics.harvester_states.video, "VIDEO"),
                ("WiFi", "WIFI", metrics.harvester_states.wifi, "WIFI"),
                ("USB Serial", "USB_SERIAL", metrics.harvester_states.usb_serial, "USB_SERIAL"),
                ("BT Passive", "BT_PASSIVE", metrics.harvester_states.bt_passive, "BT_PASSIVE"),
            ];
            for (label, toggle_name, enabled, metric_key) in &sources {
                self.draw_source_toggle(ui, label, toggle_name, *enabled, &metrics, metric_key);
            }

            // GPU sources — show both if available
            if metrics.gpu_cuda_available {
                self.draw_source_toggle(ui, &format!("GPU CUDA"),
                    "GPU_CUDA", metrics.harvester_states.gpu_cuda, &metrics, "GPU_CUDA");
            }
            if metrics.gpu_ocl_available {
                self.draw_source_toggle(ui, &format!("GPU OpenCL"),
                    "GPU_OCL", metrics.harvester_states.gpu_ocl, &metrics, "GPU_OCL");
            }

            // Dual GPU hint
            if metrics.gpu_cuda_available && metrics.gpu_ocl_available {
                ui.label(RichText::new("  (both GPUs independent)").color(DIM).size(8.0));
            }

            #[cfg(feature = "bt-active")]
            { self.draw_source_toggle(ui, "BT RSSI", "BT_ACTIVE",
                metrics.harvester_states.bt_active, &metrics, "BT_RSSI"); }

            // Audio diagnostic — show warning if enabled but no data
            if metrics.harvester_states.audio {
                let audio_m = metrics.source_metrics.get("AUDIO");
                let has_data = audio_m.map(|m| m.samples > 0).unwrap_or(false);
                if !has_data {
                    ui.label(RichText::new("  ⚠ Audio: no data (check device)").color(AMBER).size(9.0));
                }
            }

            // Guitars
            if !metrics.guitar_states.is_empty() {
                ui.add_space(8.0);
                ui.label(RichText::new("GUITARS").color(MAGENTA).size(10.0));
                ui.separator();
                let mut guitar_list: Vec<_> = metrics.guitar_states.iter().collect();
                guitar_list.sort_by(|(a, _), (b, _)| a.cmp(b));
                for (name, gs) in &guitar_list {
                    let mk = format!("GUITAR_{}", name.to_uppercase());
                    let health = metrics.source_metrics.get(&mk).map(|m| m.health_state.as_str()).unwrap_or("INIT");
                    let dot = health_dot_color(gs.enabled, health);
                    ui.horizontal(|ui| {
                        paint_dot(ui, dot);
                        let mut on = gs.enabled;
                        if ui.checkbox(&mut on, RichText::new(format!("{} :{}", name, gs.ctrl_port)).color(TEXT_BRIGHT).size(11.0)).changed() {
                            self.engine.toggle_harvester(&format!("GUITAR_{}", name.to_uppercase()), on);
                        }
                    });
                    if gs.packets_received > 0 {
                        ui.label(RichText::new(format!("  {} pkts / {} B", gs.packets_received, gs.bytes_received)).color(AMBER).size(9.0));
                    }
                }
            }

            // Headscale
            ui.add_space(8.0);
            ui.label(RichText::new("HEADSCALE").color(CYAN).size(10.0));
            ui.separator();
            for (i, hs) in metrics.headscale_targets.iter().enumerate() {
                let dot = match (hs.target.enabled, hs.reachable) {
                    (true, true) => GREEN, (true, false) => AMBER, _ => Color32::from_rgb(50,50,50),
                };
                ui.horizontal(|ui| {
                    paint_dot(ui, dot);
                    let mut on = hs.target.enabled;
                    if ui.checkbox(&mut on, RichText::new(&hs.target.name).color(TEXT_BRIGHT).size(11.0)).changed() {
                        self.engine.toggle_headscale(i, on);
                    }
                });
            }
        });
    }

    fn draw_source_toggle(&self, ui: &mut Ui, label: &str, toggle_name: &str, enabled: bool, metrics: &MetricsSnapshot, metric_key: &str) {
        let health = metrics.source_metrics.get(metric_key).map(|m| m.health_state.as_str()).unwrap_or("INIT");
        let dot = health_dot_color(enabled, health);
        let min_ent = metrics.source_metrics.get(metric_key).map(|m| m.min_entropy).unwrap_or(0.0);
        let samples = metrics.source_metrics.get(metric_key).map(|m| m.samples).unwrap_or(0);
        ui.horizontal(|ui| {
            paint_dot(ui, dot);
            let mut on = enabled;
            if ui.checkbox(&mut on, RichText::new(label).color(TEXT_BRIGHT).size(11.0)).changed() {
                self.engine.toggle_harvester(toggle_name, on);
            }
            if enabled && samples > 0 {
                ui.label(RichText::new(format!("{:.1}", min_ent)).color(DIM).size(9.0));
            }
        });
    }

    fn draw_dashboard(&mut self, ui: &mut Ui) {
        let metrics = match &self.metrics { Some(m) => m.clone(), None => { ui.label("Waiting for engine..."); return; } };
        ScrollArea::vertical().show(ui, |ui| {
            // === TOP STATS ROW (per-batch, instant) ===
            ui.label(RichText::new("INSTANT (per-batch)").color(DIM).size(9.0));
            ui.horizontal(|ui| {
                stat_card(ui, "Shannon", &format!("{:.2}", metrics.current_shannon), CYAN);
                stat_card(ui, "Min-Entropy", &format!("{:.2}", metrics.current_raw_entropy), MAGENTA);
                stat_card(ui, "H_cond", &format!("{:.2}", metrics.conditioned_hmin), AMBER);
                stat_card(ui, "Credited", &format!("{:.0}/256", metrics.aggregate_credited_bits),
                    if metrics.aggregate_credited_bits >= 256.0 { GREEN } else { AMBER });
                stat_card(ui, "Sources", &format!("{}", count_active_sources(&metrics)), TEXT_BRIGHT);
            });
            ui.add_space(4.0);

            // === RUNNING ENTROPY ROW (accumulated — accurate) ===
            ui.label(RichText::new("RUNNING (accumulated — more accurate)").color(CYAN).size(9.0));
            ui.horizontal(|ui| {
                stat_card(ui, "Run Shannon", &format!("{:.3}", metrics.running_shannon), CYAN);
                stat_card(ui, "Run H_min", &format!("{:.3}", metrics.running_min_entropy), MAGENTA);
                stat_card(ui, "Raw Bytes", &format_bits(metrics.running_total_bytes as f64), GREEN);
                stat_card(ui, "Unique/256", &format!("{}", metrics.running_unique_values),
                    if metrics.running_unique_values >= 250 { GREEN }
                    else if metrics.running_unique_values >= 200 { AMBER }
                    else { RED });
                stat_card(ui, "Bits Out", &format_bits(metrics.estimated_true_bits), TEXT_BRIGHT);
            });
            ui.add_space(4.0);

            // === CONDITIONED OUTPUT QUALITY ===
            ui.label(RichText::new("OUTPUT QUALITY (SHA-256 conditioned — should be ~8.0)").color(MAGENTA).size(9.0));
            ui.horizontal(|ui| {
                let out_sh_color = if metrics.output_shannon > 7.9 { GREEN }
                    else if metrics.output_shannon > 7.0 { AMBER } else { RED };
                let out_hm_color = if metrics.output_min_entropy > 7.5 { GREEN }
                    else if metrics.output_min_entropy > 6.0 { AMBER } else { RED };
                stat_card(ui, "Out Shannon", &format!("{:.3}", metrics.output_shannon), out_sh_color);
                stat_card(ui, "Out H_min", &format!("{:.3}", metrics.output_min_entropy), out_hm_color);
                stat_card(ui, "Out Bytes", &format_bits(metrics.output_total_bytes as f64), TEXT_BRIGHT);
                stat_card(ui, "Extractions", &format!("{}", metrics.extractions_count), TEXT_BRIGHT);

                // NIST SP 800-22 stat test badge
                if let Some(ref st) = metrics.stat_tests {
                    let (label, color) = if st.all_passed {
                        ("NIST PASS", GREEN)
                    } else {
                        ("NIST FAIL", RED)
                    };
                    stat_card(ui, "SP 800-22", label, color);
                } else {
                    stat_card(ui, "SP 800-22", "pending", DIM);
                }
            });

            // SP 800-22 detail line
            if let Some(ref st) = metrics.stat_tests {
                ui.horizontal(|ui| {
                    let mk = |pass: bool, name: &str, p: f64| -> (String, Color32) {
                        let color = if pass { GREEN } else { RED };
                        (format!("{}: p={:.3} {}", name, p, if pass {"✓"} else {"✗"}), color)
                    };
                    let (mt, mc) = mk(st.monobit_pass, "Monobit", st.monobit_p);
                    let (rt, rc) = mk(st.runs_pass, "Runs", st.runs_p);
                    let (ft, fc) = mk(st.freq_block_pass, "FreqBlock", st.freq_block_p);
                    ui.label(RichText::new(mt).color(mc).size(9.0).monospace());
                    ui.label(RichText::new(rt).color(rc).size(9.0).monospace());
                    ui.label(RichText::new(ft).color(fc).size(9.0).monospace());
                    ui.label(RichText::new(format!("(n={})", st.sample_size)).color(DIM).size(8.0));
                });
            }

            ui.add_space(8.0);

            // === PER-SOURCE ENTROPY BARS ===
            ui.label(RichText::new("LIVE ENTROPY MIX  (S=Shannon  H=Min-Entropy per batch)").color(DIM).size(10.0));
            let mut sources: Vec<_> = metrics.source_metrics.iter().collect();
            sources.sort_by(|a, b| b.1.raw_shannon.partial_cmp(&a.1.raw_shannon).unwrap_or(std::cmp::Ordering::Equal));
            for (name, m) in sources.iter().take(14) {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(format!("{:>12}", truncate_name(name, 12))).color(DIM).size(10.0).monospace());
                    let frac = (m.raw_shannon / 8.0).clamp(0.0, 1.0) as f32;
                    let bar_color = lerp_color(AMBER, CYAN, frac);
                    let avail = (ui.available_width() - 130.0).max(60.0);
                    let (rect, _) = ui.allocate_exact_size(egui::vec2(avail, 10.0), egui::Sense::hover());
                    ui.painter().rect_filled(rect, 2.0, Color32::from_rgb(10, 10, 22));
                    let fill = egui::Rect::from_min_size(rect.min, egui::vec2(rect.width() * frac, rect.height()));
                    ui.painter().rect_filled(fill, 2.0, bar_color);
                    ui.label(RichText::new(format!("S:{:.2}  H:{:.2}", m.raw_shannon, m.min_entropy)).color(bar_color).size(9.0).monospace());
                });
            }
            // Mixed bar
            if !sources.is_empty() {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(format!("{:>12}", "Mixed")).color(CYAN).size(10.0).monospace());
                    let frac = (metrics.current_shannon / 8.0).clamp(0.0, 1.0) as f32;
                    let avail = (ui.available_width() - 130.0).max(60.0);
                    let (rect, _) = ui.allocate_exact_size(egui::vec2(avail, 10.0), egui::Sense::hover());
                    ui.painter().rect_filled(rect, 2.0, Color32::from_rgb(10, 10, 22));
                    let fill = egui::Rect::from_min_size(rect.min, egui::vec2(rect.width() * frac, rect.height()));
                    ui.painter().rect_filled(fill, 2.0, CYAN);
                    ui.label(RichText::new(format!("S:{:.2}  H:{:.2}", metrics.current_shannon, metrics.conditioned_hmin)).color(CYAN).size(9.0).strong().monospace());
                });
            }
            ui.add_space(8.0);

            // === WAVEFORM ===
            ui.horizontal(|ui| {
                ui.label(RichText::new("ENTROPY WAVEFORM").color(DIM).size(10.0));
                ui.label(RichText::new("(cyan=raw H_min, magenta=whitened)").color(DIM).size(8.0));
            });
            let raw_points: PlotPoints = metrics.history_raw.iter().enumerate().map(|(i, &v)| [i as f64, v]).collect();
            let whi_points: PlotPoints = metrics.history_whitened.iter().enumerate().map(|(i, &v)| [i as f64, v]).collect();
            Plot::new("entropy_waveform").height(120.0).show_axes([false, true])
                .allow_drag(false).allow_zoom(false).allow_scroll(false)
                .include_y(0.0).include_y(8.5)
                .show(ui, |plot_ui| {
                    plot_ui.line(Line::new(raw_points).color(CYAN).name("Raw H_min"));
                    plot_ui.line(Line::new(whi_points).color(MAGENTA).name("Whitened"));
                });
            ui.add_space(8.0);

            // === PQC KEYGEN ===
            ui.horizontal(|ui| {
                ui.label(RichText::new("PQC KEY GENERATION").color(DIM).size(10.0));
                ui.label(RichText::new("ML-KEM-1024 + Falcon-512").color(MAGENTA).size(9.0));
            });
            let credit_frac = (metrics.aggregate_credited_bits / 256.0).clamp(0.0, 1.0) as f32;
            let bar_color = if credit_frac >= 1.0 { GREEN } else { AMBER };
            let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 14.0), egui::Sense::hover());
            ui.painter().rect_filled(rect, 3.0, Color32::from_rgb(10, 10, 22));
            let fill = egui::Rect::from_min_size(rect.min, egui::vec2(rect.width() * credit_frac, rect.height()));
            ui.painter().rect_filled(fill, 3.0, bar_color);
            ui.painter().text(rect.center(), egui::Align2::CENTER_CENTER,
                &format!("{:.0} / 256 credited bits", metrics.aggregate_credited_bits),
                egui::FontId::monospace(9.0), TEXT_BRIGHT);

            ui.horizontal(|ui| {
                let mint_ok = metrics.aggregate_credited_bits >= 256.0;
                if ui.add_enabled(mint_ok, egui::Button::new(
                    RichText::new("⚿ Mint Key Bundle").color(if mint_ok {CYAN} else {DIM}).size(12.0)
                )).clicked() {
                    match self.engine.mint_pqc_bundle("MANUAL") {
                        Ok(msg) => self.mint_result = msg, Err(e) => self.mint_result = format!("Error: {}", e),
                    }
                }
                let mut auto = metrics.auto_mint_enabled;
                if ui.checkbox(&mut auto, RichText::new("Auto-mint").color(TEXT_BRIGHT).size(11.0)).changed() {
                    self.engine.set_auto_mint(auto);
                }
                if !self.mint_result.is_empty() {
                    let c = if self.mint_result.starts_with("Error") { RED } else { GREEN };
                    ui.label(RichText::new(&self.mint_result).color(c).size(10.0));
                }
            });
            ui.add_space(12.0);

            // === LOG CONSOLE ===
            ui.label(RichText::new("LOG CONSOLE").color(DIM).size(10.0));
            egui::Frame::none().fill(Color32::from_rgb(8, 8, 14)).rounding(4.0).inner_margin(6.0).show(ui, |ui| {
                ScrollArea::vertical().max_height(200.0).stick_to_bottom(self.log_scroll_to_bottom).show(ui, |ui| {
                    for line in &metrics.logs {
                        let color = if line.contains("GUITAR") {
                            AMBER
                        } else if line.contains("EXTRACT") {
                            CYAN
                        } else if line.contains("VAULT") || line.contains("AUTO-MINT") {
                            GREEN
                        } else if line.contains("FAIL") || line.contains("ERROR") || line.contains("WARNING") {
                            RED
                        } else if line.contains("HEADSCALE") {
                            MAGENTA
                        } else if line.contains("P2P") {
                            Color32::from_rgb(100, 200, 255)
                        } else {
                            DIM
                        };
                        ui.label(RichText::new(line).color(color).size(10.0).monospace());
                    }
                });
            });
        });
    }

    fn draw_settings(&mut self, ui: &mut Ui) {
        ScrollArea::vertical().show(ui, |ui| {
            // Display / Performance
            ui.label(RichText::new("DISPLAY / PERFORMANCE").color(CYAN).size(10.0));
            ui.horizontal(|ui| {
                ui.label(RichText::new("Data poll rate:").color(TEXT_BRIGHT).size(11.0));
                if ui.add(egui::Slider::new(&mut self.graph_fps, 1..=30)
                    .text("fps")
                    .suffix(" fps")).changed()
                {
                    self.data_poll_ms = if self.graph_fps > 0 { 1000 / self.graph_fps as u64 } else { 250 };
                    self.engine.config.lock().general.graph_fps = self.graph_fps;
                }
            });
            ui.label(RichText::new(format!(
                "Render: {}fps (capped) | Data poll: {}fps | Poll interval: {}ms",
                MAX_RENDER_FPS, self.graph_fps, self.data_poll_ms))
                .color(DIM).size(9.0));
            ui.add_space(12.0);

            // Audio
            ui.label(RichText::new("AUDIO INPUT").color(CYAN).size(10.0));
            if self.detected.audio_inputs.is_empty() {
                ui.label(RichText::new("No audio inputs detected").color(DIM).size(11.0));
            } else {
                let current = if self.selected_audio.is_empty() { "(System Default)".into() } else { self.selected_audio.clone() };
                egui::ComboBox::from_id_salt("audio_dev")
                    .selected_text(RichText::new(&current).color(TEXT_BRIGHT).size(11.0)).width(350.0)
                    .show_ui(ui, |ui| {
                        if ui.selectable_label(self.selected_audio.is_empty(),
                            RichText::new("(System Default)").color(TEXT_BRIGHT)).clicked() { self.selected_audio.clear(); }
                        for (idx, name) in &self.detected.audio_inputs {
                            if ui.selectable_label(self.selected_audio == *name,
                                RichText::new(name).color(TEXT_BRIGHT)).clicked() {
                                self.selected_audio = name.clone();
                                self.engine.set_audio_device(*idx);
                            }
                        }
                    });
                // List detected devices for reference
                ui.label(RichText::new(format!("Detected: {} device(s)", self.detected.audio_inputs.len())).color(DIM).size(9.0));
            }
            ui.horizontal(|ui| {
                ui.label(RichText::new("Gain:").color(TEXT_BRIGHT).size(11.0));
                if ui.add(egui::Slider::new(&mut self.audio_gain, 0.1..=10.0).step_by(0.1)).changed() {
                    self.engine.set_audio_gain(self.audio_gain as f64);
                }
            });
            ui.add_space(12.0);

            // Camera
            ui.label(RichText::new("CAMERA").color(CYAN).size(10.0));
            if self.detected.cameras.is_empty() {
                ui.label(RichText::new("No cameras detected (try restarting app)").color(DIM).size(11.0));
            } else {
                let current = if self.selected_camera.is_empty() {
                    self.detected.cameras.first().map(|(_, n)| n.clone()).unwrap_or_default()
                } else { self.selected_camera.clone() };
                egui::ComboBox::from_id_salt("camera_dev")
                    .selected_text(RichText::new(&current).color(TEXT_BRIGHT).size(11.0)).width(350.0)
                    .show_ui(ui, |ui| {
                        for (idx, name) in &self.detected.cameras {
                            if ui.selectable_label(self.selected_camera == *name,
                                RichText::new(name).color(TEXT_BRIGHT)).clicked() {
                                self.selected_camera = name.clone();
                                self.engine.set_camera_device(*idx);
                            }
                        }
                    });
                ui.label(RichText::new(format!("Detected: {} camera(s)", self.detected.cameras.len())).color(DIM).size(9.0));
            }
            ui.add_space(12.0);

            // USB Serial
            ui.label(RichText::new("USB SERIAL").color(CYAN).size(10.0));
            if self.detected.serial_ports.is_empty() {
                ui.label(RichText::new("No serial ports detected").color(DIM).size(11.0));
            } else {
                let current = if self.selected_serial.is_empty() { "(Auto-detect)".into() } else { self.selected_serial.clone() };
                egui::ComboBox::from_id_salt("serial_dev")
                    .selected_text(RichText::new(&current).color(TEXT_BRIGHT).size(11.0)).width(350.0)
                    .show_ui(ui, |ui| {
                        if ui.selectable_label(self.selected_serial.is_empty(),
                            RichText::new("(Auto-detect)").color(TEXT_BRIGHT)).clicked() {
                            self.selected_serial.clear(); self.engine.set_usb_serial_port(String::new(), 115200);
                        }
                        for (path, desc) in &self.detected.serial_ports {
                            let lbl = format!("{} — {}", path, desc);
                            if ui.selectable_label(self.selected_serial == *path,
                                RichText::new(&lbl).color(TEXT_BRIGHT)).clicked() {
                                self.selected_serial = path.clone();
                                self.engine.set_usb_serial_port(path.clone(), 115200);
                            }
                        }
                    });
            }
            ui.add_space(12.0);

            // WiFi
            ui.label(RichText::new("WIFI INTERFACE").color(CYAN).size(10.0));
            if !self.detected.wifi_interfaces.is_empty() {
                let current = if self.selected_wifi.is_empty() { "(Auto-detect)".into() } else { self.selected_wifi.clone() };
                egui::ComboBox::from_id_salt("wifi_dev")
                    .selected_text(RichText::new(&current).color(TEXT_BRIGHT).size(11.0)).width(350.0)
                    .show_ui(ui, |ui| {
                        if ui.selectable_label(self.selected_wifi.is_empty(),
                            RichText::new("(Auto-detect)").color(TEXT_BRIGHT)).clicked() {
                            self.selected_wifi.clear(); self.engine.set_wifi_interface(String::new());
                        }
                        for iface in &self.detected.wifi_interfaces {
                            if ui.selectable_label(self.selected_wifi == *iface,
                                RichText::new(iface).color(TEXT_BRIGHT)).clicked() {
                                self.selected_wifi = iface.clone();
                                self.engine.set_wifi_interface(iface.clone());
                            }
                        }
                    });
            } else { ui.label(RichText::new("No WiFi interfaces detected").color(DIM).size(11.0)); }
            ui.add_space(12.0);

            // Bluetooth
            ui.label(RichText::new("BLUETOOTH").color(CYAN).size(10.0));
            if self.detected.bt_adapters.is_empty() {
                ui.label(RichText::new("No BT adapters detected").color(DIM).size(11.0));
            } else {
                for (name, addr) in &self.detected.bt_adapters {
                    let desc = if addr.is_empty() { name.clone() } else { format!("{} ({})", name, addr) };
                    ui.label(RichText::new(desc).color(TEXT_BRIGHT).size(11.0));
                }
            }
            ui.add_space(16.0); ui.separator();

            // GPU Info
            if let Some(ref m) = self.metrics {
                ui.label(RichText::new("GPU INFO").color(CYAN).size(10.0));
                if m.gpu_cuda_available {
                    ui.label(RichText::new(format!("CUDA: {} ✓", m.gpu_cuda_backend)).color(GREEN).size(11.0));
                }
                if m.gpu_ocl_available {
                    ui.label(RichText::new(format!("OpenCL: {} ✓", m.gpu_ocl_backend)).color(GREEN).size(11.0));
                }
                if m.gpu_cuda_available && m.gpu_ocl_available {
                    ui.label(RichText::new("Both GPUs can run simultaneously (independent threads)")
                        .color(DIM).size(9.0));
                }
                if !m.gpu_cuda_available && !m.gpu_ocl_available {
                    ui.label(RichText::new("No GPU detected (build with --features gpu-opencl or gpu-cuda)")
                        .color(DIM).size(9.0));
                }
                ui.add_space(12.0);
            }

            // Headscale Targets
            ui.label(RichText::new("HEADSCALE TARGETS").color(CYAN).size(10.0));
            if let Some(ref m) = self.metrics {
                for (i, hs) in m.headscale_targets.iter().enumerate() {
                    ui.horizontal(|ui| {
                        let (st, c) = if hs.reachable { ("●", GREEN) } else { ("○", DIM) };
                        ui.label(RichText::new(st).color(c).size(12.0));
                        ui.label(RichText::new(format!("{} — {}:{} (fwd:{})", hs.target.name, hs.target.ip, hs.target.port, hs.forwarded_count)).color(TEXT_BRIGHT).size(11.0));
                        if ui.small_button(RichText::new("✕").color(RED)).clicked() { self.engine.remove_headscale_target(i); }
                    });
                }
            }
            ui.horizontal(|ui| {
                ui.label(RichText::new("Name:").color(DIM).size(10.0));
                ui.add(egui::TextEdit::singleline(&mut self.new_hs_name).desired_width(100.0));
                ui.label(RichText::new("IP:").color(DIM).size(10.0));
                ui.add(egui::TextEdit::singleline(&mut self.new_hs_ip).desired_width(120.0));
                ui.label(RichText::new("Port:").color(DIM).size(10.0));
                ui.add(egui::TextEdit::singleline(&mut self.new_hs_port).desired_width(50.0));
                if ui.button(RichText::new("+ Add").color(GREEN).size(11.0)).clicked() {
                    let port: u16 = self.new_hs_port.parse().unwrap_or(8100);
                    if !self.new_hs_ip.is_empty() {
                        let name = if self.new_hs_name.is_empty() { format!("Node {}", self.new_hs_ip) } else { self.new_hs_name.clone() };
                        self.engine.add_headscale_target(name, self.new_hs_ip.clone(), port);
                        self.new_hs_name.clear(); self.new_hs_ip.clear(); self.new_hs_port = "8100".into();
                    }
                }
            });
            ui.add_space(12.0);

            // P2P
            ui.label(RichText::new("P2P MESH").color(CYAN).size(10.0));
            if let Some(ref m) = self.metrics {
                let mut p2p = m.p2p_active;
                if ui.checkbox(&mut p2p, RichText::new("P2P Enabled").color(TEXT_BRIGHT).size(11.0)).changed() { self.engine.toggle_p2p(p2p); }
                ui.label(RichText::new(format!("Received: {} | HMAC: {}", m.p2p_received, if m.p2p_hmac_enabled {"ON"} else {"OFF"})).color(DIM).size(10.0));
            }
            ui.horizontal(|ui| {
                ui.label(RichText::new("Add peer:").color(DIM).size(10.0));
                ui.add(egui::TextEdit::singleline(&mut self.new_peer_addr).desired_width(200.0));
                if ui.button("+").clicked() && !self.new_peer_addr.is_empty() { self.engine.add_peer(self.new_peer_addr.clone()); self.new_peer_addr.clear(); }
            });
            ui.horizontal(|ui| {
                ui.label(RichText::new("HMAC key (hex):").color(DIM).size(10.0));
                ui.add(egui::TextEdit::singleline(&mut self.new_hmac_key).desired_width(300.0));
                if ui.button("Set").clicked() && !self.new_hmac_key.is_empty() {
                    match self.engine.set_p2p_hmac_key(self.new_hmac_key.clone()) {
                        Ok(_) => { self.new_hmac_key.clear(); self.vault_status = "HMAC set!".into(); }
                        Err(e) => self.vault_status = format!("HMAC error: {}", e),
                    }
                }
            });
            ui.add_space(12.0);

            // Uplink
            ui.label(RichText::new("NETWORK UPLINK").color(CYAN).size(10.0));
            if let Some(ref m) = self.metrics {
                let mut net = m.net_mode;
                if ui.checkbox(&mut net, RichText::new("Uplink Enabled").color(TEXT_BRIGHT).size(11.0)).changed() { self.engine.toggle_uplink(net); }
            }
            ui.add_space(12.0);

            if ui.button(RichText::new("💾 Save Config to TOML").color(GREEN).size(12.0)).clicked() {
                self.engine.save_config(); self.vault_status = "Config saved!".into();
            }
            if !self.vault_status.is_empty() { ui.label(RichText::new(&self.vault_status).color(AMBER).size(10.0)); }
        });
    }

    fn draw_vault(&mut self, ui: &mut Ui) {
        ScrollArea::vertical().show(ui, |ui| {
            ui.label(RichText::new("ENCRYPTED VAULT").color(CYAN).size(10.0));
            ui.label(RichText::new("AES-256-GCM encrypted PQC key bundles").color(DIM).size(10.0));
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("Vault Password:").color(TEXT_BRIGHT).size(11.0));
                if self.vault_password_visible {
                    ui.add(egui::TextEdit::singleline(&mut self.vault_password).desired_width(250.0));
                } else {
                    ui.add(egui::TextEdit::singleline(&mut self.vault_password).password(true).desired_width(250.0));
                }
                if ui.button(if self.vault_password_visible {"🙈"} else {"👁"}).clicked() {
                    self.vault_password_visible = !self.vault_password_visible;
                }
            });
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button(RichText::new("⚿ Mint + Encrypt").color(CYAN).size(12.0)).clicked() {
                    if self.vault_password.is_empty() { self.vault_status = "Set vault password first".into(); }
                    else {
                        match self.engine.mint_pqc_bundle_encrypted(&self.vault_password) {
                            Ok(msg) => { self.vault_status = msg; self.vault_files = vault::list_vault_files("keys"); }
                            Err(e) => self.vault_status = format!("Error: {}", e),
                        }
                    }
                }
                // Also offer unencrypted mint for testing
                if ui.button(RichText::new("⚿ Mint (plaintext)").color(DIM).size(10.0)).clicked() {
                    match self.engine.mint_pqc_bundle("VAULT") {
                        Ok(msg) => { self.vault_status = msg; self.vault_files = vault::list_vault_files("keys"); }
                        Err(e) => self.vault_status = format!("Error: {}", e),
                    }
                }
                if ui.button(RichText::new("🔄 Refresh").color(MID).size(11.0)).clicked() { self.vault_files = vault::list_vault_files("keys"); }
            });

            // Push to Headscale
            if let Some(ref m) = self.metrics {
                let targets: Vec<_> = m.headscale_targets.iter().filter(|h| h.target.enabled).collect();
                if !targets.is_empty() {
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Push to:").color(DIM).size(10.0));
                        for hs in &targets {
                            if ui.button(RichText::new(format!("⇈ {}", hs.target.name)).color(GREEN).size(11.0)).clicked() {
                                self.vault_status = format!("Pushing to {}:{}...", hs.target.ip, hs.target.port);
                            }
                        }
                    });
                }
            }
            if !self.vault_status.is_empty() { ui.label(RichText::new(&self.vault_status).color(AMBER).size(10.0)); }
            ui.add_space(12.0);

            // Decrypt
            ui.label(RichText::new("DECRYPT & VIEW").color(MAGENTA).size(10.0));
            ui.horizontal(|ui| {
                ui.label(RichText::new("File:").color(DIM).size(10.0));
                ui.add(egui::TextEdit::singleline(&mut self.vault_decrypt_target).desired_width(300.0).hint_text("e.g. key_1234_abcd"));
                if ui.button(RichText::new("🔓 Decrypt").color(AMBER).size(11.0)).clicked() {
                    if self.vault_password.is_empty() { self.vault_decrypt_result = "Set password first".into(); }
                    else {
                        let path = std::path::PathBuf::from("keys").join(format!("{}.vault", self.vault_decrypt_target));
                        match vault::read_encrypted_bundle(&path, &self.vault_password) {
                            Ok(json) => self.vault_decrypt_result = if json.len() > 500 { format!("{}...", &json[..500]) } else { json },
                            Err(e) => self.vault_decrypt_result = format!("Error: {}", e),
                        }
                    }
                }
            });
            if !self.vault_decrypt_result.is_empty() {
                egui::Frame::none().fill(Color32::from_rgb(8,8,14)).rounding(4.0).inner_margin(6.0).show(ui, |ui| {
                    ui.label(RichText::new(&self.vault_decrypt_result).color(MID).size(9.0).monospace());
                });
            }
            ui.add_space(12.0);

            // File list
            ui.label(RichText::new("STORED BUNDLES").color(DIM).size(10.0));
            if self.vault_files.is_empty() { self.vault_files = vault::list_vault_files("keys"); }
            if self.vault_files.is_empty() {
                ui.label(RichText::new("No vault files yet. Mint some keys!").color(DIM).size(11.0));
            } else {
                egui::Frame::none().fill(Color32::from_rgb(8,8,14)).rounding(4.0).inner_margin(6.0).show(ui, |ui| {
                    for (name, size, modified) in &self.vault_files {
                        ui.horizontal(|ui| {
                            let icon = if name.contains("unencrypted") {"🔓"} else {"🔒"};
                            ui.label(RichText::new(icon).size(12.0));
                            ui.label(RichText::new(name).color(TEXT_BRIGHT).size(11.0));
                            ui.label(RichText::new(format!("{}B", size)).color(DIM).size(9.0));
                            ui.label(RichText::new(modified).color(DIM).size(9.0));
                        });
                    }
                });
            }
        });
    }
}

fn paint_dot(ui: &mut Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), 4.0, color);
}
fn health_dot_color(enabled: bool, health: &str) -> Color32 {
    match (enabled, health) {
        (true, "STEADY") => GREEN, (true, "STARTUP") => AMBER, (true, "FAILED") => RED,
        (true, _) => AMBER, (false, _) => Color32::from_rgb(50, 50, 50),
    }
}
fn stat_card(ui: &mut Ui, label: &str, value: &str, color: Color32) {
    egui::Frame::none().fill(BG_PANEL).rounding(4.0).inner_margin(8.0).show(ui, |ui| {
        ui.vertical(|ui| {
            ui.label(RichText::new(value).color(color).size(14.0).strong().monospace());
            ui.label(RichText::new(label).color(DIM).size(9.0));
        });
    });
}
fn format_bits(bits: f64) -> String {
    if bits >= 1_000_000.0 { format!("{:.1}M", bits / 1_000_000.0) }
    else if bits >= 1_000.0 { format!("{:.1}K", bits / 1_000.0) }
    else { format!("{:.0}", bits) }
}
fn count_active_sources(m: &MetricsSnapshot) -> usize {
    let h = &m.harvester_states;
    let mut c = 0;
    if h.trng {c+=1;} if h.audio {c+=1;} if h.system {c+=1;} if h.mouse {c+=1;}
    if h.video {c+=1;} if h.gpu_cuda {c+=1;} if h.gpu_ocl {c+=1;} if h.wifi {c+=1;}
    if h.usb_serial {c+=1;} if h.bt_passive {c+=1;} if h.bt_active {c+=1;}
    c += m.guitar_states.values().filter(|g| g.enabled).count();
    c
}
fn truncate_name(name: &str, max: usize) -> String {
    if name.len() <= max { name.to_string() } else { format!("{}…", &name[..max-1]) }
}
fn lerp_color(a: Color32, b: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    Color32::from_rgb(
        (a.r() as f32 * (1.0-t) + b.r() as f32 * t) as u8,
        (a.g() as f32 * (1.0-t) + b.g() as f32 * t) as u8,
        (a.b() as f32 * (1.0-t) + b.b() as f32 * t) as u8,
    )
}
