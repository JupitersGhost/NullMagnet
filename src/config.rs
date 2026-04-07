//! NullMagnet Live v2 - config.rs
//! Jupiter Labs - TOML configuration persistence + shared data structures
//!
//! Auto-saves settings when changed in GUI.
//! Auto-detects devices on first run.
//! All structs are shared across engine, GUI, and vault modules.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ============================================================================
// DEFAULT CONFIG PATH
// ============================================================================

pub fn config_path() -> PathBuf {
    // Look next to the binary first, fall back to current dir
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join("nullmagnet.toml");
            if p.exists() || !PathBuf::from("nullmagnet.toml").exists() {
                return p;
            }
        }
    }
    PathBuf::from("nullmagnet.toml")
}

// ============================================================================
// TOP-LEVEL CONFIG (serialized to TOML)
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NullMagnetConfig {
    #[serde(default)]
    pub general: GeneralConfig,

    #[serde(default)]
    pub sources: SourcesConfig,

    #[serde(default)]
    pub devices: DevicesConfig,

    #[serde(default)]
    pub pqc: PqcConfig,

    #[serde(default)]
    pub vault: VaultConfig,

    #[serde(default)]
    pub network: NetworkConfig,

    #[serde(default)]
    pub guitars: GuitarsConfig,
}

impl Default for NullMagnetConfig {
    fn default() -> Self {
        Self {
            general: GeneralConfig::default(),
            sources: SourcesConfig::default(),
            devices: DevicesConfig::default(),
            pqc: PqcConfig::default(),
            vault: VaultConfig::default(),
            network: NetworkConfig::default(),
            guitars: GuitarsConfig::default(),
        }
    }
}

impl NullMagnetConfig {
    /// Load config from disk, or create default if missing
    pub fn load() -> Self {
        let path = config_path();
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                toml::from_str(&contents).unwrap_or_else(|e| {
                    eprintln!("CONFIG: Parse error in {}: {} — using defaults", path.display(), e);
                    Self::default()
                })
            }
            Err(_) => {
                let cfg = Self::default();
                cfg.save(); // Create default config on first run
                cfg
            }
        }
    }

    /// Save config to disk
    pub fn save(&self) {
        let path = config_path();
        match toml::to_string_pretty(self) {
            Ok(contents) => {
                if let Err(e) = std::fs::write(&path, contents) {
                    eprintln!("CONFIG: Failed to save {}: {}", path.display(), e);
                }
            }
            Err(e) => {
                eprintln!("CONFIG: Serialization error: {}", e);
            }
        }
    }
}

// ============================================================================
// GENERAL SETTINGS
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// Start all safe harvesters on launch
    pub auto_start: bool,
    /// Polling interval for GUI metrics refresh (ms)
    pub gui_refresh_ms: u64,
    /// Waveform/graph update rate (FPS, 1-60)
    pub graph_fps: u32,
    /// Max log lines kept in memory
    pub max_log_lines: usize,
    /// Keys output directory
    pub keys_dir: String,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            auto_start: false,
            gui_refresh_ms: 250,
            graph_fps: 4,
            max_log_lines: 500,
            keys_dir: "keys".to_string(),
        }
    }
}

// ============================================================================
// ENTROPY SOURCE ENABLE/DISABLE
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourcesConfig {
    pub trng: bool,
    pub audio: bool,
    pub system: bool,
    pub mouse: bool,
    pub video: bool,
    pub gpu_cuda: bool,
    pub gpu_opencl: bool,
    pub wifi: bool,
    pub usb_serial: bool,
    pub bt_passive: bool,
    pub bt_active: bool,
}

impl Default for SourcesConfig {
    fn default() -> Self {
        Self {
            trng: false,
            audio: false,
            system: false,
            mouse: false,
            video: false,
            gpu_cuda: false,
            gpu_opencl: false,
            wifi: false,
            usb_serial: false,
            bt_passive: false,
            bt_active: false,
        }
    }
}

// ============================================================================
// DEVICE CONFIGURATION (dropdowns in GUI)
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DevicesConfig {
    /// Selected audio input device name (empty = default)
    pub audio_device: String,
    /// Audio input gain multiplier
    pub audio_gain: f64,

    /// Selected camera device name (empty = default, supports multiple)
    pub camera_device: String,
    /// Additional camera devices (multi-cam support)
    pub extra_cameras: Vec<String>,

    /// USB serial port path (empty = auto-detect)
    pub usb_serial_port: String,
    /// USB serial baud rate
    pub usb_serial_baud: u32,
    /// Additional USB serial ports (multi-device)
    pub extra_serial_ports: Vec<String>,

    /// WiFi interface name (empty = auto-detect)
    pub wifi_interface: String,

    /// OpenCL platform index (0 = auto)
    pub opencl_platform: usize,
    /// OpenCL device index (0 = auto)
    pub opencl_device: usize,
}

impl Default for DevicesConfig {
    fn default() -> Self {
        Self {
            audio_device: String::new(),
            audio_gain: 1.0,
            camera_device: String::new(),
            extra_cameras: Vec::new(),
            usb_serial_port: String::new(),
            usb_serial_baud: 115200,
            extra_serial_ports: Vec::new(),
            wifi_interface: String::new(),
            opencl_platform: 0,
            opencl_device: 0,
        }
    }
}

// ============================================================================
// PQC KEY GENERATION CONFIG
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqcConfig {
    /// Auto-mint keys when entropy threshold is met
    pub auto_mint: bool,
    /// Minimum credited entropy bits before minting
    pub min_entropy_bits: f64,
    /// ML-KEM parameter set: 512, 768, or 1024
    pub mlkem_parameter: u16,
}

impl Default for PqcConfig {
    fn default() -> Self {
        Self {
            auto_mint: false,
            min_entropy_bits: 256.0,
            mlkem_parameter: 1024,
        }
    }
}

// ============================================================================
// VAULT CONFIG (local encrypted storage + Headscale targets)
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultConfig {
    /// Local vault directory
    pub vault_dir: String,
    /// Vault encryption password hint (NOT the password itself)
    pub password_hint: String,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            vault_dir: "keys".to_string(),
            password_hint: String::new(),
        }
    }
}

// ============================================================================
// NETWORK CONFIG (Headscale targets, P2P, uplink)
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeadscaleTarget {
    pub name: String,
    pub ip: String,
    pub port: u16,
    pub enabled: bool,
}

impl Default for HeadscaleTarget {
    fn default() -> Self {
        Self {
            name: "Vault Node".to_string(),
            ip: "127.0.0.1".to_string(),
            port: 8100,
            enabled: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Headscale vault targets (you can add multiple)
    pub headscale_targets: Vec<HeadscaleTarget>,

    /// P2P mesh
    pub p2p_enabled: bool,
    pub p2p_port: u16,
    pub p2p_peers: Vec<String>,
    pub p2p_hmac_key_hex: String,

    /// General uplink
    pub uplink_enabled: bool,
    pub uplink_url: String,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            headscale_targets: vec![HeadscaleTarget::default()],
            p2p_enabled: false,
            p2p_port: 9000,
            p2p_peers: Vec::new(),
            p2p_hmac_key_hex: String::new(),
            uplink_enabled: false,
            uplink_url: "http://127.0.0.1:8000/ingest".to_string(),
        }
    }
}

// ============================================================================
// GUITAR ESP32 CONFIG
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuitarEntry {
    pub name: String,
    pub data_port: u16,
    pub ctrl_port: u16,
    pub enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuitarsConfig {
    pub guitars: Vec<GuitarEntry>,
}

impl Default for GuitarsConfig {
    fn default() -> Self {
        Self {
            guitars: vec![
                GuitarEntry { name: "Spectra".into(),   data_port: 5005, ctrl_port: 5056, enabled: true },
                GuitarEntry { name: "Neptonius".into(), data_port: 5006, ctrl_port: 5057, enabled: true },
                GuitarEntry { name: "Thalyn".into(),    data_port: 5007, ctrl_port: 5058, enabled: true },
                GuitarEntry { name: "Sylvia".into(),    data_port: 5009, ctrl_port: 5060, enabled: true },
                // Nocturnus — ports TBD, uncomment when assigned:
                // GuitarEntry { name: "Nocturnus".into(), data_port: 0, ctrl_port: 0, enabled: false },
            ],
        }
    }
}

// ============================================================================
// RUNTIME STATE (not persisted — lives only in memory)
// These are the live metrics/state that the GUI reads every frame
// ============================================================================

#[derive(Clone, Debug, Default)]
pub struct SourceMetrics {
    pub raw_shannon: f64,
    pub min_entropy: f64,
    pub samples: u64,
    pub avg_raw_entropy: f64,
    pub total_bits_contributed: f64,
    pub health_state: String,
}

#[derive(Clone, Debug)]
pub struct GuitarState {
    pub name: String,
    pub data_port: u16,
    pub ctrl_port: u16,
    pub enabled: bool,
    pub packets_received: u64,
    pub bytes_received: u64,
}

/// Runtime harvester enable states (mirrors SourcesConfig but mutable at runtime)
#[derive(Clone, Debug)]
pub struct HarvesterStates {
    pub trng: bool,
    pub audio: bool,
    pub system: bool,
    pub mouse: bool,
    pub video: bool,
    pub gpu_cuda: bool,
    pub gpu_ocl: bool,
    pub wifi: bool,
    pub usb_serial: bool,
    pub bt_passive: bool,
    pub bt_active: bool,
}

impl Default for HarvesterStates {
    fn default() -> Self {
        Self {
            trng: false,
            audio: false,
            system: false,
            mouse: false,
            video: false,
            gpu_cuda: false,
            gpu_ocl: false,
            wifi: false,
            usb_serial: false,
            bt_passive: false,
            bt_active: false,
        }
    }
}

impl HarvesterStates {
    /// Sync from persisted config
    pub fn from_config(cfg: &SourcesConfig) -> Self {
        Self {
            trng: cfg.trng,
            audio: cfg.audio,
            system: cfg.system,
            mouse: cfg.mouse,
            video: cfg.video,
            gpu_cuda: cfg.gpu_cuda,
            gpu_ocl: cfg.gpu_opencl,
            wifi: cfg.wifi,
            usb_serial: cfg.usb_serial,
            bt_passive: cfg.bt_passive,
            bt_active: cfg.bt_active,
        }
    }

    /// Sync back to config for saving
    pub fn to_config(&self) -> SourcesConfig {
        SourcesConfig {
            trng: self.trng,
            audio: self.audio,
            system: self.system,
            mouse: self.mouse,
            video: self.video,
            gpu_cuda: self.gpu_cuda,
            gpu_opencl: self.gpu_ocl,
            wifi: self.wifi,
            usb_serial: self.usb_serial,
            bt_passive: self.bt_passive,
            bt_active: self.bt_active,
        }
    }
}

// ============================================================================
// DETECTED DEVICES (populated at startup by auto-detection)
// ============================================================================

#[derive(Clone, Debug, Default)]
pub struct DetectedDevices {
    /// Audio input devices: (index, name)
    pub audio_inputs: Vec<(usize, String)>,
    /// Camera devices: (index, name)
    pub cameras: Vec<(usize, String)>,
    /// USB serial ports: (path, description)
    pub serial_ports: Vec<(String, String)>,
    /// WiFi interfaces: name
    pub wifi_interfaces: Vec<String>,
    /// OpenCL devices: (platform_idx, device_idx, name, type)
    pub opencl_devices: Vec<(usize, usize, String, String)>,
    /// Bluetooth adapters: (name, address)
    pub bt_adapters: Vec<(String, String)>,
    /// GPU CUDA available
    pub cuda_available: bool,
    pub cuda_backend: String,
    /// GPU OpenCL available
    pub opencl_available: bool,
    pub opencl_backend: String,
}

/// Auto-detect all available devices on the system
pub fn detect_devices() -> DetectedDevices {
    let mut detected = DetectedDevices::default();

    // --- Audio inputs ---
    {
        use cpal::traits::{DeviceTrait, HostTrait};
        let host = cpal::default_host();
        if let Ok(devices) = host.input_devices() {
            for (i, device) in devices.enumerate() {
                let name = device.name().unwrap_or_else(|_| format!("Audio Input {}", i));
                detected.audio_inputs.push((i, name));
            }
        }
    }

    // --- Cameras ---
    {
        // Use nokhwa::query() for real device names (Windows: Media Foundation, Linux: V4L2)
        match nokhwa::query(nokhwa::utils::ApiBackend::Auto) {
            Ok(cameras) => {
                for info in cameras {
                    let idx = match info.index() {
                        nokhwa::utils::CameraIndex::Index(i) => *i as usize,
                        nokhwa::utils::CameraIndex::String(s) => {
                            // Some backends return string IDs — use hash as index
                            s.len() % 256
                        }
                    };
                    let name = info.human_name().to_string();
                    let name = if name.is_empty() {
                        format!("Camera {}", idx)
                    } else {
                        name
                    };
                    detected.cameras.push((idx, name));
                }
            }
            Err(_) => {
                // Fallback: probe first 4 camera indices
                use nokhwa::utils::CameraIndex;
                use nokhwa::pixel_format::RgbFormat;
                use nokhwa::utils::{RequestedFormat, RequestedFormatType};
                for i in 0..4u32 {
                    let index = CameraIndex::Index(i);
                    let format = RequestedFormat::new::<RgbFormat>(RequestedFormatType::AbsoluteHighestFrameRate);
                    if nokhwa::Camera::new(index, format).is_ok() {
                        detected.cameras.push((i as usize, format!("Camera {}", i)));
                    }
                }
            }
        }
    }

    // --- Serial ports ---
    {
        if let Ok(ports) = serialport::available_ports() {
            for port in ports {
                let desc = match &port.port_type {
                    serialport::SerialPortType::UsbPort(info) => {
                        format!("{} ({})",
                            info.product.as_deref().unwrap_or("USB Serial"),
                            info.manufacturer.as_deref().unwrap_or("Unknown"))
                    }
                    _ => "Serial Port".to_string(),
                };
                detected.serial_ports.push((port.port_name, desc));
            }
        }
    }

    // --- WiFi interfaces ---
    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy().to_string();
                let wireless_path = format!("/sys/class/net/{}/wireless", name_str);
                if std::path::Path::new(&wireless_path).exists() {
                    detected.wifi_interfaces.push(name_str);
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Parse `netsh wlan show interfaces` for interface names
        if let Ok(output) = std::process::Command::new("netsh")
            .args(&["wlan", "show", "interfaces"])
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("Name") {
                    if let Some(name) = trimmed.split(':').nth(1) {
                        detected.wifi_interfaces.push(name.trim().to_string());
                    }
                }
            }
        }
        // If nothing found, add a generic entry so the UI doesn't look empty
        if detected.wifi_interfaces.is_empty() {
            detected.wifi_interfaces.push("Wi-Fi".to_string());
        }
    }

    // --- Bluetooth adapters ---
    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/sys/class/bluetooth") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                let addr_path = format!("/sys/class/bluetooth/{}/address", name);
                let addr = std::fs::read_to_string(&addr_path)
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                detected.bt_adapters.push((name, addr));
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Check for BT radio via PowerShell (lightweight check)
        if let Ok(output) = std::process::Command::new("powershell")
            .args(&["-Command", "Get-PnpDevice -Class Bluetooth -Status OK | Select-Object -First 3 -ExpandProperty FriendlyName"])
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                let name = line.trim().to_string();
                if !name.is_empty() {
                    detected.bt_adapters.push((name, String::new()));
                }
            }
        }
    }

    detected
}
