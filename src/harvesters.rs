//! NullMagnet Live v2 - harvesters.rs
//! Jupiter Labs - All entropy harvester threads
//!
//! Each harvester runs in its own thread, performs NIST health testing
//! locally, and sends passed samples to the mixer via crossbeam channel.
//!
//! Harvesters:
//!   Standard:  TRNG, Audio, System, Mouse, Video
//!   GPU:       CUDA (independent thread), OpenCL (independent thread)
//!   Live:      Guitar ESP32 UDP (Spectra, Neptonius, Thalyn, Sylvia)
//!   Extended:  WiFi noise, USB serial, Bluetooth (passive + active RSSI)
//!   Network:   P2P server (HMAC auth), Headscale forwarder

use std::sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}};
use parking_lot::Mutex;
use crossbeam_channel::Sender;
use std::thread;
use std::time::{Duration, Instant};
use sha2::Digest as Sha2Digest;
use sha3::Sha3_256;
use hmac::Mac;

use crate::engine::{SharedState, HmacSha256};
use crate::entropy::{
    NistHealthTester,
    get_timestamp, get_timestamp_nanos,
};

// ============================================================================
// HELPER: Log to engine console (visible in GUI)
// ============================================================================

fn log_to_engine(state: &Arc<Mutex<SharedState>>, msg: &str) {
    if let Some(mut lock) = state.try_lock() {
        let ts = chrono::Local::now().format("%H:%M:%S").to_string();
        let full = format!("[{}] {}", ts, msg);
        if lock.logs.len() >= 500 { lock.logs.pop_front(); }
        lock.logs.push_back(full);
    }
    // Also print to stderr for terminal debugging
    eprintln!("{}", msg);
}

// ============================================================================
// GPU ENTROPY - CUDA (NVIDIA) - Independent Thread
// ============================================================================

#[cfg(feature = "gpu-cuda")]
mod cuda_entropy {
    pub fn harvest_cuda(size: usize) -> Option<Vec<u8>> {
        use cudarc::driver::{CudaDevice, LaunchAsync, LaunchConfig};

        const KERNEL: &str = r#"
            extern "C" __global__ void race_entropy(int *out, int n, int iters) {
                __shared__ int s[256];
                int t = threadIdx.x;
                s[t % 256] = 0;
                __syncthreads();
                for (int i = 0; i < iters; i++) {
                    s[(t + i) % 256] += t;
                    s[(t + i) % 256] ^= (i * 37);
                    __threadfence_block();
                }
                __syncthreads();
                if (t < n) out[t] = s[t % 256] ^ (t * 0x9E3779B9);
            }
        "#;

        let device = CudaDevice::new(0).ok()?;
        let ptx = cudarc::nvrtc::compile_ptx(KERNEL).ok()?;
        device.load_ptx(ptx, "entropy", &["race_entropy"]).ok()?;

        let mut output = device.alloc_zeros::<i32>(size).ok()?;

        let cfg = LaunchConfig {
            block_dim: (256, 1, 1),
            grid_dim: (((size as u32) + 255) / 256, 1, 1),
            shared_mem_bytes: 1024,
        };

        unsafe {
            let f = device.get_func("entropy", "race_entropy")?;
            f.launch(cfg, (&mut output, size as i32, 100i32)).ok()?;
        }

        device.synchronize().ok()?;
        let host = device.dtoh_sync_copy(&output).ok()?;

        let bytes: Vec<u8> = host.iter()
            .flat_map(|&x| [(x & 0xFF) as u8, ((x >> 8) & 0xFF) as u8])
            .take(size)
            .collect();

        Some(bytes)
    }

    pub fn is_available() -> bool {
        cudarc::driver::CudaDevice::new(0).is_ok()
    }
}

// ============================================================================
// GPU ENTROPY - OpenCL (AMD/Intel/NVIDIA)
// ============================================================================

#[cfg(feature = "gpu-opencl")]
mod opencl_entropy {
    use ocl::{Buffer, Context, Device, DeviceType, Kernel, Platform, Program, Queue};

    pub fn enumerate_devices() -> Vec<(usize, usize, String, String)> {
        let mut results = Vec::new();
        let platforms = Platform::list();
        for (pi, platform) in platforms.iter().enumerate() {
            let devices = Device::list(*platform, Some(DeviceType::GPU))
                .or_else(|_| Device::list(*platform, Some(DeviceType::ALL)))
                .unwrap_or_default();
            for (di, device) in devices.iter().enumerate() {
                let name = device.name().unwrap_or_else(|_| "Unknown".into());
                let dtype = device.info(ocl::enums::DeviceInfo::Type)
                    .map(|v| format!("{:?}", v))
                    .unwrap_or_else(|_| "Unknown".into());
                results.push((pi, di, name, dtype));
            }
        }
        results
    }

    pub fn get_device(platform_idx: usize, device_idx: usize) -> Option<(Platform, Device)> {
        let platforms = Platform::list();
        if platforms.is_empty() { return None; }

        if let Some(platform) = platforms.get(platform_idx) {
            let devices = Device::list(*platform, Some(DeviceType::GPU))
                .or_else(|_| Device::list(*platform, Some(DeviceType::ALL)))
                .unwrap_or_default();
            if let Some(device) = devices.get(device_idx) {
                return Some((*platform, *device));
            }
        }

        for platform in &platforms {
            if let Ok(devices) = Device::list(*platform, Some(DeviceType::GPU)) {
                if let Some(device) = devices.first() {
                    return Some((*platform, *device));
                }
            }
        }

        for platform in &platforms {
            if let Ok(devices) = Device::list(*platform, Some(DeviceType::ALL)) {
                if let Some(device) = devices.first() {
                    return Some((*platform, *device));
                }
            }
        }

        None
    }

    fn safe_local_work_size(device: &Device) -> usize {
        device.max_wg_size().unwrap_or(64).min(256)
    }

    pub fn harvest_opencl(size: usize, platform_idx: usize, device_idx: usize) -> Option<Vec<u8>> {
        let (platform, device) = get_device(platform_idx, device_idx)?;
        let local_size = safe_local_work_size(&device);

        const KERNEL: &str = r#"
            __kernel void race_entropy(__global int *out, int n, int iters) {
                __local int s[256];
                int t = get_local_id(0);
                int g = get_global_id(0);
                int ls = get_local_size(0);
                s[t % ls] = 0;
                barrier(CLK_LOCAL_MEM_FENCE);
                for (int i = 0; i < iters; i++) {
                    s[(t + i) % ls] += t;
                    s[(t + i) % ls] ^= (i * 37);
                    mem_fence(CLK_LOCAL_MEM_FENCE);
                }
                barrier(CLK_LOCAL_MEM_FENCE);
                if (g < n) out[g] = s[t % ls] ^ (t * 0x9E3779B9);
            }
        "#;

        let context = Context::builder().platform(platform).devices(device).build().ok()?;
        let queue = Queue::new(&context, device, None).ok()?;
        let program = Program::builder().src(KERNEL).devices(device).build(&context).ok()?;
        let buffer = Buffer::<i32>::builder().queue(queue.clone()).len(size).build().ok()?;
        let global_size = ((size + local_size - 1) / local_size) * local_size;

        let kernel = Kernel::builder()
            .program(&program)
            .name("race_entropy")
            .queue(queue.clone())
            .global_work_size(global_size)
            .local_work_size(local_size)
            .arg(&buffer)
            .arg(size as i32)
            .arg(100i32)
            .build().ok()?;

        unsafe { kernel.enq().ok()?; }

        let mut host = vec![0i32; size];
        buffer.read(&mut host).enq().ok()?;
        queue.finish().ok()?;

        let bytes: Vec<u8> = host.iter()
            .flat_map(|&x| [(x & 0xFF) as u8, ((x >> 8) & 0xFF) as u8])
            .take(size)
            .collect();

        Some(bytes)
    }

    pub fn is_available() -> bool {
        get_device(0, 0).is_some()
    }

    pub fn device_info(platform_idx: usize, device_idx: usize) -> String {
        match get_device(platform_idx, device_idx) {
            Some((_plat, dev)) => {
                let name = dev.name().unwrap_or_else(|_| "Unknown".into());
                let max_wg = dev.max_wg_size().unwrap_or(0);
                let max_cu = dev.info(ocl::enums::DeviceInfo::MaxComputeUnits)
                    .map(|v| format!("{}", v))
                    .unwrap_or_else(|_| "?".into());
                format!("{} (CUs:{}, MaxWG:{})", name, max_cu, max_wg)
            }
            None => "No OpenCL device".to_string(),
        }
    }
}

// ============================================================================
// GPU DETECTION
// ============================================================================

pub fn detect_gpu_cuda() -> (bool, String) {
    #[cfg(feature = "gpu-cuda")]
    {
        if cuda_entropy::is_available() {
            return (true, "CUDA (NVIDIA)".to_string());
        }
    }
    (false, "None".to_string())
}

pub fn detect_gpu_opencl() -> (bool, String) {
    #[cfg(feature = "gpu-opencl")]
    {
        if opencl_entropy::is_available() {
            let info = opencl_entropy::device_info(0, 0);
            return (true, format!("OpenCL: {}", info));
        }
    }
    (false, "None".to_string())
}

pub fn enumerate_opencl_devices() -> Vec<(usize, usize, String, String)> {
    #[cfg(feature = "gpu-opencl")]
    {
        return opencl_entropy::enumerate_devices();
    }
    #[cfg(not(feature = "gpu-opencl"))]
    {
        return Vec::new();
    }
}

// ============================================================================
// TRNG (OS Random Number Generator)
// ============================================================================

pub fn start_trng_harvester(
    tx: Sender<(String, Vec<u8>)>,
    running: Arc<AtomicBool>,
    state: Arc<Mutex<SharedState>>,
) {
    thread::spawn(move || {
        use rand::prelude::*;
        let mut rng = rand::rngs::OsRng;
        let mut health_tester = NistHealthTester::new();
        health_tester.start();

        while running.load(Ordering::Relaxed) {
            let enabled = state.try_lock()
                .map(|l| l.harvester_states.trng)
                .unwrap_or(false);
            if enabled {
                let mut buf = [0u8; 1024];
                rng.fill_bytes(&mut buf);

                let passed = health_tester.process_batch(&buf);
                if !passed.is_empty() {
                    let _ = tx.try_send(("TRNG".to_string(), passed));
                }

                if let Some(mut lock) = state.try_lock() {
                    let metrics = lock.source_metrics.entry("TRNG".to_string()).or_default();
                    metrics.health_state = health_tester.state_name().to_string();
                }
            }
            thread::sleep(Duration::from_secs(1));
        }
    });
}

// ============================================================================
// AUDIO (Microphone ADC Noise)
// Logs failures to engine log console so you can see what went wrong.
// Supports device selection via audio_device_index in SharedState.
// Handles f32, i16, u16 sample formats (Windows WASAPI may use i16).
// ============================================================================

pub fn start_audio_harvester(
    tx: Sender<(String, Vec<u8>)>,
    running: Arc<AtomicBool>,
    state: Arc<Mutex<SharedState>>,
) {
    thread::spawn(move || {
        use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
        use cpal::SampleFormat;

        let host = cpal::default_host();

        // Try selected device, fall back to default
        let device_idx = state.lock().audio_device_index;
        let device = if let Some(idx) = device_idx {
            match host.input_devices() {
                Ok(mut devices) => devices.nth(idx).or_else(|| {
                    log_to_engine(&state, &format!("AUDIO: Device index {} not found, using default", idx));
                    host.default_input_device()
                }),
                Err(_) => host.default_input_device(),
            }
        } else {
            host.default_input_device()
        };

        let device = match device {
            Some(d) => d,
            None => {
                log_to_engine(&state, "AUDIO: No input device found — check system audio settings");
                return;
            }
        };

        let device_name = device.name().unwrap_or_else(|_| "Unknown".into());
        log_to_engine(&state, &format!("AUDIO: Using device: {}", device_name));

        let supported_config = match device.default_input_config() {
            Ok(c) => c,
            Err(e) => {
                log_to_engine(&state, &format!("AUDIO: Config error on {}: {}", device_name, e));
                return;
            }
        };

        let sample_format = supported_config.sample_format();
        let config: cpal::StreamConfig = supported_config.into();

        log_to_engine(&state, &format!("AUDIO: {}ch, {}Hz, {:?}",
            config.channels, config.sample_rate.0, sample_format));

        // Shared state for the callback (all Arc'd for thread safety)
        let audio_enabled = Arc::new(AtomicBool::new(false));
        use std::sync::atomic::AtomicU64;
        let gain_bits = Arc::new(AtomicU64::new(1.0f64.to_bits()));
        let last_send = Arc::new(Mutex::new(Instant::now()));
        let health_tester = Arc::new(Mutex::new({
            let mut h = NistHealthTester::new();
            h.start();
            h
        }));

        // Poller thread: syncs enabled + gain from SharedState
        {
            let state_poll = state.clone();
            let running_poll = running.clone();
            let enabled_poll = audio_enabled.clone();
            let gain_poll = gain_bits.clone();
            thread::spawn(move || {
                while running_poll.load(Ordering::Relaxed) {
                    if let Some(lock) = state_poll.try_lock() {
                        enabled_poll.store(lock.harvester_states.audio, Ordering::Relaxed);
                        gain_poll.store(lock.audio_gain.to_bits(), Ordering::Relaxed);
                    }
                    thread::sleep(Duration::from_millis(200));
                }
            });
        }

        // Helper: process raw audio bytes (shared logic for all sample formats)
        fn process_bytes(
            raw: Vec<u8>,
            running: &AtomicBool,
            enabled: &AtomicBool,
            last_send: &Mutex<Instant>,
            health: &Mutex<NistHealthTester>,
            tx: &Sender<(String, Vec<u8>)>,
            state: &Mutex<SharedState>,
        ) {
            if !running.load(Ordering::Relaxed) || !enabled.load(Ordering::Relaxed) { return; }
            let mut last = match last_send.try_lock() { Some(l) => l, None => return };
            if last.elapsed() < Duration::from_millis(200) { return; }
            *last = Instant::now();
            drop(last);

            let mut bytes = raw;
            bytes.extend_from_slice(&get_timestamp_nanos().to_le_bytes());

            if let Some(mut ht) = health.try_lock() {
                let passed = ht.process_batch(&bytes);
                if !passed.is_empty() {
                    let _ = tx.try_send(("AUDIO".to_string(), passed));
                }
                if let Some(mut lock) = state.try_lock() {
                    let m = lock.source_metrics.entry("AUDIO".to_string()).or_default();
                    m.health_state = ht.state_name().to_string();
                }
            }
        }

        // Build stream — each format gets its own closure with cloned Arcs
        let stream_result = match sample_format {
            SampleFormat::F32 => {
                let r = running.clone(); let e = audio_enabled.clone();
                let l = last_send.clone(); let h = health_tester.clone();
                let t = tx.clone(); let s = state.clone(); let g = gain_bits.clone();
                device.build_input_stream(&config,
                    move |data: &[f32], _: &_| {
                        let gain = f64::from_bits(g.load(Ordering::Relaxed)) as f32;
                        let bytes: Vec<u8> = data.iter().take(256).step_by(2)
                            .map(|&s| ((s * gain).to_bits() & 0xFF) as u8).collect();
                        process_bytes(bytes, &r, &e, &l, &h, &t, &s);
                    },
                    move |err| { eprintln!("AUDIO stream error: {}", err); },
                    None,
                )
            }
            SampleFormat::I16 => {
                let r = running.clone(); let e = audio_enabled.clone();
                let l = last_send.clone(); let h = health_tester.clone();
                let t = tx.clone(); let s = state.clone();
                device.build_input_stream(&config,
                    move |data: &[i16], _: &_| {
                        let bytes: Vec<u8> = data.iter().take(256).step_by(2)
                            .map(|&s| (s as u16 & 0xFF) as u8).collect();
                        process_bytes(bytes, &r, &e, &l, &h, &t, &s);
                    },
                    move |err| { eprintln!("AUDIO stream error: {}", err); },
                    None,
                )
            }
            SampleFormat::U16 => {
                let r = running.clone(); let e = audio_enabled.clone();
                let l = last_send.clone(); let h = health_tester.clone();
                let t = tx.clone(); let s = state.clone();
                device.build_input_stream(&config,
                    move |data: &[u16], _: &_| {
                        let bytes: Vec<u8> = data.iter().take(256).step_by(2)
                            .map(|&s| (s & 0xFF) as u8).collect();
                        process_bytes(bytes, &r, &e, &l, &h, &t, &s);
                    },
                    move |err| { eprintln!("AUDIO stream error: {}", err); },
                    None,
                )
            }
            other => {
                log_to_engine(&state, &format!("AUDIO: Unsupported format: {:?}", other));
                return;
            }
        };

        match stream_result {
            Ok(s) => match s.play() {
                Ok(_) => {
                    log_to_engine(&state, &format!("AUDIO: ✓ Streaming from {}", device_name));
                    while running.load(Ordering::Relaxed) {
                        thread::sleep(Duration::from_secs(1));
                    }
                }
                Err(e) => log_to_engine(&state, &format!("AUDIO: Play failed: {}", e)),
            },
            Err(e) => log_to_engine(&state, &format!("AUDIO: Build stream failed: {}", e)),
        }
    });
}

// ============================================================================
// SYSTEM (CPU / Memory Stats)
// ============================================================================

pub fn start_system_harvester(
    tx: Sender<(String, Vec<u8>)>,
    running: Arc<AtomicBool>,
    state: Arc<Mutex<SharedState>>,
) {
    thread::spawn(move || {
        use sysinfo::{System, RefreshKind, CpuRefreshKind, MemoryRefreshKind};

        let mut sys = System::new_with_specifics(
            RefreshKind::new()
                .with_cpu(CpuRefreshKind::everything())
                .with_memory(MemoryRefreshKind::everything())
        );

        let mut health_tester = NistHealthTester::new();
        health_tester.start();

        sys.refresh_cpu_usage();
        thread::sleep(Duration::from_millis(300));

        while running.load(Ordering::Relaxed) {
            let enabled = state.try_lock()
                .map(|l| l.harvester_states.system)
                .unwrap_or(false);
            if enabled {
                sys.refresh_cpu_usage();
                sys.refresh_memory();

                let mut raw_bytes = Vec::with_capacity(256);
                for cpu in sys.cpus() {
                    let usage_bits = cpu.cpu_usage().to_bits();
                    let freq = cpu.frequency();
                    raw_bytes.extend_from_slice(&usage_bits.to_le_bytes());
                    raw_bytes.extend_from_slice(&freq.to_le_bytes());
                }

                let nanos = get_timestamp_nanos();
                raw_bytes.extend_from_slice(&nanos.to_le_bytes());
                raw_bytes.extend_from_slice(&sys.used_memory().to_le_bytes());
                raw_bytes.extend_from_slice(&sys.available_memory().to_le_bytes());

                if raw_bytes.len() > 16 {
                    let passed = health_tester.process_batch(&raw_bytes);
                    if !passed.is_empty() {
                        let _ = tx.try_send(("SYSTEM".to_string(), passed));
                    }
                }

                if let Some(mut lock) = state.try_lock() {
                    let metrics = lock.source_metrics.entry("SYSTEM".to_string()).or_default();
                    metrics.health_state = health_tester.state_name().to_string();
                }
            }
            thread::sleep(Duration::from_millis(500));
        }
    });
}

// ============================================================================
// MOUSE / HID (Timing Jitter) — Lazy-Start
// ============================================================================

pub fn start_mouse_harvester(
    tx: Sender<(String, Vec<u8>)>,
    running: Arc<AtomicBool>,
    state: Arc<Mutex<SharedState>>,
) {
    let mouse_enabled = Arc::new(AtomicBool::new(true));
    let mouse_enabled_hook = mouse_enabled.clone();

    let mouse_enabled_poll = mouse_enabled.clone();
    let state_poll = state.clone();
    let running_poll = running.clone();
    thread::spawn(move || {
        while running_poll.load(Ordering::Relaxed) {
            if let Some(lock) = state_poll.try_lock() {
                mouse_enabled_poll.store(lock.harvester_states.mouse, Ordering::Relaxed);
            }
            thread::sleep(Duration::from_millis(200));
        }
    });

    thread::spawn(move || {
        use rdev::{listen, EventType};

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        let last_nanos = Arc::new(AtomicUsize::new(0));
        let last_nanos_clone = last_nanos.clone();
        let health_tester = Arc::new(Mutex::new({
            let mut h = NistHealthTester::new();
            h.start();
            h
        }));
        let ht_clone = health_tester.clone();

        let callback = move |event: rdev::Event| {
            if !running.load(Ordering::Relaxed) { return; }
            if !mouse_enabled_hook.load(Ordering::Relaxed) { return; }

            match event.event_type {
                EventType::MouseMove { x, y } => {
                    let count = counter_clone.fetch_add(1, Ordering::Relaxed);
                    if count % 50 != 0 { return; }

                    let now_nanos = get_timestamp_nanos() as usize;
                    let prev = last_nanos_clone.swap(now_nanos, Ordering::Relaxed);
                    let delta = now_nanos.wrapping_sub(prev) as u64;

                    let mut payload = Vec::with_capacity(24);
                    payload.extend_from_slice(&(x as f64).to_bits().to_le_bytes());
                    payload.extend_from_slice(&(y as f64).to_bits().to_le_bytes());
                    payload.extend_from_slice(&delta.to_le_bytes());

                    if let Some(mut ht) = ht_clone.try_lock() {
                        let passed = ht.process_batch(&payload);
                        if !passed.is_empty() {
                            let _ = tx.try_send(("MOUSE".to_string(), passed));
                        }
                    }
                }
                EventType::ButtonPress(_) => {
                    let now_nanos = get_timestamp_nanos() as usize;
                    let prev = last_nanos_clone.swap(now_nanos, Ordering::Relaxed);
                    let delta = now_nanos.wrapping_sub(prev) as u64;

                    let mut payload = Vec::with_capacity(16);
                    payload.extend_from_slice(&delta.to_le_bytes());
                    payload.extend_from_slice(&(now_nanos as u64).to_le_bytes());

                    if let Some(mut ht) = ht_clone.try_lock() {
                        let passed = ht.process_batch(&payload);
                        if !passed.is_empty() {
                            let _ = tx.try_send(("MOUSE_CLK".to_string(), passed));
                        }
                    }
                }
                _ => {}
            }
        };

        let _ = listen(callback);
    });
}

// ============================================================================
// VIDEO (Camera Noise) — with fallback detection and logging
// ============================================================================

pub fn start_video_harvester(
    tx: Sender<(String, Vec<u8>)>,
    running: Arc<AtomicBool>,
    state: Arc<Mutex<SharedState>>,
) {
    thread::spawn(move || {
        use nokhwa::pixel_format::RgbFormat;
        use nokhwa::utils::{CameraIndex, RequestedFormat, RequestedFormatType};
        use nokhwa::Camera;

        let cam_idx = state.lock().camera_device_index;

        // Try the configured index first, then fall back to 0, 1, 2
        let indices_to_try: Vec<u32> = if cam_idx > 0 {
            vec![cam_idx as u32, 0, 1, 2]
        } else {
            vec![0, 1, 2, 3]
        };

        let mut camera_opt: Option<Camera> = None;
        let mut used_idx = 0u32;

        for idx in &indices_to_try {
            let index = CameraIndex::Index(*idx);
            let format = RequestedFormat::new::<RgbFormat>(RequestedFormatType::AbsoluteHighestFrameRate);
            match Camera::new(index, format) {
                Ok(cam) => {
                    log_to_engine(&state, &format!("VIDEO: Found camera at index {}", idx));
                    camera_opt = Some(cam);
                    used_idx = *idx;
                    break;
                }
                Err(e) => {
                    log_to_engine(&state, &format!("VIDEO: Index {} failed: {}", idx, e));
                }
            }
        }

        let mut camera = match camera_opt {
            Some(c) => c,
            None => {
                log_to_engine(&state, "VIDEO: No camera found — check USB connections");
                return;
            }
        };

        match camera.open_stream() {
            Ok(_) => {
                log_to_engine(&state, &format!("VIDEO: ✓ Streaming from camera {}", used_idx));
            }
            Err(e) => {
                log_to_engine(&state, &format!("VIDEO: Failed to open stream: {}", e));
                return;
            }
        }

        let mut last_frame_hash: Option<[u8; 32]> = None;
        let mut health_tester = NistHealthTester::new();
        health_tester.start();

        while running.load(Ordering::Relaxed) {
            let enabled = state.try_lock()
                .map(|l| l.harvester_states.video)
                .unwrap_or(false);
            if enabled {
                if let Ok(frame) = camera.frame() {
                    let buffer = frame.buffer();
                    let mut noise: Vec<u8> = buffer.iter()
                        .step_by(7)
                        .map(|&b| b & 0x0F)
                        .take(512)
                        .collect();

                    let nanos = get_timestamp_nanos();
                    noise.extend_from_slice(&nanos.to_le_bytes());

                    if let Some(ref prev_hash) = last_frame_hash {
                        for (i, b) in noise.iter_mut().enumerate().take(32) {
                            *b ^= prev_hash[i % 32];
                        }
                    }

                    let mut hasher = Sha3_256::new();
                    hasher.update(&noise);
                    last_frame_hash = Some(hasher.finalize().into());

                    let passed = health_tester.process_batch(&noise);
                    if !passed.is_empty() {
                        let _ = tx.try_send(("VIDEO".to_string(), passed));
                    }

                    if let Some(mut lock) = state.try_lock() {
                        let metrics = lock.source_metrics.entry("VIDEO".to_string()).or_default();
                        metrics.health_state = health_tester.state_name().to_string();
                    }
                }
            }
            thread::sleep(Duration::from_secs(1));
        }
    });
}

// ============================================================================
// GPU HARVESTERS (Per-GPU Independent Threads)
// ============================================================================

pub fn start_gpu_cuda_harvester(
    tx: Sender<(String, Vec<u8>)>,
    running: Arc<AtomicBool>,
    state: Arc<Mutex<SharedState>>,
) {
    #[cfg(not(feature = "gpu-cuda"))]
    { let _ = (tx, running, state); return; }

    #[cfg(feature = "gpu-cuda")]
    thread::spawn(move || {
        let mut health_tester = NistHealthTester::new();
        health_tester.start();

        while running.load(Ordering::Relaxed) {
            let enabled = state.try_lock()
                .map(|l| l.harvester_states.gpu_cuda)
                .unwrap_or(false);
            if enabled {
                if let Some(gpu_bytes) = cuda_entropy::harvest_cuda(512) {
                    let mut data = gpu_bytes;
                    data.extend_from_slice(&get_timestamp_nanos().to_le_bytes());

                    let passed = health_tester.process_batch(&data);
                    if !passed.is_empty() {
                        let _ = tx.try_send(("GPU_CUDA".to_string(), passed));
                        if let Some(mut lock) = state.try_lock() {
                            let metrics = lock.source_metrics
                                .entry("GPU_CUDA".to_string()).or_default();
                            metrics.health_state = health_tester.state_name().to_string();
                        }
                    }
                }
            }
            thread::sleep(Duration::from_millis(500));
        }
    });
}

pub fn start_gpu_ocl_harvester(
    tx: Sender<(String, Vec<u8>)>,
    running: Arc<AtomicBool>,
    state: Arc<Mutex<SharedState>>,
) {
    #[cfg(not(feature = "gpu-opencl"))]
    { let _ = (tx, running, state); return; }

    #[cfg(feature = "gpu-opencl")]
    thread::spawn(move || {
        let mut health_tester = NistHealthTester::new();
        health_tester.start();

        while running.load(Ordering::Relaxed) {
            let (enabled, plat_idx, dev_idx) = state.try_lock()
                .map(|l| (
                    l.harvester_states.gpu_ocl,
                    l.gpu_ocl_platform_id,
                    l.gpu_ocl_device_id,
                ))
                .unwrap_or((false, 0, 0));

            if enabled {
                let result = std::panic::catch_unwind(|| {
                    opencl_entropy::harvest_opencl(512, plat_idx, dev_idx)
                });

                if let Ok(Some(gpu_bytes)) = result {
                    let mut data = gpu_bytes;
                    data.extend_from_slice(&get_timestamp_nanos().to_le_bytes());

                    let passed = health_tester.process_batch(&data);
                    if !passed.is_empty() {
                        let _ = tx.try_send(("GPU_OCL".to_string(), passed));
                        if let Some(mut lock) = state.try_lock() {
                            let metrics = lock.source_metrics
                                .entry("GPU_OCL".to_string()).or_default();
                            metrics.health_state = health_tester.state_name().to_string();
                        }
                    }
                }
            }
            thread::sleep(Duration::from_millis(500));
        }
    });
}

// ============================================================================
// GUITAR ESP32 UDP ENTROPY LISTENER
// Listens on UDP entropy ports (ctrl_port) for guitar entropy data.
// STRUM/ping ports (data_port) are owned by Null Tunnel — NullMagnet does NOT bind them.
// This prevents port conflicts when both apps run simultaneously.
// ============================================================================

pub fn start_guitar_udp_listener(
    tx: Sender<(String, Vec<u8>)>,
    running: Arc<AtomicBool>,
    state: Arc<Mutex<SharedState>>,
) {
    let guitar_configs: Vec<(String, u16)> = {
        let lock = state.lock();
        lock.guitar_states.iter().map(|(name, gs)| {
            (name.clone(), gs.ctrl_port)
        }).collect()
    };

    for (gname, ctrl_port) in guitar_configs {
        // --- Entropy port listener (ctrl_port) ---
        // data_port (STRUM) is intentionally NOT bound here — Null Tunnel owns it.
        let tx_ctrl = tx.clone();
        let running_ctrl = running.clone();
        let state_ctrl = state.clone();
        let gname_ctrl = gname.clone();

        thread::spawn(move || {
            use std::net::UdpSocket;

            let bind_addr = format!("0.0.0.0:{}", ctrl_port);
            let socket = match UdpSocket::bind(&bind_addr) {
                Ok(s) => {
                    if let Some(mut lock) = state_ctrl.try_lock() {
                        let ts = chrono::Local::now().format("%H:%M:%S").to_string();
                        let msg = format!("[{}] GUITAR {}: Listening on UDP:{} (ctrl)",
                            ts, gname_ctrl, ctrl_port);
                        if lock.logs.len() >= 500 { lock.logs.pop_front(); }
                        lock.logs.push_back(msg);
                    }
                    s
                }
                Err(e) => {
                    eprintln!("GUITAR {}: Failed to bind UDP:{} - {}", gname_ctrl, ctrl_port, e);
                    return;
                }
            };

            socket.set_read_timeout(Some(Duration::from_millis(500))).ok();
            let mut health_tester = NistHealthTester::new();
            health_tester.start();
            let mut buf = [0u8; 2048];

            while running_ctrl.load(Ordering::Relaxed) {
                let enabled = state_ctrl.try_lock()
                    .and_then(|l| l.guitar_states.get(&gname_ctrl).map(|gs| gs.enabled))
                    .unwrap_or(false);

                if !enabled {
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }

                match socket.recv_from(&mut buf) {
                    Ok((len, _addr)) => {
                        if len == 0 { continue; }

                        let mut data = buf[..len].to_vec();
                        data.extend_from_slice(&get_timestamp_nanos().to_le_bytes());

                        let passed = health_tester.process_batch(&data);
                        if !passed.is_empty() {
                            let source = format!("GUITAR_{}_CTRL", gname_ctrl.to_uppercase());
                            let _ = tx_ctrl.try_send((source, passed));
                        }

                        if let Some(mut lock) = state_ctrl.try_lock() {
                            if let Some(gs) = lock.guitar_states.get_mut(&gname_ctrl) {
                                gs.packets_received += 1;
                                gs.bytes_received += len as u64;

                                // Log every 10th packet so guitar activity is visible in console
                                if gs.packets_received % 10 == 1 {
                                    let ts = chrono::Local::now().format("%H:%M:%S").to_string();
                                    let msg = format!(
                                        "[{}] GUITAR {}: {} bytes (pkt #{}, {} total bytes)",
                                        ts, gname_ctrl, len, gs.packets_received, gs.bytes_received
                                    );
                                    if lock.logs.len() >= 500 { lock.logs.pop_front(); }
                                    lock.logs.push_back(msg);
                                }
                            }
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                    Err(_) => { thread::sleep(Duration::from_millis(100)); }
                }
            }
        });
    }
}

// ============================================================================
// WIFI NOISE HARVESTER
// ============================================================================

pub fn start_wifi_harvester(
    tx: Sender<(String, Vec<u8>)>,
    running: Arc<AtomicBool>,
    state: Arc<Mutex<SharedState>>,
) {
    thread::spawn(move || {
        let mut health_tester = NistHealthTester::new();
        health_tester.start();

        while running.load(Ordering::Relaxed) {
            let enabled = state.try_lock()
                .map(|l| l.harvester_states.wifi)
                .unwrap_or(false);
            if enabled {
                let mut noise_data = Vec::with_capacity(256);

                // Read /proc/net/wireless (Linux)
                if let Ok(contents) = std::fs::read_to_string("/proc/net/wireless") {
                    noise_data.extend_from_slice(contents.as_bytes());
                }

                let iface = state.try_lock()
                    .map(|l| l.wifi_interface.clone())
                    .unwrap_or_default();

                if !iface.is_empty() {
                    for stat in &["rx_bytes", "tx_bytes", "rx_dropped", "collisions"] {
                        let path = format!("/sys/class/net/{}/statistics/{}", iface, stat);
                        if let Ok(val) = std::fs::read_to_string(&path) {
                            noise_data.extend_from_slice(val.trim().as_bytes());
                        }
                    }
                } else {
                    // Auto-detect wireless interface
                    #[cfg(target_os = "linux")]
                    {
                        let mut found = false;
                        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
                            for entry in entries.flatten() {
                                let name = entry.file_name();
                                let name_str = name.to_string_lossy();
                                let wireless_path = format!("/sys/class/net/{}/wireless", name_str);
                                if std::path::Path::new(&wireless_path).exists() {
                                    for stat in &["rx_bytes", "tx_bytes", "collisions"] {
                                        let path = format!(
                                            "/sys/class/net/{}/statistics/{}", name_str, stat);
                                        if let Ok(val) = std::fs::read_to_string(&path) {
                                            noise_data.extend_from_slice(val.trim().as_bytes());
                                        }
                                    }
                                    found = true;
                                    break;
                                }
                            }
                        }

                        if !found {
                            for candidate in &["wlan0", "wlp2s0", "wlp3s0", "wifi0"] {
                                let path = format!("/sys/class/net/{}/statistics/rx_bytes", candidate);
                                if let Ok(val) = std::fs::read_to_string(&path) {
                                    noise_data.extend_from_slice(val.trim().as_bytes());
                                    break;
                                }
                            }
                        }
                    }

                    #[cfg(target_os = "windows")]
                    {
                        if let Ok(output) = std::process::Command::new("netsh")
                            .args(&["wlan", "show", "interfaces"])
                            .output()
                        {
                            noise_data.extend_from_slice(&output.stdout);
                        }
                    }
                }

                noise_data.extend_from_slice(&get_timestamp_nanos().to_le_bytes());

                if noise_data.len() > 8 {
                    let passed = health_tester.process_batch(&noise_data);
                    if !passed.is_empty() {
                        let _ = tx.try_send(("WIFI".to_string(), passed));
                        if let Some(mut lock) = state.try_lock() {
                            lock.wifi_active = true;
                            lock.wifi_samples += 1;
                            let metrics = lock.source_metrics
                                .entry("WIFI".to_string()).or_default();
                            metrics.health_state = health_tester.state_name().to_string();
                        }
                    }
                }
            } else {
                if let Some(mut lock) = state.try_lock() {
                    lock.wifi_active = false;
                }
            }
            thread::sleep(Duration::from_secs(2));
        }
    });
}

// ============================================================================
// USB SERIAL HARVESTER
// ============================================================================

pub fn start_usb_serial_harvester(
    tx: Sender<(String, Vec<u8>)>,
    running: Arc<AtomicBool>,
    state: Arc<Mutex<SharedState>>,
) {
    thread::spawn(move || {
        let mut health_tester = NistHealthTester::new();
        health_tester.start();

        let mut current_port: Option<Box<dyn serialport::SerialPort>> = None;
        let mut last_port_name = String::new();

        while running.load(Ordering::Relaxed) {
            let enabled = state.try_lock()
                .map(|l| l.harvester_states.usb_serial)
                .unwrap_or(false);
            if !enabled {
                current_port = None;
                if let Some(mut lock) = state.try_lock() {
                    lock.usb_serial_active = false;
                }
                thread::sleep(Duration::from_millis(500));
                continue;
            }

            let (port_name, baud) = state.try_lock()
                .map(|l| (l.usb_serial_port.clone(), l.usb_serial_baud))
                .unwrap_or_else(|| (String::new(), 115200));

            let target_port = if port_name.is_empty() {
                match serialport::available_ports() {
                    Ok(ports) => ports.into_iter().next().map(|p| p.port_name).unwrap_or_default(),
                    Err(_) => String::new(),
                }
            } else {
                port_name
            };

            if target_port.is_empty() {
                if let Some(mut lock) = state.try_lock() {
                    lock.usb_serial_active = false;
                }
                thread::sleep(Duration::from_secs(2));
                continue;
            }

            if target_port != last_port_name || current_port.is_none() {
                current_port = serialport::new(&target_port, baud)
                    .timeout(Duration::from_millis(500))
                    .open()
                    .ok();

                if current_port.is_some() {
                    last_port_name = target_port.clone();
                    if let Some(mut lock) = state.try_lock() {
                        lock.usb_serial_active = true;
                        let ts = chrono::Local::now().format("%H:%M:%S").to_string();
                        let msg = format!("[{}] USB: Opened {} @ {}", ts, target_port, baud);
                        if lock.logs.len() >= 500 { lock.logs.pop_front(); }
                        lock.logs.push_back(msg);
                    }
                } else {
                    if let Some(mut lock) = state.try_lock() {
                        lock.usb_serial_active = false;
                    }
                    thread::sleep(Duration::from_secs(2));
                    continue;
                }
            }

            if let Some(ref mut port) = current_port {
                let mut buf = [0u8; 512];
                match port.read(&mut buf) {
                    Ok(len) if len > 0 => {
                        let mut data = buf[..len].to_vec();
                        data.extend_from_slice(&get_timestamp_nanos().to_le_bytes());

                        let passed = health_tester.process_batch(&data);
                        if !passed.is_empty() {
                            let _ = tx.try_send(("USB_SERIAL".to_string(), passed));
                            if let Some(mut lock) = state.try_lock() {
                                lock.usb_serial_bytes += len as u64;
                                let metrics = lock.source_metrics
                                    .entry("USB_SERIAL".to_string()).or_default();
                                metrics.health_state = health_tester.state_name().to_string();
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                    Err(_) => {
                        current_port = None;
                        if let Some(mut lock) = state.try_lock() {
                            lock.usb_serial_active = false;
                        }
                    }
                }
            }

            thread::sleep(Duration::from_millis(500));
        }
    });
}

// ============================================================================
// BLUETOOTH PASSIVE (Timing Jitter from BT Stack)
// Always available — reads adapter stats + scheduling noise
// Windows: reads BT radio info via PowerShell
// ============================================================================

pub fn start_bt_passive_harvester(
    tx: Sender<(String, Vec<u8>)>,
    running: Arc<AtomicBool>,
    state: Arc<Mutex<SharedState>>,
) {
    thread::spawn(move || {
        let mut health_tester = NistHealthTester::new();
        health_tester.start();
        let mut logged_start = false;

        while running.load(Ordering::Relaxed) {
            let enabled = state.try_lock()
                .map(|l| l.harvester_states.bt_passive)
                .unwrap_or(false);
            if enabled {
                if !logged_start {
                    log_to_engine(&state, "BT_PASSIVE: Starting Bluetooth passive entropy");
                    logged_start = true;
                }

                let mut noise_data = Vec::with_capacity(256);

                #[cfg(target_os = "linux")]
                {
                    if let Ok(entries) = std::fs::read_dir("/sys/class/bluetooth") {
                        for entry in entries.flatten() {
                            let name = entry.file_name();
                            let name_str = name.to_string_lossy();
                            let addr_path = format!("/sys/class/bluetooth/{}/address", name_str);
                            if let Ok(val) = std::fs::read_to_string(&addr_path) {
                                noise_data.extend_from_slice(val.trim().as_bytes());
                            }
                            let type_path = format!("/sys/class/bluetooth/{}/type", name_str);
                            if let Ok(val) = std::fs::read_to_string(&type_path) {
                                noise_data.extend_from_slice(val.trim().as_bytes());
                            }
                        }
                    }

                    for hci_id in 0..4 {
                        let path = format!("/sys/kernel/debug/bluetooth/hci{}/features", hci_id);
                        if let Ok(val) = std::fs::read_to_string(&path) {
                            noise_data.extend_from_slice(val.as_bytes());
                        }
                    }
                }

                #[cfg(target_os = "windows")]
                {
                    // Read BT radio info — includes USB BT dongles
                    if let Ok(output) = std::process::Command::new("powershell")
                        .args(&["-Command",
                            "Get-PnpDevice -Class Bluetooth -Status OK 2>$null | Select-Object InstanceId,FriendlyName | Format-List"])
                        .output()
                    {
                        if !output.stdout.is_empty() {
                            noise_data.extend_from_slice(&output.stdout);
                        }
                    }
                    // Also try BluetoothLE class for USB BT dongles
                    if let Ok(output) = std::process::Command::new("powershell")
                        .args(&["-Command",
                            "Get-PnpDevice -Class BluetoothLE -Status OK 2>$null | Select-Object InstanceId | Format-List"])
                        .output()
                    {
                        if !output.stdout.is_empty() {
                            noise_data.extend_from_slice(&output.stdout);
                        }
                    }
                }

                // Timing jitter from BT stack scheduling (cross-platform)
                let t1 = get_timestamp_nanos();
                std::thread::yield_now();
                let t2 = get_timestamp_nanos();
                let jitter = t2.wrapping_sub(t1);
                noise_data.extend_from_slice(&jitter.to_le_bytes());
                noise_data.extend_from_slice(&t1.to_le_bytes());

                if noise_data.len() > 8 {
                    let passed = health_tester.process_batch(&noise_data);
                    if !passed.is_empty() {
                        let _ = tx.try_send(("BT_PASSIVE".to_string(), passed));
                        if let Some(mut lock) = state.try_lock() {
                            let metrics = lock.source_metrics
                                .entry("BT_PASSIVE".to_string()).or_default();
                            metrics.health_state = health_tester.state_name().to_string();
                        }
                    }
                }
            }
            thread::sleep(Duration::from_secs(2));
        }
    });
}

// ============================================================================
// BLUETOOTH ACTIVE (BLE RSSI Scanning) — requires bt-active feature
// ============================================================================

#[cfg(feature = "bt-active")]
pub fn start_bt_active_harvester(
    tx: Sender<(String, Vec<u8>)>,
    running: Arc<AtomicBool>,
    state: Arc<Mutex<SharedState>>,
) {
    thread::spawn(move || {
        // btleplug is async — run in a small tokio runtime
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("BT_ACTIVE: Failed to create runtime: {}", e);
                return;
            }
        };

        rt.block_on(async {
            use btleplug::api::{Central, Manager as _, ScanFilter};
            use btleplug::platform::Manager;

            let manager = match Manager::new().await {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("BT_ACTIVE: No BT manager: {}", e);
                    return;
                }
            };

            let adapters = match manager.adapters().await {
                Ok(a) => a,
                Err(_) => return,
            };

            let adapter = match adapters.into_iter().next() {
                Some(a) => a,
                None => {
                    eprintln!("BT_ACTIVE: No BT adapters found");
                    return;
                }
            };

            let mut health_tester = NistHealthTester::new();
            health_tester.start();

            while running.load(Ordering::Relaxed) {
                let enabled = state.try_lock()
                    .map(|l| l.harvester_states.bt_active)
                    .unwrap_or(false);
                if !enabled {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    continue;
                }

                // Short BLE scan burst (2 seconds)
                if adapter.start_scan(ScanFilter::default()).await.is_ok() {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    let _ = adapter.stop_scan().await;

                    if let Ok(peripherals) = adapter.peripherals().await {
                        let mut rssi_data = Vec::with_capacity(256);

                        for peripheral in peripherals.iter().take(20) {
                            if let Ok(Some(props)) = peripheral.properties().await {
                                if let Some(rssi) = props.rssi {
                                    rssi_data.extend_from_slice(&(rssi as i16).to_le_bytes());
                                }
                                // TX power level is also good entropy
                                if let Some(tx_power) = props.tx_power_level {
                                    rssi_data.extend_from_slice(&(tx_power as i16).to_le_bytes());
                                }
                            }
                        }

                        // Add timing jitter
                        rssi_data.extend_from_slice(&get_timestamp_nanos().to_le_bytes());

                        if rssi_data.len() > 8 {
                            let passed = health_tester.process_batch(&rssi_data);
                            if !passed.is_empty() {
                                let _ = tx.try_send(("BT_RSSI".to_string(), passed));
                                if let Some(mut lock) = state.try_lock() {
                                    let metrics = lock.source_metrics
                                        .entry("BT_RSSI".to_string()).or_default();
                                    metrics.health_state = health_tester.state_name().to_string();
                                }
                            }
                        }
                    }
                }

                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        });
    });
}

// ============================================================================
// P2P SERVER WITH HMAC AUTHENTICATION
// ============================================================================

fn validate_hmac(
    key: &[u8],
    node_id: &str,
    seq: u64,
    timestamp: i64,
    payload: &[u8],
    sources: &str,
    claimed_mac: &str,
) -> bool {
    let mut mac = match HmacSha256::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => return false,
    };

    mac.update(node_id.as_bytes());
    mac.update(b"|");
    mac.update(&seq.to_le_bytes());
    mac.update(b"|");
    mac.update(&timestamp.to_le_bytes());
    mac.update(b"|");
    mac.update(sources.as_bytes());
    mac.update(b"|");
    mac.update(payload);

    let claimed_bytes = match hex::decode(claimed_mac) {
        Ok(b) => b,
        Err(_) => return false,
    };
    mac.verify_slice(&claimed_bytes).is_ok()
}

pub fn start_p2p_server(
    tx: Sender<(String, Vec<u8>)>,
    state: Arc<Mutex<SharedState>>,
    running: Arc<AtomicBool>,
) {
    thread::spawn(move || {
        use std::net::TcpListener;
        use std::io::{Read, Write};

        let port = state.lock().p2p_config.listen_port;
        let addr = format!("0.0.0.0:{}", port);

        let listener = match TcpListener::bind(&addr) {
            Ok(l) => {
                let ts = chrono::Local::now().format("%H:%M:%S").to_string();
                let mut lock = state.lock();
                let hmac_status = if lock.p2p_config.hmac_key.is_some() {
                    "ENABLED"
                } else {
                    "DISABLED"
                };
                let msg = format!("[{}] P2P: Listening on port {} (HMAC: {})",
                    ts, port, hmac_status);
                if lock.logs.len() >= 500 { lock.logs.pop_front(); }
                lock.logs.push_back(msg);
                drop(lock);
                l
            }
            Err(e) => {
                eprintln!("P2P: Failed to bind to {}: {}", addr, e);
                return;
            }
        };

        listener.set_nonblocking(true).ok();
        let mut health_tester = NistHealthTester::new();
        health_tester.start();

        while running.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, addr)) => {
                    let p2p_active = state.try_lock()
                        .map(|l| l.p2p_config.active)
                        .unwrap_or(false);
                    if !p2p_active { continue; }

                    let tx_clone = tx.clone();
                    let state_clone = state.clone();

                    thread::spawn(move || {
                        let mut buffer = String::new();
                        if stream.read_to_string(&mut buffer).is_ok() {
                            if let Some(body_start) = buffer.find("\r\n\r\n") {
                                let body = &buffer[body_start + 4..];

                                if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
                                    let payload_hex = json["payload_hex"].as_str().unwrap_or("");
                                    let entropy_bytes = match hex::decode(payload_hex) {
                                        Ok(b) => b,
                                        Err(_) => {
                                            let resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\n\r\nINVALID_HEX";
                                            let _ = stream.write_all(resp.as_bytes());
                                            return;
                                        }
                                    };

                                    if let Some(lock) = state_clone.try_lock() {
                                        if let Some(ref hmac_key) = lock.p2p_config.hmac_key {
                                            let node_id = json["node_id"].as_str().unwrap_or("");
                                            let seq = json["seq"].as_u64().unwrap_or(0);
                                            let timestamp = json["timestamp"].as_i64().unwrap_or(0);
                                            let sources = json["sources"].as_str().unwrap_or("");
                                            let mac_hex = json["mac_hex"].as_str().unwrap_or("");

                                            if !validate_hmac(hmac_key, node_id, seq, timestamp,
                                                &entropy_bytes, sources, mac_hex)
                                            {
                                                drop(lock);
                                                let resp = "HTTP/1.1 403 Forbidden\r\nContent-Length: 12\r\n\r\nHMAC_INVALID";
                                                let _ = stream.write_all(resp.as_bytes());
                                                return;
                                            }

                                            let now = get_timestamp() as i64;
                                            if (now - timestamp).abs() > 300 {
                                                drop(lock);
                                                let resp = "HTTP/1.1 403 Forbidden\r\nContent-Length: 13\r\n\r\nTIME_MISMATCH";
                                                let _ = stream.write_all(resp.as_bytes());
                                                return;
                                            }
                                        }
                                        drop(lock);
                                    } else {
                                        let resp = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\n\r\nBUSY";
                                        let _ = stream.write_all(resp.as_bytes());
                                        return;
                                    }

                                    let source = format!("P2P_{}", addr.ip());
                                    let _ = tx_clone.try_send((source, entropy_bytes));

                                    if let Some(mut lock) = state_clone.try_lock() {
                                        lock.p2p_config.received_count += 1;
                                    }

                                    let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
                                    let _ = stream.write_all(resp.as_bytes());
                                    return;
                                }
                            }
                        }

                        let resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 5\r\n\r\nERROR";
                        let _ = stream.write_all(resp.as_bytes());
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(100));
                }
                Err(_) => {
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
    });
}

// ============================================================================
// HEADSCALE FORWARDER
// Monitors connectivity to all configured Headscale targets
// Actual forwarding happens in the mixer thread (engine.rs)
// ============================================================================

pub fn start_headscale_forwarder(
    state: Arc<Mutex<SharedState>>,
    running: Arc<AtomicBool>,
) {
    thread::spawn(move || {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_millis(2000))
            .build()
            .unwrap_or_else(|_| reqwest::blocking::Client::new());

        let mut last_ping = Instant::now();

        while running.load(Ordering::Relaxed) {
            if last_ping.elapsed() >= Duration::from_secs(30) {
                // Ping all enabled targets
                let targets: Vec<(usize, String, u16, String)> = match state.try_lock() {
                    Some(lock) => {
                        lock.headscale_targets.iter().enumerate()
                            .filter(|(_, hs)| hs.target.enabled)
                            .map(|(i, hs)| (i, hs.target.ip.clone(), hs.target.port, hs.target.name.clone()))
                            .collect()
                    }
                    None => Vec::new(),
                };

                for (idx, ip, port, name) in targets {
                    let url = format!("http://{}:{}/ping", ip, port);
                    let reachable = client.get(&url).send()
                        .map(|r| r.status().is_success())
                        .unwrap_or(false);

                    if let Some(mut lock) = state.try_lock() {
                        if let Some(hs) = lock.headscale_targets.get_mut(idx) {
                            hs.reachable = reachable;
                        }
                        if reachable {
                            let ts = chrono::Local::now().format("%H:%M:%S").to_string();
                            let msg = format!("[{}] HEADSCALE: {} reachable ({}:{})",
                                ts, name, ip, port);
                            if lock.logs.len() >= 500 { lock.logs.pop_front(); }
                            lock.logs.push_back(msg);
                        }
                    }
                }

                last_ping = Instant::now();
            }

            thread::sleep(Duration::from_secs(5));
        }
    });
}
