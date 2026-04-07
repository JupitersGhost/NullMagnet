//! NullMagnet Live v2 - engine.rs
//! Jupiter Labs - ChaosEngine Core
//!
//! Architecture:
//!   engine.rs     - Engine, shared state, mixer thread, all control methods
//!   entropy.rs    - NIST health tests, entropy estimators, extraction pool
//!   harvesters.rs - All harvester threads
//!   vault.rs      - Encrypted local vault + Headscale push
//!
//! NIST Compliance:
//! - Repetition Count Test (RCT) cutoff=31 (alpha=2^-30, H=1)
//! - Adaptive Proportion Test (APT) W=512, C=325
//! - Startup sample discard (4096 samples)
//! - SHA-256 vetted conditioning function
//! - Conservative entropy crediting (0.85 factor)
//! - Min-entropy estimation (Most Common Value + Collision)
//!
//! PQC: ML-KEM-1024 (FIPS 203) + Falcon-512 (NIST round 3)

use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use parking_lot::Mutex;
use crossbeam_channel::{bounded, Sender, Receiver};
use std::thread;
use std::time::Duration;
use std::fs;
use std::collections::{VecDeque, HashMap};
use sha2::{Sha256, Digest as Sha2Digest};
use sha3::Sha3_256;
use hmac::{Hmac, Mac};
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{SecretKey as SignSecretKey, DetachedSignature};
use pqcrypto_traits::sign::PublicKey as SignPublicKey;
use zeroize::Zeroize;
use ml_kem::{KemCore, MlKem1024, EncodedSizeUser};
use rand_core::{RngCore, CryptoRng};

use crate::entropy::{
    NistHealthTester, EntropyExtractionPool, StatTestResults,
    EXTRACTION_POOL_SIZE, POOL_SIZE, HISTORY_LEN,
    NIST_RCT_CUTOFF, NIST_APT_WINDOW, NIST_APT_CUTOFF,
    NIST_CONDITIONING_FACTOR,
    MIN_ENTROPY_FOR_MINT, AUTO_MINT_THRESHOLD,
    shannon_entropy, conservative_min_entropy, credit_entropy,
    get_timestamp, get_timestamp_nanos,
};
use crate::config::{
    NullMagnetConfig, HarvesterStates, SourceMetrics, GuitarState,
    HeadscaleTarget,
};
use crate::harvesters;

pub type HmacSha256 = Hmac<Sha256>;

// ============================================================================
// HARVESTED RNG — XORs OsRng with entropy pool for key generation
//
// This ensures PQC keys are seeded by BOTH:
//   1. The OS CSPRNG (baseline security — always safe)
//   2. Your harvested entropy pool (guitars, sensors, GPU noise, etc.)
//
// The XOR combination means:
//   - If OsRng is good but pool is weak → keys are still safe (OsRng dominates)
//   - If pool is good but OsRng is compromised → keys are still safe (pool dominates)
//   - If both are good → keys are stronger than either alone
//
// This is the standard construction for entropy mixing (NIST SP 800-90C).
// The pool is re-hashed with SHA-3 + counter to produce unlimited key material.
// ============================================================================

struct HarvestedRng {
    /// SHA-3 hash of pool + counter, expanded as needed
    pool_seed: [u8; 32],
    /// Counter for generating more bytes from the same pool snapshot
    counter: u64,
    /// Position within current 32-byte block
    pos: usize,
    /// Current expanded block
    block: [u8; 32],
}

impl HarvestedRng {
    /// Create from a 32-byte entropy pool snapshot
    fn from_pool(pool: &[u8; 32]) -> Self {
        let mut seed = [0u8; 32];
        // Hash pool with domain separator to derive seed
        let mut hasher = Sha3_256::new();
        hasher.update(b"NullMagnet_HarvestedRng_v2");
        hasher.update(pool);
        hasher.update(&get_timestamp_nanos().to_le_bytes());
        let result = hasher.finalize();
        seed.copy_from_slice(&result);

        let mut rng = Self {
            pool_seed: seed,
            counter: 0,
            pos: 32, // Force regeneration on first use
            block: [0u8; 32],
        };
        rng.regenerate_block();
        rng
    }

    /// Generate next 32-byte block from seed + counter
    fn regenerate_block(&mut self) {
        let mut hasher = Sha3_256::new();
        hasher.update(&self.pool_seed);
        hasher.update(&self.counter.to_le_bytes());
        let result = hasher.finalize();
        self.block.copy_from_slice(&result);
        self.counter += 1;
        self.pos = 0;
    }
}

impl RngCore for HarvestedRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // Get OsRng bytes first
        let mut os_bytes = vec![0u8; dest.len()];
        rand::rngs::OsRng.fill_bytes(&mut os_bytes);

        // Get pool-derived bytes
        let mut pool_bytes = vec![0u8; dest.len()];
        let mut written = 0;
        while written < dest.len() {
            if self.pos >= 32 {
                self.regenerate_block();
            }
            let available = 32 - self.pos;
            let needed = dest.len() - written;
            let take = available.min(needed);
            pool_bytes[written..written + take]
                .copy_from_slice(&self.block[self.pos..self.pos + take]);
            self.pos += take;
            written += take;
        }

        // XOR: dest = OsRng ⊕ pool_derived
        // This is the standard entropy mixing construction
        for i in 0..dest.len() {
            dest[i] = os_bytes[i] ^ pool_bytes[i];
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

// SAFETY: HarvestedRng is cryptographically secure because:
//   1. OsRng is CryptoRng (provides baseline security)
//   2. Pool-derived bytes come from SHA-3 (cryptographic hash)
//   3. XOR of two independent sources is at least as strong as the stronger one
impl CryptoRng for HarvestedRng {}

/// FIPS 203 §3.3: Zeroize intermediate seed/block material when RNG is dropped.
/// Prevents recovery of pool-derived keying material from memory after keygen.
impl Drop for HarvestedRng {
    fn drop(&mut self) {
        self.pool_seed.zeroize();
        self.block.zeroize();
        self.counter = 0;
        self.pos = 0;
    }
}

// ============================================================================
// P2P CONFIG (runtime state)
// ============================================================================

#[derive(Clone)]
pub struct P2PConfig {
    pub active: bool,
    pub listen_port: u16,
    pub peers: Vec<String>,
    pub received_count: u64,
    pub hmac_key: Option<Vec<u8>>,
}

impl Default for P2PConfig {
    fn default() -> Self {
        Self {
            active: false,
            listen_port: 9000,
            peers: Vec::new(),
            received_count: 0,
            hmac_key: None,
        }
    }
}

// ============================================================================
// HEADSCALE RUNTIME STATE (per-target)
// ============================================================================

#[derive(Clone)]
pub struct HeadscaleState {
    pub target: HeadscaleTarget,
    pub forwarded_count: u64,
    pub last_forward_ts: u64,
    pub reachable: bool,
}

impl HeadscaleState {
    pub fn from_target(t: &HeadscaleTarget) -> Self {
        Self {
            target: t.clone(),
            forwarded_count: 0,
            last_forward_ts: 0,
            reachable: false,
        }
    }
}

// ============================================================================
// SHARED STATE — protected by parking_lot::Mutex
// ============================================================================

pub struct SharedState {
    pub extraction_pool: EntropyExtractionPool,
    pub pool: [u8; 32],
    pub display_pool: VecDeque<u8>,
    pub history_raw_entropy: VecDeque<f64>,
    pub history_whitened_entropy: VecDeque<f64>,
    pub source_metrics: HashMap<String, SourceMetrics>,
    pub estimated_true_entropy_bits: f64,
    pub credited_entropy_bits: f64,
    pub logs: VecDeque<String>,
    pub total_bytes: usize,
    pub sequence_id: u64,

    // Network
    pub net_mode: bool,
    pub uplink_url: String,

    // PQC Identity
    pub falcon_pk: Vec<u8>,
    pub falcon_sk: Vec<u8>,
    pub pqc_active: bool,

    // Harvesters
    pub harvester_states: HarvesterStates,
    pub health_testers: HashMap<String, NistHealthTester>,

    // P2P
    pub p2p_config: P2PConfig,

    // Auto-mint
    pub auto_mint_enabled: bool,
    pub last_auto_mint_ts: u64,

    // GPU (per-GPU independent tracking)
    pub gpu_cuda_available: bool,
    pub gpu_cuda_backend: String,
    pub gpu_ocl_available: bool,
    pub gpu_ocl_backend: String,
    pub gpu_ocl_platform_id: usize,
    pub gpu_ocl_device_id: usize,

    // Guitar ESP32 sources
    pub guitar_states: HashMap<String, GuitarState>,

    // Headscale targets (multiple)
    pub headscale_targets: Vec<HeadscaleState>,

    // Device config (runtime — mirrors config.rs DevicesConfig)
    pub audio_device_index: Option<usize>,
    pub audio_gain: f64,
    pub camera_device_index: usize,
    pub usb_serial_port: String,
    pub usb_serial_baud: u32,
    pub wifi_interface: String,

    // WiFi noise tracking
    pub wifi_active: bool,
    pub wifi_samples: u64,

    // USB serial tracking
    pub usb_serial_active: bool,
    pub usb_serial_bytes: u64,

    // Live mode
    pub live_mode: bool,

    // Mouse harvester lazy-start flag
    pub mouse_harvester_started: bool,

    // Global Shannon entropy tracking (for GUI display)
    pub last_shannon: f64,
}

/// FIPS 140-3: Ensure secret key material is zeroized when SharedState is dropped
impl Drop for SharedState {
    fn drop(&mut self) {
        self.falcon_sk.zeroize();
        self.pool.zeroize();
        if let Some(ref mut hmac_key) = self.p2p_config.hmac_key {
            hmac_key.zeroize();
        }
    }
}

// ============================================================================
// CHAOSENGINE — Core Engine
// ============================================================================

pub struct ChaosEngine {
    pub state: Arc<Mutex<SharedState>>,
    pub running: Arc<AtomicBool>,
    pub tx_entropy: Sender<(String, Vec<u8>)>,
    pub config: Arc<Mutex<NullMagnetConfig>>,
}

// ============================================================================
// MIXER THREAD WITH NIST ENTROPY CREDITING
// ============================================================================

fn start_mixer_thread(
    rx: Receiver<(String, Vec<u8>)>,
    state: Arc<Mutex<SharedState>>,
    running: Arc<AtomicBool>,
) {
    thread::spawn(move || {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_millis(500))
            .build()
            .unwrap_or_else(|_| reqwest::blocking::Client::new());

        let mut last_net_time = 0u64;
        let mut last_headscale_times: HashMap<usize, u64> = HashMap::new();

        while running.load(Ordering::Relaxed) {
            let (source, data) = match rx.recv_timeout(Duration::from_secs(1)) {
                Ok(d) => d,
                Err(_) => continue,
            };

            // Calculate entropy estimates (no lock needed)
            let raw_shannon = shannon_entropy(&data);
            let raw_min = conservative_min_entropy(&data);
            let credited_bits = credit_entropy(data.len(), raw_min);

            // =============================================================
            // PHASE 1: Brief lock — state updates, collect config for Phase 2
            // =============================================================
            struct MixerExtracted {
                extracted: Vec<u8>,
                seq_id: u64,
                mint_pool: Option<[u8; 32]>,
                mint_falcon_sk: Option<Vec<u8>>,
                mint_falcon_pk: Option<Vec<u8>>,
                mint_agg_bits: f64,
                mint_now_ts: u64,
                net_target: Option<String>,
                hs_targets: Vec<(usize, String)>, // (index, url)
                p2p_peers: Option<Vec<String>>,
                p2p_hmac_key: Option<Vec<u8>>,
            }

            let phase2: Option<MixerExtracted> = {
                let mut lock = state.lock();

                // Feed to extraction pool
                let extracted_opt = lock.extraction_pool.add_raw_bytes(&data, raw_min);

                // Update source metrics
                let metrics = lock.source_metrics.entry(source.clone()).or_default();
                metrics.samples += 1;
                metrics.raw_shannon = raw_shannon;
                metrics.min_entropy = raw_min;
                metrics.total_bits_contributed += credited_bits;
                metrics.avg_raw_entropy = if metrics.samples == 1 {
                    raw_shannon
                } else {
                    metrics.avg_raw_entropy * 0.95 + raw_shannon * 0.05
                };

                lock.estimated_true_entropy_bits += credited_bits;
                lock.credited_entropy_bits += credited_bits;
                lock.last_shannon = raw_shannon;

                // Update history
                if lock.history_raw_entropy.len() >= HISTORY_LEN {
                    lock.history_raw_entropy.pop_front();
                }
                lock.history_raw_entropy.push_back(raw_min);

                // Process extracted entropy
                if let Some(extracted) = extracted_opt {
                    let extracted_shannon = shannon_entropy(&extracted);

                    if lock.history_whitened_entropy.len() >= HISTORY_LEN {
                        lock.history_whitened_entropy.pop_front();
                    }
                    lock.history_whitened_entropy.push_back(extracted_shannon);

                    // Mix into pool using SHA-3
                    let mut pool_hasher = Sha3_256::new();
                    pool_hasher.update(&lock.pool);
                    pool_hasher.update(source.as_bytes());
                    pool_hasher.update(&extracted);
                    pool_hasher.update(&get_timestamp_nanos().to_le_bytes());
                    lock.pool = pool_hasher.finalize().into();

                    // Update display pool
                    for &b in extracted.iter() {
                        if lock.display_pool.len() >= POOL_SIZE {
                            lock.display_pool.pop_front();
                        }
                        lock.display_pool.push_back(b);
                    }

                    lock.total_bytes += extracted.len();
                    lock.sequence_id += 1;

                    // Log extraction
                    let ts = chrono::Local::now().format("%H:%M:%S").to_string();
                    let msg = format!(
                        "[{}] EXTRACT #{} | {}->32 bytes | H_min:{:.2} | Credited:{:.0} bits | Src:{}",
                        ts, lock.extraction_pool.extractions_count,
                        EXTRACTION_POOL_SIZE, raw_min, credited_bits, source
                    );
                    if lock.logs.len() >= 500 { lock.logs.pop_front(); }
                    lock.logs.push_back(msg);

                    // --- Auto-mint prerequisites ---
                    let agg_bits = lock.extraction_pool.aggregate_credited_bits;
                    let should_mint = agg_bits >= MIN_ENTROPY_FOR_MINT
                        && raw_min > AUTO_MINT_THRESHOLD
                        && lock.pqc_active
                        && lock.auto_mint_enabled;

                    let (mint_pool, mint_fsk, mint_fpk, mint_agg, mint_ts) = if should_mint {
                        let now_ts = get_timestamp();
                        if lock.last_auto_mint_ts == 0 || (now_ts - lock.last_auto_mint_ts) >= 10 {
                            let ts = chrono::Local::now().format("%H:%M:%S").to_string();
                            let msg = format!(
                                "[{}] AUTO-MINT: Aggregate={:.0} bits, H_min={:.2}",
                                ts, agg_bits, raw_min
                            );
                            if lock.logs.len() >= 500 { lock.logs.pop_front(); }
                            lock.logs.push_back(msg);
                            (Some(lock.pool), Some(lock.falcon_sk.clone()),
                             Some(lock.falcon_pk.clone()), agg_bits, now_ts)
                        } else {
                            (None, None, None, 0.0, 0)
                        }
                    } else {
                        (None, None, None, 0.0, 0)
                    };

                    // --- Network config snapshots ---
                    let now = get_timestamp();

                    let net_target = if lock.net_mode && now > last_net_time {
                        last_net_time = now;
                        Some(lock.uplink_url.clone())
                    } else {
                        None
                    };

                    // Collect all enabled Headscale targets
                    let mut hs_targets = Vec::new();
                    for (i, hs) in lock.headscale_targets.iter_mut().enumerate() {
                        if hs.target.enabled {
                            let last_t = last_headscale_times.get(&i).copied().unwrap_or(0);
                            if now > last_t + 5 {
                                last_headscale_times.insert(i, now);
                                hs.forwarded_count += 1;
                                hs.last_forward_ts = now;
                                let url = format!("http://{}:{}/entropy",
                                    hs.target.ip, hs.target.port);
                                hs_targets.push((i, url));
                            }
                        }
                    }

                    let (p2p_peers, p2p_hmac) = if lock.p2p_config.active
                        && !lock.p2p_config.peers.is_empty()
                    {
                        (Some(lock.p2p_config.peers.clone()),
                         lock.p2p_config.hmac_key.clone())
                    } else {
                        (None, None)
                    };

                    let seq_id = lock.sequence_id;

                    Some(MixerExtracted {
                        extracted,
                        seq_id,
                        mint_pool,
                        mint_falcon_sk: mint_fsk,
                        mint_falcon_pk: mint_fpk,
                        mint_agg_bits: mint_agg,
                        mint_now_ts: mint_ts,
                        net_target,
                        hs_targets,
                        p2p_peers,
                        p2p_hmac_key: p2p_hmac,
                    })
                } else {
                    None
                }
            }; // === LOCK DROPS HERE ===

            // =============================================================
            // PHASE 2: No lock — expensive PQC keygen + network sends
            // =============================================================
            if let Some(mx) = phase2 {

                // --- AUTO-MINT (ML-KEM-1024 + Falcon-512) ---
                if let (Some(pool), Some(falcon_sk_bytes), Some(falcon_pk_bytes)) =
                    (mx.mint_pool, mx.mint_falcon_sk, mx.mint_falcon_pk)
                {
                    // ML-KEM-1024 keypair seeded from harvested entropy + OsRng
                    // rng is zeroized on drop (FIPS 203 §3.3)
                    let mut rng = HarvestedRng::from_pool(&pool);
                    let (mlkem_dk, mlkem_ek) = MlKem1024::generate(&mut rng);

                    let mut ek_bytes: Vec<u8> = mlkem_ek.as_bytes()[..].to_vec();
                    let mut dk_bytes: Vec<u8> = mlkem_dk.as_bytes()[..].to_vec();

                    let mut context_hasher = Sha3_256::new();
                    context_hasher.update(&pool);
                    context_hasher.update(&ek_bytes);
                    let context = context_hasher.finalize();

                    if let Ok(falcon_secret) = falcon512::SecretKey::from_bytes(&falcon_sk_bytes) {
                        let signature = falcon512::detached_sign(&context, &falcon_secret);
                        let timestamp = get_timestamp();

                        let bundle = serde_json::json!({
                            "type": "NULLMAGNET_PQC_BUNDLE",
                            "version": "2.0",
                            "nist_compliant": true,
                            "kem_algorithm": "ML-KEM-1024",
                            "kem_seed": "OsRng_XOR_HarvestedPool",
                            "sig_algorithm": "Falcon-512",
                            "requester": "AUTO",
                            "timestamp": timestamp,
                            "raw_min_entropy": raw_min,
                            "aggregate_credited_bits": mx.mint_agg_bits,
                            "mlkem_ek": hex::encode(&ek_bytes),
                            "mlkem_dk": hex::encode(&dk_bytes),
                            "falcon_sig": hex::encode(signature.as_bytes()),
                            "falcon_signer_pk": hex::encode(&falcon_pk_bytes),
                        });

                        let filename = format!("keys/key_{}_{}.json",
                            timestamp, hex::encode(&ek_bytes[0..4]));
                        if let Ok(file) = fs::File::create(&filename) {
                            let _ = serde_json::to_writer_pretty(file, &bundle);
                        }

                        // Brief re-lock: update mint state
                        {
                            let mut lock = state.lock();
                            lock.extraction_pool.reset_aggregate_credits();
                            lock.credited_entropy_bits = 0.0;
                            lock.last_auto_mint_ts = mx.mint_now_ts;

                            let ts = chrono::Local::now().format("%H:%M:%S").to_string();
                            let msg = format!("[{}] VAULT: Saved {}", ts, filename);
                            if lock.logs.len() >= 500 { lock.logs.pop_front(); }
                            lock.logs.push_back(msg);
                        }
                    }

                    // FIPS 203 §3.3: Zeroize ML-KEM intermediate values
                    ek_bytes.zeroize();
                    dk_bytes.zeroize();
                    // rng dropped here — pool_seed + block zeroized via Drop impl
                }

                // --- NETWORK UPLINK ---
                if let Some(target) = mx.net_target {
                    let seq = mx.seq_id;
                    let source_clone = source.clone();
                    let c = client.clone();
                    let payload_hex = hex::encode(&mx.extracted[..]);

                    let digest = {
                        let mut hasher = Sha3_256::new();
                        hasher.update(&data);
                        hex::encode(hasher.finalize())
                    };

                    thread::spawn(move || {
                        let _ = c.post(&target)
                            .json(&serde_json::json!({
                                "node": "nullmagnet_live",
                                "version": "2.0",
                                "nist_compliant": true,
                                "seq": seq,
                                "timestamp": get_timestamp(),
                                "source": source_clone,
                                "payload_hex": payload_hex,
                                "digest": digest,
                            }))
                            .send();
                    });
                }

                // --- HEADSCALE FORWARDING (all enabled targets) ---
                for (_idx, hs_url) in mx.hs_targets {
                    let payload_hex = hex::encode(&mx.extracted[..]);
                    let seq = mx.seq_id;
                    let c = client.clone();

                    thread::spawn(move || {
                        let _ = c.post(&hs_url)
                            .json(&serde_json::json!({
                                "node": "nullmagnet_live",
                                "version": "2.0",
                                "seq": seq,
                                "timestamp": get_timestamp(),
                                "payload_hex": payload_hex,
                            }))
                            .send();
                    });
                }

                // --- P2P DISTRIBUTION ---
                if let Some(peers) = mx.p2p_peers {
                    let payload_hex = hex::encode(&mx.extracted[..]);
                    let seq = mx.seq_id;
                    let c = client.clone();
                    let hmac_key = mx.p2p_hmac_key;

                    thread::spawn(move || {
                        let timestamp = get_timestamp() as i64;
                        for peer in peers {
                            let url = format!("http://{}", peer);
                            let mut payload = serde_json::json!({
                                "node_id": "nullmagnet_live",
                                "seq": seq,
                                "timestamp": timestamp,
                                "payload_hex": payload_hex,
                                "sources": "mixed",
                            });

                            if let Some(ref key) = hmac_key {
                                let payload_bytes = hex::decode(&payload_hex).unwrap_or_default();
                                let mut mac = HmacSha256::new_from_slice(key).unwrap();
                                mac.update(b"nullmagnet_live|");
                                mac.update(&seq.to_le_bytes());
                                mac.update(b"|");
                                mac.update(&timestamp.to_le_bytes());
                                mac.update(b"|mixed|");
                                mac.update(&payload_bytes);
                                let mac_hex = hex::encode(mac.finalize().into_bytes());
                                payload["mac_hex"] = serde_json::Value::String(mac_hex);
                            }

                            let _ = c.post(&url).json(&payload).send();
                        }
                    });
                }
            }
        }
    });
}

// ============================================================================
// ENGINE IMPLEMENTATION
// ============================================================================

impl ChaosEngine {
    /// Create new engine from config
    pub fn new(config: NullMagnetConfig) -> Self {
        let (tx, rx) = bounded(1000);
        let _ = fs::create_dir_all(&config.general.keys_dir);

        // Falcon-512 session identity (uses OsRng — no harvested pool exists yet at startup)
        // This is a per-session signing key, regenerated each launch.
        // PQC key bundles (minted later) use HarvestedRng seeded from the entropy pool.
        let (pk, sk) = falcon512::keypair();

        let mut display_pool = VecDeque::with_capacity(POOL_SIZE);
        display_pool.extend(vec![0u8; POOL_SIZE]);

        // Detect GPUs independently
        let (cuda_avail, cuda_backend) = harvesters::detect_gpu_cuda();
        let (ocl_avail, ocl_backend) = harvesters::detect_gpu_opencl();

        // Initialize guitar states from config
        let mut guitar_states = HashMap::new();
        for g in &config.guitars.guitars {
            guitar_states.insert(g.name.clone(), GuitarState {
                name: g.name.clone(),
                data_port: g.data_port,
                ctrl_port: g.ctrl_port,
                enabled: g.enabled,
                packets_received: 0,
                bytes_received: 0,
            });
        }

        // Initialize Headscale targets from config
        let headscale_targets: Vec<HeadscaleState> = config.network.headscale_targets
            .iter()
            .map(|t| HeadscaleState::from_target(t))
            .collect();

        // Initialize P2P from config
        let hmac_key = if config.network.p2p_hmac_key_hex.is_empty() {
            None
        } else {
            hex::decode(&config.network.p2p_hmac_key_hex).ok()
        };

        let p2p_config = P2PConfig {
            active: config.network.p2p_enabled,
            listen_port: config.network.p2p_port,
            peers: config.network.p2p_peers.clone(),
            received_count: 0,
            hmac_key,
        };

        // Initialize harvester states from config
        let harvester_states = HarvesterStates::from_config(&config.sources);

        let state = Arc::new(Mutex::new(SharedState {
            extraction_pool: EntropyExtractionPool::new(),
            pool: [0u8; 32],
            display_pool,
            history_raw_entropy: VecDeque::from(vec![0.0; HISTORY_LEN]),
            history_whitened_entropy: VecDeque::from(vec![0.0; HISTORY_LEN]),
            source_metrics: HashMap::new(),
            estimated_true_entropy_bits: 0.0,
            credited_entropy_bits: 0.0,
            logs: VecDeque::from(vec![
                format!("ENGINE: NullMagnet Live v2.0 (NIST SP 800-90B)"),
                format!("PQC: ML-KEM-1024 (FIPS 203) + Falcon-512"),
                format!("CONFIG: RCT={}, APT_W={}, APT_C={}",
                    NIST_RCT_CUTOFF, NIST_APT_WINDOW, NIST_APT_CUTOFF),
                format!("GPU-CUDA: {} ({})", if cuda_avail { "Available" } else { "N/A" }, cuda_backend),
                format!("GPU-OCL:  {} ({})", if ocl_avail { "Available" } else { "N/A" }, ocl_backend),
            ]),
            total_bytes: 0,
            net_mode: config.network.uplink_enabled,
            uplink_url: config.network.uplink_url.clone(),
            sequence_id: 0,
            falcon_pk: pk.as_bytes().to_vec(),
            falcon_sk: sk.as_bytes().to_vec(),
            pqc_active: true,
            harvester_states,
            health_testers: HashMap::new(),
            p2p_config,
            auto_mint_enabled: config.pqc.auto_mint,
            last_auto_mint_ts: 0,
            gpu_cuda_available: cuda_avail,
            gpu_cuda_backend: cuda_backend,
            gpu_ocl_available: ocl_avail,
            gpu_ocl_backend: ocl_backend,
            gpu_ocl_platform_id: config.devices.opencl_platform,
            gpu_ocl_device_id: config.devices.opencl_device,
            guitar_states,
            headscale_targets,
            audio_device_index: None,
            audio_gain: config.devices.audio_gain,
            camera_device_index: 0,
            usb_serial_port: config.devices.usb_serial_port.clone(),
            usb_serial_baud: config.devices.usb_serial_baud,
            wifi_interface: config.devices.wifi_interface.clone(),
            wifi_active: false,
            wifi_samples: 0,
            usb_serial_active: false,
            usb_serial_bytes: 0,
            live_mode: false,
            mouse_harvester_started: false,
            last_shannon: 0.0,
        }));

        // Startup logging
        {
            let mut lock = state.lock();
            let ts = chrono::Local::now().format("%H:%M:%S").to_string();
            lock.logs.push_back(format!(
                "[{}] IDENTITY: Falcon-512 Session Key Generated", ts));
            lock.logs.push_back(format!(
                "[{}] EXTRACTION: {}->32 byte conditioning (SHA-256)", ts, EXTRACTION_POOL_SIZE));

            let guitar_list: Vec<String> = lock.guitar_states.iter()
                .map(|(name, gs)| format!("{}:{}", name, gs.data_port))
                .collect();
            if !guitar_list.is_empty() {
                lock.logs.push_back(format!(
                    "[{}] GUITARS: {} (UDP)", ts, guitar_list.join(" ")));
            }

            let hs_msgs: Vec<String> = lock.headscale_targets.iter()
                .map(|hs| format!(
                    "[{}] HEADSCALE: {} @ {}:{} ({})", ts,
                    hs.target.name, hs.target.ip, hs.target.port,
                    if hs.target.enabled { "enabled" } else { "disabled" }))
                .collect();
            for msg in hs_msgs {
                lock.logs.push_back(msg);
            }
        }

        let running = Arc::new(AtomicBool::new(true));

        // Start core threads
        start_mixer_thread(rx, state.clone(), running.clone());
        harvesters::start_p2p_server(tx.clone(), state.clone(), running.clone());

        // Start standard harvesters
        // NOTE: Mouse harvester lazy-started via toggle (rdev global hook causes lag)
        harvesters::start_trng_harvester(tx.clone(), running.clone(), state.clone());
        harvesters::start_audio_harvester(tx.clone(), running.clone(), state.clone());
        harvesters::start_system_harvester(tx.clone(), running.clone(), state.clone());
        harvesters::start_video_harvester(tx.clone(), running.clone(), state.clone());

        // GPU harvesters (independent threads)
        harvesters::start_gpu_cuda_harvester(tx.clone(), running.clone(), state.clone());
        harvesters::start_gpu_ocl_harvester(tx.clone(), running.clone(), state.clone());

        // Extended harvesters
        harvesters::start_guitar_udp_listener(tx.clone(), running.clone(), state.clone());
        harvesters::start_wifi_harvester(tx.clone(), running.clone(), state.clone());
        harvesters::start_usb_serial_harvester(tx.clone(), running.clone(), state.clone());
        harvesters::start_bt_passive_harvester(tx.clone(), running.clone(), state.clone());
        harvesters::start_headscale_forwarder(state.clone(), running.clone());

        #[cfg(feature = "bt-active")]
        harvesters::start_bt_active_harvester(tx.clone(), running.clone(), state.clone());

        let config = Arc::new(Mutex::new(config));

        ChaosEngine {
            state,
            running,
            tx_entropy: tx,
            config,
        }
    }

    // ========================================================================
    // HARVESTER TOGGLES
    // ========================================================================

    pub fn toggle_harvester(&self, name: &str, active: bool) {
        let mut lock = self.state.lock();
        let mut need_mouse_start = false;

        match name.to_uppercase().as_str() {
            "TRNG" | "HARDWARE/TRNG"          => lock.harvester_states.trng = active,
            "AUDIO" | "AUDIO (MIC)"           => lock.harvester_states.audio = active,
            "SYS" | "SYSTEM" | "SYSTEM/CPU"   => lock.harvester_states.system = active,
            "MOUSE" | "HID (MOUSE)"           => {
                lock.harvester_states.mouse = active;
                if active && !lock.mouse_harvester_started {
                    lock.mouse_harvester_started = true;
                    need_mouse_start = true;
                }
            }
            "VIDEO" | "VIDEO (CAM)"           => lock.harvester_states.video = active,
            "GPU_CUDA" | "GPU (CUDA)"         => lock.harvester_states.gpu_cuda = active,
            "GPU_OCL" | "GPU (OPENCL)"        => lock.harvester_states.gpu_ocl = active,
            "WIFI" | "WIFI NOISE"             => lock.harvester_states.wifi = active,
            "USB_SERIAL" | "USB SERIAL"       => lock.harvester_states.usb_serial = active,
            "BT_PASSIVE" | "BT PASSIVE"       => lock.harvester_states.bt_passive = active,
            "BT_ACTIVE" | "BT ACTIVE"         => lock.harvester_states.bt_active = active,
            other => {
                if other.starts_with("GUITAR_") {
                    let gname = other.trim_start_matches("GUITAR_");
                    let key = lock.guitar_states.keys()
                        .find(|k| k.to_uppercase() == gname)
                        .cloned();
                    if let Some(key) = key {
                        if let Some(gs) = lock.guitar_states.get_mut(&key) {
                            gs.enabled = active;
                        }
                    }
                }
            }
        }

        let status = if active { "Active" } else { "Inactive" };
        let suffix = if need_mouse_start { " (hook starting)" } else { "" };
        let ts = chrono::Local::now().format("%H:%M:%S").to_string();
        let msg = format!("[{}] Toggle: {} -> {}{}", ts, name, status, suffix);
        if lock.logs.len() >= 500 { lock.logs.pop_front(); }
        lock.logs.push_back(msg);

        drop(lock);

        if need_mouse_start {
            let tx = self.tx_entropy.clone();
            let running = self.running.clone();
            let state_clone = self.state.clone();
            harvesters::start_mouse_harvester(tx, running, state_clone);
        }
    }

    // ========================================================================
    // NETWORK CONTROLS
    // ========================================================================

    pub fn toggle_uplink(&self, active: bool) {
        let mut lock = self.state.lock();
        lock.net_mode = active;
        let ts = chrono::Local::now().format("%H:%M:%S").to_string();
        let msg = format!("[{}] Network Uplink -> {}",
            ts, if active { "ENABLED" } else { "PAUSED" });
        if lock.logs.len() >= 500 { lock.logs.pop_front(); }
        lock.logs.push_back(msg);
    }

    pub fn set_uplink_target(&self, ip: String, port: u16) {
        let port = if port == 0 { 8000 } else { port };
        let mut lock = self.state.lock();
        lock.uplink_url = format!("http://{}:{}/entropy", ip, port);
        let ts = chrono::Local::now().format("%H:%M:%S").to_string();
        let msg = format!("[{}] NET: Uplink target set to {}:{}", ts, ip, port);
        if lock.logs.len() >= 500 { lock.logs.pop_front(); }
        lock.logs.push_back(msg);
    }

    // ========================================================================
    // HEADSCALE CONTROLS (multiple targets)
    // ========================================================================

    pub fn toggle_headscale(&self, index: usize, active: bool) {
        let mut lock = self.state.lock();
        if let Some(hs) = lock.headscale_targets.get_mut(index) {
            hs.target.enabled = active;
            let ts = chrono::Local::now().format("%H:%M:%S").to_string();
            let msg = format!("[{}] HEADSCALE: {} -> {} ({}:{})",
                ts, hs.target.name,
                if active { "ENABLED" } else { "DISABLED" },
                hs.target.ip, hs.target.port);
            if lock.logs.len() >= 500 { lock.logs.pop_front(); }
            lock.logs.push_back(msg);
        }
    }

    pub fn add_headscale_target(&self, name: String, ip: String, port: u16) {
        let target = HeadscaleTarget {
            name: name.clone(),
            ip: ip.clone(),
            port,
            enabled: true,
        };
        let mut lock = self.state.lock();
        lock.headscale_targets.push(HeadscaleState::from_target(&target));
        let ts = chrono::Local::now().format("%H:%M:%S").to_string();
        let msg = format!("[{}] HEADSCALE: Added target {} @ {}:{}", ts, name, ip, port);
        if lock.logs.len() >= 500 { lock.logs.pop_front(); }
        lock.logs.push_back(msg);
    }

    pub fn remove_headscale_target(&self, index: usize) {
        let mut lock = self.state.lock();
        if index < lock.headscale_targets.len() {
            let removed = lock.headscale_targets.remove(index);
            let ts = chrono::Local::now().format("%H:%M:%S").to_string();
            let msg = format!("[{}] HEADSCALE: Removed target {}", ts, removed.target.name);
            if lock.logs.len() >= 500 { lock.logs.pop_front(); }
            lock.logs.push_back(msg);
        }
    }

    // ========================================================================
    // P2P CONTROLS
    // ========================================================================

    pub fn toggle_p2p(&self, active: bool) {
        let mut lock = self.state.lock();
        lock.p2p_config.active = active;
        let ts = chrono::Local::now().format("%H:%M:%S").to_string();
        let msg = format!("[{}] P2P Mode -> {}",
            ts, if active { "ENABLED" } else { "PAUSED" });
        if lock.logs.len() >= 500 { lock.logs.pop_front(); }
        lock.logs.push_back(msg);
    }

    pub fn set_p2p_hmac_key(&self, key_hex: String) -> Result<(), String> {
        let key = hex::decode(key_hex.trim())
            .map_err(|_| "Invalid hex key".to_string())?;
        if key.len() != 32 {
            return Err("HMAC key must be 32 bytes".to_string());
        }
        let mut lock = self.state.lock();
        lock.p2p_config.hmac_key = Some(key);
        let ts = chrono::Local::now().format("%H:%M:%S").to_string();
        let msg = format!("[{}] P2P: HMAC authentication ENABLED", ts);
        if lock.logs.len() >= 500 { lock.logs.pop_front(); }
        lock.logs.push_back(msg);
        Ok(())
    }

    pub fn add_peer(&self, peer_addr: String) {
        let mut lock = self.state.lock();
        if !lock.p2p_config.peers.contains(&peer_addr) {
            lock.p2p_config.peers.push(peer_addr.clone());
            let ts = chrono::Local::now().format("%H:%M:%S").to_string();
            let msg = format!("[{}] P2P: Added peer {}", ts, peer_addr);
            if lock.logs.len() >= 500 { lock.logs.pop_front(); }
            lock.logs.push_back(msg);
        }
    }

    // ========================================================================
    // PQC KEY GENERATION (ML-KEM-1024 + Falcon-512)
    // ========================================================================

    pub fn set_auto_mint(&self, enabled: bool) {
        let mut lock = self.state.lock();
        lock.auto_mint_enabled = enabled;
        let ts = chrono::Local::now().format("%H:%M:%S").to_string();
        let msg = format!("[{}] AUTO-MINT -> {} (threshold: {} credited bits)",
            ts, if enabled { "ENABLED" } else { "DISABLED" },
            MIN_ENTROPY_FOR_MINT as u32);
        if lock.logs.len() >= 500 { lock.logs.pop_front(); }
        lock.logs.push_back(msg);
    }

    pub fn mint_pqc_bundle(&self, requester: &str) -> Result<String, String> {
        let requester = if requester.is_empty() { "MANUAL" } else { requester };
        let mut lock = self.state.lock();

        if !lock.pqc_active {
            return Err("PQC Engine Offline".to_string());
        }

        let agg_bits = lock.extraction_pool.aggregate_credited_bits;
        if agg_bits < MIN_ENTROPY_FOR_MINT {
            return Err(format!(
                "Insufficient entropy ({:.0}/{} aggregate credited bits)",
                agg_bits, MIN_ENTROPY_FOR_MINT as u32
            ));
        }

        // ML-KEM-1024 keypair seeded from harvested entropy + OsRng
        // rng is zeroized on drop (FIPS 203 §3.3)
        let mut rng = HarvestedRng::from_pool(&lock.pool);
        let (mlkem_dk, mlkem_ek) = MlKem1024::generate(&mut rng);
        let mut ek_bytes: Vec<u8> = mlkem_ek.as_bytes()[..].to_vec();
        let mut dk_bytes: Vec<u8> = mlkem_dk.as_bytes()[..].to_vec();

        let mut context_hasher = Sha3_256::new();
        context_hasher.update(&lock.pool);
        context_hasher.update(&ek_bytes);
        let context = context_hasher.finalize();

        let falcon_secret = falcon512::SecretKey::from_bytes(&lock.falcon_sk)
            .map_err(|e| format!("Falcon key error: {}", e))?;
        let signature = falcon512::detached_sign(&context, &falcon_secret);
        let timestamp = get_timestamp();

        let bundle = serde_json::json!({
            "type": "NULLMAGNET_PQC_BUNDLE",
            "version": "2.0",
            "nist_compliant": true,
            "kem_algorithm": "ML-KEM-1024",
            "kem_seed": "OsRng_XOR_HarvestedPool",
            "sig_algorithm": "Falcon-512",
            "requester": requester,
            "timestamp": timestamp,
            "aggregate_credited_bits": agg_bits,
            "mlkem_ek": hex::encode(&ek_bytes),
            "mlkem_dk": hex::encode(&dk_bytes),
            "falcon_sig": hex::encode(signature.as_bytes()),
            "falcon_signer_pk": hex::encode(&lock.falcon_pk),
        });

        let filename = format!("keys/key_{}_{}.json",
            timestamp, hex::encode(&ek_bytes[0..4]));

        // FIPS 203 §3.3: Zeroize ML-KEM intermediate values before any early return
        ek_bytes.zeroize();
        dk_bytes.zeroize();

        if let Ok(file) = fs::File::create(&filename) {
            let _ = serde_json::to_writer_pretty(file, &bundle);
        }

        let ts = chrono::Local::now().format("%H:%M:%S").to_string();
        let msg = format!("[{}] VAULT: Saved {} (aggregate: {:.0} bits)", ts, filename, agg_bits);
        if lock.logs.len() >= 500 { lock.logs.pop_front(); }
        lock.logs.push_back(msg);

        lock.extraction_pool.reset_aggregate_credits();
        lock.credited_entropy_bits = 0.0;

        Ok(format!("Generated {}", filename))
    }

    /// Mint a PQC bundle and save it encrypted to the local vault.
    /// Returns the vault filename on success.
    pub fn mint_pqc_bundle_encrypted(&self, password: &str) -> Result<String, String> {
        if password.is_empty() {
            return Err("Vault password required".to_string());
        }

        let mut lock = self.state.lock();

        if !lock.pqc_active {
            return Err("PQC Engine Offline".to_string());
        }

        let agg_bits = lock.extraction_pool.aggregate_credited_bits;
        if agg_bits < MIN_ENTROPY_FOR_MINT {
            return Err(format!(
                "Insufficient entropy ({:.0}/{} aggregate credited bits)",
                agg_bits, MIN_ENTROPY_FOR_MINT as u32
            ));
        }

        // ML-KEM-1024 keypair seeded from harvested entropy + OsRng
        // rng is zeroized on drop (FIPS 203 §3.3)
        let mut rng = HarvestedRng::from_pool(&lock.pool);
        let (mlkem_dk, mlkem_ek) = MlKem1024::generate(&mut rng);
        let mut ek_bytes: Vec<u8> = mlkem_ek.as_bytes()[..].to_vec();
        let mut dk_bytes: Vec<u8> = mlkem_dk.as_bytes()[..].to_vec();

        let mut context_hasher = Sha3_256::new();
        context_hasher.update(&lock.pool);
        context_hasher.update(&ek_bytes);
        let context = context_hasher.finalize();

        let falcon_secret = falcon512::SecretKey::from_bytes(&lock.falcon_sk)
            .map_err(|e| format!("Falcon key error: {}", e))?;
        let signature = falcon512::detached_sign(&context, &falcon_secret);
        let timestamp = get_timestamp();

        let bundle = serde_json::json!({
            "type": "NULLMAGNET_PQC_BUNDLE",
            "version": "2.0",
            "nist_compliant": true,
            "kem_algorithm": "ML-KEM-1024",
            "kem_seed": "OsRng_XOR_HarvestedPool",
            "sig_algorithm": "Falcon-512",
            "requester": "VAULT_ENCRYPTED",
            "timestamp": timestamp,
            "aggregate_credited_bits": agg_bits,
            "mlkem_ek": hex::encode(&ek_bytes),
            "mlkem_dk": hex::encode(&dk_bytes),
            "falcon_sig": hex::encode(signature.as_bytes()),
            "falcon_signer_pk": hex::encode(&lock.falcon_pk),
        });

        let bundle_json = serde_json::to_string_pretty(&bundle)
            .map_err(|e| format!("JSON error: {}", e))?;

        let filename_hint = format!("key_{}_{}", timestamp, hex::encode(&ek_bytes[0..4]));

        // FIPS 203 §3.3: Zeroize ML-KEM intermediate values immediately after use
        ek_bytes.zeroize();
        dk_bytes.zeroize();

        // Encrypt and save to vault
        let vault_path = crate::vault::save_encrypted_bundle(
            "keys", &bundle_json, password, &filename_hint
        ).map_err(|e| format!("Vault error: {}", e))?;

        let ts_str = chrono::Local::now().format("%H:%M:%S").to_string();
        let msg = format!("[{}] VAULT: Encrypted {} (AES-256-GCM, {:.0} bits)",
            ts_str, vault_path.display(), agg_bits);
        if lock.logs.len() >= 500 { lock.logs.pop_front(); }
        lock.logs.push_back(msg);

        lock.extraction_pool.reset_aggregate_credits();
        lock.credited_entropy_bits = 0.0;

        Ok(format!("Encrypted: {}", vault_path.display()))
    }

    // ========================================================================
    // DEVICE CONTROLS
    // ========================================================================

    pub fn set_audio_device(&self, index: usize) {
        let mut lock = self.state.lock();
        lock.audio_device_index = Some(index);
    }

    pub fn set_audio_gain(&self, gain: f64) {
        let mut lock = self.state.lock();
        lock.audio_gain = gain.max(0.1).min(10.0);
    }

    pub fn set_camera_device(&self, index: usize) {
        let mut lock = self.state.lock();
        lock.camera_device_index = index;
    }

    pub fn set_usb_serial_port(&self, port: String, baud: u32) {
        let mut lock = self.state.lock();
        lock.usb_serial_port = port;
        lock.usb_serial_baud = baud;
    }

    pub fn set_wifi_interface(&self, iface: String) {
        let mut lock = self.state.lock();
        lock.wifi_interface = iface;
    }

    // ========================================================================
    // LIVE MODE (enable all safe harvesters at once)
    // ========================================================================

    pub fn set_live_mode(&self, active: bool) {
        let mut lock = self.state.lock();
        lock.live_mode = active;

        lock.harvester_states.trng = active;
        lock.harvester_states.audio = active;
        lock.harvester_states.system = active;
        lock.harvester_states.video = active;
        lock.harvester_states.wifi = active;
        lock.harvester_states.usb_serial = active;
        lock.harvester_states.bt_passive = active;

        if lock.gpu_cuda_available { lock.harvester_states.gpu_cuda = active; }
        if lock.gpu_ocl_available  { lock.harvester_states.gpu_ocl = active; }

        for gs in lock.guitar_states.values_mut() {
            gs.enabled = active;
        }

        let status = if active { "ON — all harvesters enabled" } else { "OFF" };
        let ts = chrono::Local::now().format("%H:%M:%S").to_string();
        let msg = format!("[{}] LIVE MODE -> {}", ts, status);
        if lock.logs.len() >= 500 { lock.logs.pop_front(); }
        lock.logs.push_back(msg);
    }

    // ========================================================================
    // METRICS (consumed by GUI every frame)
    // ========================================================================

    /// Get a snapshot of all metrics for GUI rendering.
    /// Returns everything the GUI needs in a single lock acquisition.
    pub fn get_metrics(&self) -> MetricsSnapshot {
        let lock = self.state.lock();

        let current_raw = lock.history_raw_entropy.back().copied().unwrap_or(0.0);
        let current_whitened = lock.history_whitened_entropy.back().copied().unwrap_or(0.0);

        MetricsSnapshot {
            pool_hex: hex::encode(lock.pool).to_uppercase(),
            total_bytes: lock.total_bytes,
            current_shannon: lock.last_shannon,
            current_raw_entropy: current_raw,
            current_whitened_entropy: current_whitened,
            conditioned_hmin: current_raw * NIST_CONDITIONING_FACTOR,
            estimated_true_bits: lock.estimated_true_entropy_bits,
            credited_entropy_bits: lock.credited_entropy_bits,
            aggregate_credited_bits: lock.extraction_pool.aggregate_credited_bits,
            extraction_pool_fill: lock.extraction_pool.fill_percentage(),
            extractions_count: lock.extraction_pool.extractions_count,
            source_metrics: lock.source_metrics.clone(),
            history_raw: lock.history_raw_entropy.iter().copied().collect(),
            history_whitened: lock.history_whitened_entropy.iter().copied().collect(),
            logs: lock.logs.iter().cloned().collect(),
            harvester_states: lock.harvester_states.clone(),
            guitar_states: lock.guitar_states.clone(),
            headscale_targets: lock.headscale_targets.clone(),
            gpu_cuda_available: lock.gpu_cuda_available,
            gpu_cuda_backend: lock.gpu_cuda_backend.clone(),
            gpu_ocl_available: lock.gpu_ocl_available,
            gpu_ocl_backend: lock.gpu_ocl_backend.clone(),
            p2p_active: lock.p2p_config.active,
            p2p_received: lock.p2p_config.received_count,
            p2p_hmac_enabled: lock.p2p_config.hmac_key.is_some(),
            wifi_active: lock.wifi_active,
            wifi_samples: lock.wifi_samples,
            usb_serial_active: lock.usb_serial_active,
            usb_serial_bytes: lock.usb_serial_bytes,
            live_mode: lock.live_mode,
            pqc_active: lock.pqc_active,
            auto_mint_enabled: lock.auto_mint_enabled,
            net_mode: lock.net_mode,
            audio_gain: lock.audio_gain,

            // Running entropy (accumulated — more accurate than per-batch)
            running_shannon: lock.extraction_pool.running_shannon(),
            running_min_entropy: lock.extraction_pool.running_min_entropy(),
            running_total_bytes: lock.extraction_pool.accumulator.total_bytes,
            running_unique_values: lock.extraction_pool.accumulator.unique_values(),

            // Conditioned output quality
            output_shannon: lock.extraction_pool.output_shannon(),
            output_min_entropy: lock.extraction_pool.output_min_entropy(),
            output_total_bytes: lock.extraction_pool.output_accumulator.total_bytes,

            // NIST SP 800-22 statistical tests
            stat_tests: lock.extraction_pool.last_stat_tests.clone(),
        }
    }

    // ========================================================================
    // SAVE CONFIG (sync runtime state back to TOML)
    // ========================================================================

    pub fn save_config(&self) {
        let lock = self.state.lock();
        let mut cfg = self.config.lock();

        // Sync harvester states
        cfg.sources = lock.harvester_states.to_config();

        // Sync network
        cfg.network.uplink_enabled = lock.net_mode;
        cfg.network.uplink_url = lock.uplink_url.clone();
        cfg.network.p2p_enabled = lock.p2p_config.active;

        // Sync headscale targets
        cfg.network.headscale_targets = lock.headscale_targets
            .iter()
            .map(|hs| hs.target.clone())
            .collect();

        // Sync PQC
        cfg.pqc.auto_mint = lock.auto_mint_enabled;

        // Sync devices
        cfg.devices.audio_gain = lock.audio_gain;
        cfg.devices.wifi_interface = lock.wifi_interface.clone();
        cfg.devices.usb_serial_port = lock.usb_serial_port.clone();
        cfg.devices.usb_serial_baud = lock.usb_serial_baud;

        drop(lock);
        cfg.save();
    }

    // ========================================================================
    // SHUTDOWN
    // ========================================================================

    pub fn shutdown(&self) {
        self.save_config();
        self.running.store(false, Ordering::Relaxed);
        let mut lock = self.state.lock();

        // FIPS 140-3: Zeroize all secret key material
        lock.falcon_sk.zeroize();
        lock.pool.zeroize();
        if let Some(ref mut hmac_key) = lock.p2p_config.hmac_key {
            hmac_key.zeroize();
        }

        let ts = chrono::Local::now().format("%H:%M:%S").to_string();
        let msg = format!("[{}] ENGINE: Shutdown + key zeroization complete", ts);
        if lock.logs.len() >= 500 { lock.logs.pop_front(); }
        lock.logs.push_back(msg);
    }
}

// ============================================================================
// METRICS SNAPSHOT (lock-free struct for GUI consumption)
// ============================================================================

#[derive(Clone)]
pub struct MetricsSnapshot {
    pub pool_hex: String,
    pub total_bytes: usize,
    pub current_shannon: f64,
    pub current_raw_entropy: f64,
    pub current_whitened_entropy: f64,
    pub conditioned_hmin: f64,
    pub estimated_true_bits: f64,
    pub credited_entropy_bits: f64,
    pub aggregate_credited_bits: f64,
    pub extraction_pool_fill: f64,
    pub extractions_count: u64,
    pub source_metrics: HashMap<String, SourceMetrics>,
    pub history_raw: Vec<f64>,
    pub history_whitened: Vec<f64>,
    pub logs: Vec<String>,
    pub harvester_states: HarvesterStates,
    pub guitar_states: HashMap<String, GuitarState>,
    pub headscale_targets: Vec<HeadscaleState>,
    pub gpu_cuda_available: bool,
    pub gpu_cuda_backend: String,
    pub gpu_ocl_available: bool,
    pub gpu_ocl_backend: String,
    pub p2p_active: bool,
    pub p2p_received: u64,
    pub p2p_hmac_enabled: bool,
    pub wifi_active: bool,
    pub wifi_samples: u64,
    pub usb_serial_active: bool,
    pub usb_serial_bytes: u64,
    pub live_mode: bool,
    pub pqc_active: bool,
    pub auto_mint_enabled: bool,
    pub net_mode: bool,
    pub audio_gain: f64,

    // Running entropy (accumulated across all batches — more accurate)
    pub running_shannon: f64,
    pub running_min_entropy: f64,
    pub running_total_bytes: u64,
    pub running_unique_values: usize,

    // Conditioned output quality (SHA-256 output should be near 8.0)
    pub output_shannon: f64,
    pub output_min_entropy: f64,
    pub output_total_bytes: u64,

    // NIST SP 800-22 statistical test results (on conditioned output)
    pub stat_tests: Option<StatTestResults>,
}
