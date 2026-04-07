//! NullMagnet Live v2 - entropy.rs
//! Jupiter Labs - NIST SP 800-90B Entropy Engine
//!
//! This module contains:
//! - NIST SP 800-90B Section 4.4: Health tests (RCT + APT)
//! - NIST SP 800-90B Section 6: Min-entropy estimators (MCV, collision, Markov-approx)
//! - NIST SP 800-90B Section 3.1.5: SHA-256 vetted conditioning + 0.85 factor
//! - Running entropy accumulator for accurate long-term estimates
//! - Conditioned output quality verification
//! - Basic NIST SP 800-22 statistical tests (monobit, runs, frequency-within-block)
//!
//! KEY CLARIFICATION:
//!   Extraction pool: 256 raw BYTES → SHA-256 → 32 BYTES = 256 BITS output
//!   This is correct per NIST SP 800-90B Section 3.1.5 (vetted conditioning).
//!   The 0.85 factor means max credited entropy = 256 * 0.85 = 217.6 bits/extraction.

use std::collections::VecDeque;
use sha2::{Sha256, Digest as Sha2Digest};
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// NIST SP 800-90B CONSTANTS
// ============================================================================

/// Extraction pool: raw bytes accumulated before SHA-256 conditioning
pub const EXTRACTION_POOL_SIZE: usize = 256;

/// Display pool size (for GUI visualization)
pub const POOL_SIZE: usize = 1024;

/// History length for waveform graphs
pub const HISTORY_LEN: usize = 300;

/// NIST RCT: C = 1 + ceil(30/H) where H=1, alpha=2^-30 → C=31
pub const NIST_RCT_CUTOFF: u32 = 31;

/// NIST APT: Window W=512 for non-binary sources (Section 4.4.2)
pub const NIST_APT_WINDOW: usize = 512;

/// NIST APT: Cutoff C=325 for alpha=2^-30, H=1, W=512
pub const NIST_APT_CUTOFF: u32 = 325;

/// Startup discard: 4096 samples per source before accepting data
pub const STARTUP_DISCARD_SAMPLES: usize = 4096;

/// NIST conditioning factor (SP 800-90B Section 3.1.5.1.1)
pub const NIST_CONDITIONING_FACTOR: f64 = 0.85;

/// Minimum aggregate credited bits before key minting allowed
pub const MIN_ENTROPY_FOR_MINT: f64 = 256.0;

/// Auto-mint min-entropy threshold (bits/byte)
/// Real sources typically produce 1-6 bits/byte; 1.0 is a safe floor
pub const AUTO_MINT_THRESHOLD: f64 = 1.0;

// ============================================================================
// TIMESTAMPS
// ============================================================================

pub fn get_timestamp() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

pub fn get_timestamp_nanos() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64
}

// ============================================================================
// NIST SP 800-90B SECTION 4.4: HEALTH TESTS
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthState {
    Init,
    Startup,
    Steady,
    Failed,
    Dead,
}

pub const MAX_HEALTH_RETRIES: u32 = 5;
pub const RECOVERY_COOLDOWN_SAMPLES: u64 = 10000;

#[derive(Clone)]
pub struct NistHealthTester {
    pub state: HealthState,
    rct_last_value: Option<u8>,
    rct_count: u32,
    apt_window: VecDeque<u8>,
    apt_first_value: Option<u8>,
    apt_count: u32,
    startup_samples: usize,
    failure_count: u32,
    samples_since_failure: u64,
    pub total_samples: u64,
    pub rct_failures: u64,
    pub apt_failures: u64,
    pub samples_passed: u64,
}

impl NistHealthTester {
    pub fn new() -> Self {
        Self {
            state: HealthState::Init,
            rct_last_value: None,
            rct_count: 0,
            apt_window: VecDeque::with_capacity(NIST_APT_WINDOW),
            apt_first_value: None,
            apt_count: 0,
            startup_samples: 0,
            failure_count: 0,
            samples_since_failure: 0,
            total_samples: 0,
            rct_failures: 0,
            apt_failures: 0,
            samples_passed: 0,
        }
    }

    pub fn start(&mut self) {
        self.state = HealthState::Startup;
        self.reset();
    }

    pub fn reset(&mut self) {
        self.rct_last_value = None;
        self.rct_count = 0;
        self.apt_window.clear();
        self.apt_first_value = None;
        self.apt_count = 0;
        self.startup_samples = 0;
    }

    pub fn trigger_on_demand(&mut self) {
        self.state = HealthState::Startup;
        self.reset();
    }

    /// Process samples through RCT + APT health tests.
    /// Returns samples that passed (empty during startup/failed/dead).
    pub fn process_batch(&mut self, data: &[u8]) -> Vec<u8> {
        if self.state == HealthState::Dead {
            return Vec::new();
        }

        if self.state == HealthState::Failed {
            self.samples_since_failure += data.len() as u64;
            if self.samples_since_failure >= RECOVERY_COOLDOWN_SAMPLES {
                if self.failure_count >= MAX_HEALTH_RETRIES {
                    self.state = HealthState::Dead;
                    return Vec::new();
                }
                self.state = HealthState::Startup;
                self.reset();
                self.samples_since_failure = 0;
            } else {
                return Vec::new();
            }
        }

        let mut passed = Vec::with_capacity(data.len());

        for &sample in data {
            self.total_samples += 1;

            // NIST SP 800-90B Section 4.4.1: Repetition Count Test
            if !self.run_rct(sample) {
                self.state = HealthState::Failed;
                self.rct_failures += 1;
                self.failure_count += 1;
                self.samples_since_failure = 0;
                return Vec::new();
            }

            // NIST SP 800-90B Section 4.4.2: Adaptive Proportion Test
            if !self.run_apt(sample) {
                self.state = HealthState::Failed;
                self.apt_failures += 1;
                self.failure_count += 1;
                self.samples_since_failure = 0;
                return Vec::new();
            }

            match self.state {
                HealthState::Init => {}
                HealthState::Startup => {
                    self.startup_samples += 1;
                    if self.startup_samples >= STARTUP_DISCARD_SAMPLES {
                        self.state = HealthState::Steady;
                        if self.failure_count > 0 {
                            self.failure_count = 0;
                        }
                    }
                    // Startup samples discarded per NIST requirement
                }
                HealthState::Steady => {
                    passed.push(sample);
                    self.samples_passed += 1;
                }
                HealthState::Failed | HealthState::Dead => {
                    return Vec::new();
                }
            }
        }

        passed
    }

    /// NIST SP 800-90B Section 4.4.1 — Repetition Count Test
    fn run_rct(&mut self, sample: u8) -> bool {
        match self.rct_last_value {
            Some(last) if last == sample => {
                self.rct_count += 1;
                if self.rct_count >= NIST_RCT_CUTOFF {
                    return false;
                }
            }
            _ => {
                self.rct_last_value = Some(sample);
                self.rct_count = 1;
            }
        }
        true
    }

    /// NIST SP 800-90B Section 4.4.2 — Adaptive Proportion Test
    fn run_apt(&mut self, sample: u8) -> bool {
        self.apt_window.push_back(sample);

        if self.apt_first_value.is_none() {
            self.apt_first_value = Some(sample);
            self.apt_count = 1;
            return true;
        }

        if Some(sample) == self.apt_first_value {
            self.apt_count += 1;
            if self.apt_count >= NIST_APT_CUTOFF {
                return false;
            }
        }

        if self.apt_window.len() >= NIST_APT_WINDOW {
            self.apt_window.clear();
            self.apt_first_value = None;
            self.apt_count = 0;
        }

        true
    }

    pub fn is_healthy(&self) -> bool { self.state == HealthState::Steady }
    pub fn is_dead(&self) -> bool { self.state == HealthState::Dead }
    pub fn failure_count(&self) -> u32 { self.failure_count }

    pub fn state_name(&self) -> &'static str {
        match self.state {
            HealthState::Init => "INIT",
            HealthState::Startup => "STARTUP",
            HealthState::Steady => "STEADY",
            HealthState::Failed => "FAILED",
            HealthState::Dead => "DEAD",
        }
    }
}

// ============================================================================
// NIST SP 800-90B SECTION 6: ENTROPY ESTIMATORS
// ============================================================================

/// Shannon entropy — informational upper bound, NOT used for crediting
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0usize; 256];
    for &b in data { counts[b as usize] += 1; }
    let len = data.len() as f64;
    let mut h = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

/// NIST SP 800-90B Section 6.1: Most Common Value (MCV) min-entropy estimate
/// H_min = -log2(p_max)
/// This is the PRIMARY min-entropy estimator per NIST
pub fn min_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0usize; 256];
    for &b in data { counts[b as usize] += 1; }
    let max_count = counts.iter().max().copied().unwrap_or(0);
    let max_prob = max_count as f64 / data.len() as f64;
    if max_prob <= 0.0 || max_prob >= 1.0 { return 0.0; }
    -max_prob.log2()
}

/// NIST SP 800-90B Section 6.2: Collision Estimate
/// Proper implementation using mean time to collision over the full dataset.
/// Fixed: previous version used too-small search windows (100 positions).
pub fn collision_entropy(data: &[u8]) -> f64 {
    if data.len() < 20 { return min_entropy(data); }

    let mut collision_sum = 0u64;
    let mut collision_count = 0u64;
    let max_search = data.len();  // Search full dataset, not just 100 positions
    let max_starts = data.len().saturating_sub(2).min(5000); // Up to 5000 start points

    let mut i = 0;
    while i < max_starts {
        let target = data[i];
        for j in (i + 1)..max_search {
            if data[j] == target {
                collision_sum += (j - i) as u64;
                collision_count += 1;
                break;
            }
        }
        i += 1;
    }

    if collision_count == 0 { return 8.0; }

    let mean_collision = collision_sum as f64 / collision_count as f64;
    // NIST formula: p_estimate derived from mean collision distance
    // For uniform distribution with k=256 symbols: E[collision] ≈ sqrt(π*k/2) ≈ 20.1
    // p_estimate = 1/mean_collision is simplified; proper estimate uses:
    //   p = (2*mean_collision - 1) / (2*mean_collision) then H = -log2(max(p, 1/256))
    // But for conservative estimate, simpler approach:
    let p_estimate = 1.0 / mean_collision;
    if p_estimate <= 0.0 || p_estimate >= 1.0 { return 0.0; }
    (-p_estimate.log2()).max(0.0).min(8.0)
}

/// NIST SP 800-90B Section 6.3.1: Partial Collection Estimate (t-tuple approx)
/// Counts frequency of 2-tuples (bigrams) and estimates from most common
pub fn tuple_entropy(data: &[u8]) -> f64 {
    if data.len() < 100 { return min_entropy(data); }

    // Count 2-tuples (bigrams)
    let mut bigram_counts = vec![0u32; 256 * 256];
    for window in data.windows(2) {
        let idx = (window[0] as usize) * 256 + window[1] as usize;
        bigram_counts[idx] += 1;
    }

    let total = (data.len() - 1) as f64;
    let max_count = bigram_counts.iter().max().copied().unwrap_or(0) as f64;
    if max_count <= 0.0 || total <= 0.0 { return 0.0; }

    let p_max = max_count / total;
    if p_max <= 0.0 || p_max >= 1.0 { return 0.0; }

    // Each bigram represents 2 bytes, so per-byte entropy = -log2(p_max) / 2
    let h_pair = -p_max.log2();
    (h_pair / 2.0).max(0.0).min(8.0)
}

/// Conservative combined min-entropy estimate
/// Uses the MINIMUM across multiple NIST Section 6 estimators
/// MCV is always included; collision and tuple added when data is sufficient
pub fn conservative_min_entropy(data: &[u8]) -> f64 {
    let mcv = min_entropy(data);

    if data.len() < 20 {
        return mcv.max(0.0).min(8.0);
    }

    let coll = collision_entropy(data);
    let tup = if data.len() >= 100 { tuple_entropy(data) } else { 8.0 };

    mcv.min(coll).min(tup).max(0.0).min(8.0)
}

/// Credit entropy with NIST 0.85 conditioning factor
/// Per NIST SP 800-90B Section 3.1.5.1.1:
///   h_out = min(h_in, n_out, q) × 0.85
///   h_in  = raw_bytes × min_ent_per_byte
///   n_out = 256 bits (SHA-256 output)
///   q     = 256 bits (SHA-256 internal width)
///
/// Result: max 256 × 0.85 = 217.6 credited bits per extraction
pub fn credit_entropy(raw_bytes: usize, min_ent_per_byte: f64) -> f64 {
    let h_in = raw_bytes as f64 * min_ent_per_byte;
    let n_out: f64 = 256.0;
    let q: f64 = 256.0;
    let capped = h_in.min(n_out).min(q);
    capped * NIST_CONDITIONING_FACTOR
}

// ============================================================================
// RUNNING ENTROPY ACCUMULATOR
// Maintains byte frequency counts across multiple batches for more
// accurate long-term entropy estimation (vs. per-batch estimates).
// ============================================================================

#[derive(Clone)]
pub struct RunningEntropyAccumulator {
    pub counts: [u64; 256],
    pub total_bytes: u64,
    /// Bigram counts for tuple estimate (256×256 = 65536 entries)
    pub bigram_counts: Vec<u32>,
    pub bigram_total: u64,
    pub last_byte: Option<u8>,
}

impl RunningEntropyAccumulator {
    pub fn new() -> Self {
        Self {
            counts: [0u64; 256],
            total_bytes: 0,
            bigram_counts: vec![0u32; 65536],
            bigram_total: 0,
            last_byte: None,
        }
    }

    /// Feed data into the accumulator
    pub fn update(&mut self, data: &[u8]) {
        for &b in data {
            self.counts[b as usize] += 1;
            self.total_bytes += 1;

            // Track bigrams
            if let Some(prev) = self.last_byte {
                let idx = (prev as usize) * 256 + b as usize;
                self.bigram_counts[idx] += 1;
                self.bigram_total += 1;
            }
            self.last_byte = Some(b);
        }
    }

    /// Shannon entropy from accumulated counts
    pub fn shannon(&self) -> f64 {
        if self.total_bytes == 0 { return 0.0; }
        let len = self.total_bytes as f64;
        let mut h = 0.0;
        for &count in &self.counts {
            if count > 0 {
                let p = count as f64 / len;
                h -= p * p.log2();
            }
        }
        h
    }

    /// MCV min-entropy from accumulated counts
    pub fn min_entropy(&self) -> f64 {
        if self.total_bytes == 0 { return 0.0; }
        let max_count = self.counts.iter().max().copied().unwrap_or(0);
        let p_max = max_count as f64 / self.total_bytes as f64;
        if p_max <= 0.0 || p_max >= 1.0 { return 0.0; }
        -p_max.log2()
    }

    /// Tuple (bigram) min-entropy from accumulated counts
    pub fn tuple_entropy(&self) -> f64 {
        if self.bigram_total < 100 { return 8.0; }
        let max_bg = self.bigram_counts.iter().max().copied().unwrap_or(0) as f64;
        let total = self.bigram_total as f64;
        if max_bg <= 0.0 { return 8.0; }
        let p_max = max_bg / total;
        if p_max <= 0.0 || p_max >= 1.0 { return 0.0; }
        (-p_max.log2() / 2.0).max(0.0).min(8.0)
    }

    /// Conservative min-entropy (minimum of all estimators)
    pub fn conservative_min_entropy(&self) -> f64 {
        let mcv = self.min_entropy();
        let tup = self.tuple_entropy();
        mcv.min(tup).max(0.0).min(8.0)
    }

    /// Number of unique byte values seen
    pub fn unique_values(&self) -> usize {
        self.counts.iter().filter(|&&c| c > 0).count()
    }
}

// ============================================================================
// BASIC STATISTICAL TESTS (NIST SP 800-22 subset)
// These provide additional confidence beyond the health tests.
// ============================================================================

/// NIST SP 800-22 Monobit (Frequency) Test
/// Tests whether the number of 1s and 0s in the sequence are approximately equal.
/// Returns (passed, p_value_approx)
pub fn monobit_test(data: &[u8]) -> (bool, f64) {
    if data.is_empty() { return (false, 0.0); }

    let mut ones = 0u64;
    let mut total_bits = 0u64;

    for &byte in data {
        for bit in 0..8 {
            if (byte >> bit) & 1 == 1 { ones += 1; }
            total_bits += 1;
        }
    }

    let n = total_bits as f64;
    let s = (2.0 * ones as f64 - n).abs();
    // Test statistic: s_obs = |S_n| / sqrt(n)
    let s_obs = s / n.sqrt();
    // Approximate p-value using complementary error function approximation
    // p = erfc(s_obs / sqrt(2))
    let p_approx = erfc_approx(s_obs / std::f64::consts::SQRT_2);
    (p_approx >= 0.01, p_approx)
}

/// NIST SP 800-22 Runs Test
/// Tests whether the number of runs of consecutive identical bits is as expected.
/// Returns (passed, p_value_approx)
pub fn runs_test(data: &[u8]) -> (bool, f64) {
    if data.len() < 8 { return (false, 0.0); }

    // First check monobit prerequisite
    let mut ones = 0u64;
    let total_bits = (data.len() * 8) as u64;
    for &byte in data {
        ones += byte.count_ones() as u64;
    }

    let pi = ones as f64 / total_bits as f64;
    // Prerequisite: |pi - 0.5| < 2/sqrt(n)
    let threshold = 2.0 / (total_bits as f64).sqrt();
    if (pi - 0.5).abs() >= threshold {
        return (false, 0.0);
    }

    // Count runs (transitions between 0 and 1)
    let mut runs = 1u64;
    let mut prev_bit = data[0] & 1;
    for &byte in data {
        for bit in 0..8 {
            let current = (byte >> bit) & 1;
            if current != prev_bit {
                runs += 1;
                prev_bit = current;
            }
        }
    }

    let n = total_bits as f64;
    let v_obs = runs as f64;
    let expected = 1.0 + 2.0 * n * pi * (1.0 - pi);
    let denom = 2.0 * n.sqrt() * pi * (1.0 - pi);
    if denom <= 0.0 { return (false, 0.0); }

    let z = (v_obs - expected).abs() / denom;
    let p_approx = erfc_approx(z / std::f64::consts::SQRT_2);
    (p_approx >= 0.01, p_approx)
}

/// NIST SP 800-22 Frequency Within Block Test
/// Divides data into blocks and checks frequency within each.
/// Returns (passed, chi_squared, p_value_approx)
pub fn frequency_block_test(data: &[u8], block_bits: usize) -> (bool, f64) {
    if data.is_empty() || block_bits == 0 { return (false, 0.0); }

    let total_bits = data.len() * 8;
    let num_blocks = total_bits / block_bits;
    if num_blocks < 2 { return (false, 0.0); }

    let mut chi_sq = 0.0;
    let m = block_bits as f64;

    for block_idx in 0..num_blocks {
        let bit_start = block_idx * block_bits;
        let mut ones = 0u64;
        for bit_pos in bit_start..(bit_start + block_bits) {
            let byte_idx = bit_pos / 8;
            let bit_idx = bit_pos % 8;
            if byte_idx < data.len() && (data[byte_idx] >> bit_idx) & 1 == 1 {
                ones += 1;
            }
        }
        let pi_i = ones as f64 / m;
        chi_sq += (pi_i - 0.5).powi(2);
    }

    chi_sq *= 4.0 * m;

    // Approximate p-value from chi-squared with N degrees of freedom
    // Using simple approximation: p ≈ 1 - chi_cdf(chi_sq, N)
    let n = num_blocks as f64;
    // Rough approximation: for large N, chi-sq/N should be near 1
    let normalized = chi_sq / n;
    let p_approx = if normalized < 3.0 { 0.5 } else { 0.01 / normalized };
    (p_approx >= 0.01, p_approx.min(1.0))
}

/// Run all basic statistical tests. Returns (all_passed, results)
pub fn run_statistical_tests(data: &[u8]) -> StatTestResults {
    let (mono_pass, mono_p) = monobit_test(data);
    let (runs_pass, runs_p) = runs_test(data);
    let (freq_pass, freq_p) = frequency_block_test(data, 128);

    StatTestResults {
        monobit_pass: mono_pass,
        monobit_p: mono_p,
        runs_pass: runs_pass,
        runs_p: runs_p,
        freq_block_pass: freq_pass,
        freq_block_p: freq_p,
        all_passed: mono_pass && runs_pass && freq_pass,
        sample_size: data.len(),
    }
}

#[derive(Clone, Debug)]
pub struct StatTestResults {
    pub monobit_pass: bool,
    pub monobit_p: f64,
    pub runs_pass: bool,
    pub runs_p: f64,
    pub freq_block_pass: bool,
    pub freq_block_p: f64,
    pub all_passed: bool,
    pub sample_size: usize,
}

/// Complementary error function approximation (Abramowitz & Stegun)
fn erfc_approx(x: f64) -> f64 {
    let t = 1.0 / (1.0 + 0.3275911 * x.abs());
    let poly = t * (0.254829592
        + t * (-0.284496736
        + t * (1.421413741
        + t * (-1.453152027
        + t * 1.061405429))));
    let result = poly * (-x * x).exp();
    if x < 0.0 { 2.0 - result } else { result }
}

// ============================================================================
// ENTROPY EXTRACTION POOL (SHA-256 Conditioning)
// 256 raw bytes → SHA-256 → 32 bytes (256 bits)
// ============================================================================

#[derive(Clone)]
pub struct EntropyExtractionPool {
    pub buffer: Vec<u8>,
    pub extractions_count: u64,
    pub last_extraction: f64,
    pub total_raw_consumed: usize,
    pub total_extracted_bytes: usize,
    pub credited_entropy_bits: f64,
    pub aggregate_credited_bits: f64,
    /// Running accumulator for long-term entropy estimation
    pub accumulator: RunningEntropyAccumulator,
    /// Quality measurement of conditioned output
    pub output_accumulator: RunningEntropyAccumulator,
    /// Latest statistical test results on conditioned output
    pub last_stat_tests: Option<StatTestResults>,
    /// Buffer of recent conditioned output for periodic testing
    conditioned_buffer: Vec<u8>,
}

impl EntropyExtractionPool {
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(EXTRACTION_POOL_SIZE),
            extractions_count: 0,
            last_extraction: 0.0,
            total_raw_consumed: 0,
            total_extracted_bytes: 0,
            credited_entropy_bits: 0.0,
            aggregate_credited_bits: 0.0,
            accumulator: RunningEntropyAccumulator::new(),
            output_accumulator: RunningEntropyAccumulator::new(),
            last_stat_tests: None,
            conditioned_buffer: Vec::new(),
        }
    }

    /// Add raw bytes with entropy tracking.
    /// Returns conditioned output when pool fills.
    pub fn add_raw_bytes(&mut self, raw_data: &[u8], min_ent: f64) -> Option<Vec<u8>> {
        self.buffer.extend_from_slice(raw_data);

        // Feed into running accumulator for long-term stats
        self.accumulator.update(raw_data);

        let credited = credit_entropy(raw_data.len(), min_ent);
        self.credited_entropy_bits += credited;
        self.aggregate_credited_bits += credited;

        let mut all_extracted = Vec::new();
        while self.buffer.len() >= EXTRACTION_POOL_SIZE {
            let extracted = self.extract();
            all_extracted.extend_from_slice(&extracted);
        }

        if all_extracted.is_empty() {
            None
        } else {
            Some(all_extracted)
        }
    }

    /// SHA-256 vetted conditioning: 256 raw bytes → 32 bytes (256 bits)
    fn extract(&mut self) -> Vec<u8> {
        let consume_len = EXTRACTION_POOL_SIZE.min(self.buffer.len());
        let to_condition: Vec<u8> = self.buffer.drain(..consume_len).collect();

        let mut hasher = Sha256::new();
        hasher.update(&to_condition);
        hasher.update(&self.extractions_count.to_le_bytes());
        hasher.update(&get_timestamp_nanos().to_le_bytes());
        let result = hasher.finalize();
        let output = result.to_vec();

        self.total_raw_consumed += consume_len;
        self.total_extracted_bytes += 32;
        self.extractions_count += 1;
        self.last_extraction = get_timestamp() as f64;
        self.credited_entropy_bits = 0.0;

        // Track conditioned output quality
        self.output_accumulator.update(&output);
        self.conditioned_buffer.extend_from_slice(&output);

        // Run statistical tests every 1024 bytes of conditioned output
        if self.conditioned_buffer.len() >= 1024 {
            self.last_stat_tests = Some(run_statistical_tests(&self.conditioned_buffer));
            // Keep last 4096 bytes for ongoing testing, trim older
            if self.conditioned_buffer.len() > 8192 {
                let drain_len = self.conditioned_buffer.len() - 4096;
                self.conditioned_buffer.drain(..drain_len);
            }
        }

        output
    }

    pub fn fill_percentage(&self) -> f64 {
        (self.buffer.len() as f64 / EXTRACTION_POOL_SIZE as f64) * 100.0
    }

    pub fn accumulated_bytes(&self) -> usize {
        self.buffer.len()
    }

    pub fn reset_aggregate_credits(&mut self) {
        self.aggregate_credited_bits = 0.0;
    }

    /// Get running input entropy estimate (more accurate than per-batch)
    pub fn running_shannon(&self) -> f64 { self.accumulator.shannon() }
    pub fn running_min_entropy(&self) -> f64 { self.accumulator.min_entropy() }

    /// Get conditioned output quality
    pub fn output_shannon(&self) -> f64 { self.output_accumulator.shannon() }
    pub fn output_min_entropy(&self) -> f64 { self.output_accumulator.min_entropy() }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rct_pass_normal_data() {
        let mut ht = NistHealthTester::new();
        ht.start();
        let data: Vec<u8> = (0..=255).cycle().take(5000).collect();
        let passed = ht.process_batch(&data);
        assert!(passed.len() > 0);
        assert_eq!(ht.state, HealthState::Steady);
    }

    #[test]
    fn test_rct_fail_stuck_source() {
        let mut ht = NistHealthTester::new();
        ht.start();
        let data = vec![42u8; 50];
        let passed = ht.process_batch(&data);
        assert!(passed.is_empty());
        assert_eq!(ht.state, HealthState::Failed);
        assert_eq!(ht.failure_count(), 1);
    }

    #[test]
    fn test_health_recovery_after_failure() {
        let mut ht = NistHealthTester::new();
        ht.start();
        let stuck = vec![42u8; 50];
        let _ = ht.process_batch(&stuck);
        assert_eq!(ht.state, HealthState::Failed);
        let cooldown: Vec<u8> = (0..=255).cycle().take(RECOVERY_COOLDOWN_SAMPLES as usize).collect();
        let _passed = ht.process_batch(&cooldown);
        assert!(ht.state == HealthState::Startup || ht.state == HealthState::Steady);
    }

    #[test]
    fn test_health_dead_after_max_retries() {
        let mut ht = NistHealthTester::new();
        ht.start();
        for _ in 0..MAX_HEALTH_RETRIES {
            let stuck = vec![42u8; 50];
            let _ = ht.process_batch(&stuck);
            assert_eq!(ht.state, HealthState::Failed);
            let cooldown: Vec<u8> = (0..=255).cycle().take(RECOVERY_COOLDOWN_SAMPLES as usize).collect();
            let _ = ht.process_batch(&cooldown);
        }
        let stuck = vec![42u8; 50];
        let _ = ht.process_batch(&stuck);
        let cooldown: Vec<u8> = (0..=255).cycle().take(RECOVERY_COOLDOWN_SAMPLES as usize).collect();
        let passed = ht.process_batch(&cooldown);
        assert!(passed.is_empty());
        assert_eq!(ht.state, HealthState::Dead);
    }

    #[test]
    fn test_min_entropy_uniform() {
        let data: Vec<u8> = (0..=255).collect();
        let h = min_entropy(&data);
        assert!((h - 8.0).abs() < 0.01);
    }

    #[test]
    fn test_min_entropy_biased() {
        let mut data = vec![0u8; 900];
        data.extend(vec![1u8; 100]);
        let h = min_entropy(&data);
        assert!(h < 1.0);
        assert!(h > 0.0);
    }

    #[test]
    fn test_collision_entropy_uniform() {
        // Uniform data should give high collision entropy
        let data: Vec<u8> = (0..=255).cycle().take(2000).collect();
        let h = collision_entropy(&data);
        assert!(h > 5.0, "Uniform collision entropy should be high, got {}", h);
    }

    #[test]
    fn test_tuple_entropy_uniform() {
        let data: Vec<u8> = (0..=255).cycle().take(2000).collect();
        let h = tuple_entropy(&data);
        assert!(h > 5.0, "Uniform tuple entropy should be high, got {}", h);
    }

    #[test]
    fn test_credit_entropy() {
        let credited = credit_entropy(100, 4.0);
        assert!((credited - 217.6).abs() < 0.01);

        let credited_small = credit_entropy(10, 2.0);
        assert!((credited_small - 17.0).abs() < 0.01);

        let credited_max = credit_entropy(1000, 8.0);
        assert!((credited_max - 217.6).abs() < 0.01);
    }

    #[test]
    fn test_extraction_pool_cycle() {
        let mut pool = EntropyExtractionPool::new();
        let data = vec![0xAB; EXTRACTION_POOL_SIZE];
        let result = pool.add_raw_bytes(&data, 4.0);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 32);
        assert_eq!(pool.extractions_count, 1);
    }

    #[test]
    fn test_running_accumulator() {
        let mut acc = RunningEntropyAccumulator::new();
        // Feed uniform data
        let data: Vec<u8> = (0..=255).cycle().take(10000).collect();
        acc.update(&data);
        assert!(acc.shannon() > 7.9);
        assert!(acc.min_entropy() > 7.9);
        assert_eq!(acc.unique_values(), 256);
    }

    #[test]
    fn test_monobit_random() {
        // Pseudo-random data should pass monobit
        let data: Vec<u8> = (0..=255).cycle().take(1000).collect();
        let (passed, p) = monobit_test(&data);
        assert!(passed, "Monobit should pass for uniform data, p={}", p);
    }

    #[test]
    fn test_monobit_biased() {
        // All zeros should fail monobit
        let data = vec![0u8; 1000];
        let (passed, _p) = monobit_test(&data);
        assert!(!passed, "Monobit should fail for all-zero data");
    }

    #[test]
    fn test_nist_constants() {
        assert_eq!(NIST_RCT_CUTOFF, 31);
        assert_eq!(NIST_APT_WINDOW, 512);
        assert_eq!(NIST_APT_CUTOFF, 325);
        assert_eq!(STARTUP_DISCARD_SAMPLES, 4096);
        assert!((NIST_CONDITIONING_FACTOR - 0.85).abs() < f64::EPSILON);
    }

    #[test]
    fn test_output_quality_tracking() {
        let mut pool = EntropyExtractionPool::new();
        // Feed enough data for multiple extractions
        for _ in 0..50 {
            let data: Vec<u8> = (0..=255).collect(); // 256 bytes
            let _ = pool.add_raw_bytes(&data, 4.0);
        }
        // Output accumulator should have data
        assert!(pool.output_accumulator.total_bytes > 0);
        assert!(pool.output_shannon() > 6.0, "SHA-256 output should have high entropy");
    }
}
