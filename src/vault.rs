//! NullMagnet Live v2 - vault.rs
//! Jupiter Labs - Encrypted Local Vault + Headscale Push
//!
//! Local vault: AES-256-GCM encrypted key bundles stored on disk.
//! Headscale push: Send encrypted bundles to remote vault nodes.
//!
//! Key derivation: SHA-256(password || salt) — simple for local use.
//! Each bundle gets a unique 96-bit nonce (random per encryption).

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use sha2::{Sha256, Digest};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

// ============================================================================
// VAULT ERROR TYPE
// ============================================================================

#[derive(Debug)]
pub enum VaultError {
    Io(std::io::Error),
    Crypto(String),
    Json(String),
    Network(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::Io(e) => write!(f, "IO: {}", e),
            VaultError::Crypto(e) => write!(f, "Crypto: {}", e),
            VaultError::Json(e) => write!(f, "JSON: {}", e),
            VaultError::Network(e) => write!(f, "Network: {}", e),
        }
    }
}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self { VaultError::Io(e) }
}

// ============================================================================
// ENCRYPTED VAULT FILE FORMAT
// ============================================================================
//
// File layout (.vault):
//   [16 bytes]  salt
//   [12 bytes]  nonce
//   [N bytes]   AES-256-GCM ciphertext (includes 16-byte auth tag)
//
// Key derivation:
//   key = SHA-256(password || salt)
//
// ============================================================================

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

/// Derive a 256-bit AES key from password + salt
fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(salt);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

// ============================================================================
// LOCAL VAULT OPERATIONS
// ============================================================================

/// Encrypt and save a PQC key bundle to the local vault
pub fn save_encrypted_bundle(
    vault_dir: &str,
    bundle_json: &str,
    password: &str,
    filename_hint: &str,
) -> Result<PathBuf, VaultError> {
    fs::create_dir_all(vault_dir)?;

    // Generate random salt and nonce
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);

    // Derive key
    let mut key = derive_key(password, &salt);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| VaultError::Crypto(format!("Key init: {}", e)))?;

    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let ciphertext = cipher.encrypt(nonce, bundle_json.as_bytes())
        .map_err(|e| VaultError::Crypto(format!("Encrypt: {}", e)))?;

    // Zeroize key material
    key.zeroize();

    // Write file: salt || nonce || ciphertext
    let vault_path = Path::new(vault_dir).join(format!("{}.vault", filename_hint));
    let mut file_data = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    file_data.extend_from_slice(&salt);
    file_data.extend_from_slice(&nonce_bytes);
    file_data.extend_from_slice(&ciphertext);
    fs::write(&vault_path, &file_data)?;

    Ok(vault_path)
}

/// Decrypt a vault file and return the JSON contents
pub fn read_encrypted_bundle(
    vault_path: &Path,
    password: &str,
) -> Result<String, VaultError> {
    let file_data = fs::read(vault_path)?;

    if file_data.len() < SALT_LEN + NONCE_LEN + 16 {
        return Err(VaultError::Crypto("File too small to be a valid vault file".into()));
    }

    let salt = &file_data[..SALT_LEN];
    let nonce_bytes = &file_data[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &file_data[SALT_LEN + NONCE_LEN..];

    let mut key = derive_key(password, salt);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| VaultError::Crypto(format!("Key init: {}", e)))?;

    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| VaultError::Crypto("Decryption failed — wrong password or corrupted file".into()))?;

    key.zeroize();

    String::from_utf8(plaintext)
        .map_err(|e| VaultError::Crypto(format!("UTF-8 decode: {}", e)))
}

/// List all vault files in a directory
pub fn list_vault_files(vault_dir: &str) -> Vec<(String, u64, String)> {
    let mut files = Vec::new();
    let dir = Path::new(vault_dir);

    if !dir.exists() { return files; }

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "vault").unwrap_or(false) {
                let name = path.file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                let modified = entry.metadata()
                    .and_then(|m| m.modified())
                    .map(|t| {
                        let duration = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
                        chrono::DateTime::from_timestamp(duration.as_secs() as i64, 0)
                            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                            .unwrap_or_else(|| "Unknown".to_string())
                    })
                    .unwrap_or_else(|_| "Unknown".to_string());
                files.push((name, size, modified));
            }
        }
    }

    // Also list unencrypted .json bundles (for backward compat with v1)
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                let name = path.file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                let modified = entry.metadata()
                    .and_then(|m| m.modified())
                    .map(|t| {
                        let duration = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
                        chrono::DateTime::from_timestamp(duration.as_secs() as i64, 0)
                            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                            .unwrap_or_else(|| "Unknown".to_string())
                    })
                    .unwrap_or_else(|_| "Unknown".to_string());
                files.push((format!("{} (unencrypted)", name), size, modified));
            }
        }
    }

    files.sort_by(|a, b| b.2.cmp(&a.2)); // Newest first
    files
}

// ============================================================================
// HEADSCALE VAULT PUSH
// Send an encrypted bundle to a remote Headscale vault target
// ============================================================================

/// Push an encrypted vault bundle to a Headscale target
pub fn push_to_headscale(
    ip: &str,
    port: u16,
    bundle_json: &str,
    vault_password: &str,
) -> Result<String, VaultError> {
    // Encrypt the bundle before sending
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);

    let mut key = derive_key(vault_password, &salt);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| VaultError::Crypto(format!("Key init: {}", e)))?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, bundle_json.as_bytes())
        .map_err(|e| VaultError::Crypto(format!("Encrypt: {}", e)))?;

    key.zeroize();

    // Build the payload
    let payload = serde_json::json!({
        "node": "nullmagnet_live",
        "version": "2.0",
        "type": "encrypted_vault_push",
        "timestamp": crate::entropy::get_timestamp(),
        "salt": hex::encode(&salt),
        "nonce": hex::encode(&nonce_bytes),
        "ciphertext": hex::encode(&ciphertext),
    });

    // Send to Headscale target
    let url = format!("http://{}:{}/vault/push", ip, port);
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| VaultError::Network(format!("Client: {}", e)))?;

    let resp = client.post(&url)
        .json(&payload)
        .send()
        .map_err(|e| VaultError::Network(format!("Send: {}", e)))?;

    if resp.status().is_success() {
        Ok(format!("Pushed to {}:{}", ip, port))
    } else {
        Err(VaultError::Network(format!("HTTP {}", resp.status())))
    }
}

/// Push an already-saved vault file to a Headscale target (raw encrypted bytes)
pub fn push_vault_file_to_headscale(
    ip: &str,
    port: u16,
    vault_path: &Path,
) -> Result<String, VaultError> {
    let file_data = fs::read(vault_path)?;

    let payload = serde_json::json!({
        "node": "nullmagnet_live",
        "version": "2.0",
        "type": "vault_file_push",
        "timestamp": crate::entropy::get_timestamp(),
        "filename": vault_path.file_name()
            .unwrap_or_default()
            .to_string_lossy(),
        "data": hex::encode(&file_data),
    });

    let url = format!("http://{}:{}/vault/push", ip, port);
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| VaultError::Network(format!("Client: {}", e)))?;

    let resp = client.post(&url)
        .json(&payload)
        .send()
        .map_err(|e| VaultError::Network(format!("Send: {}", e)))?;

    if resp.status().is_success() {
        Ok(format!("Pushed {} to {}:{}", vault_path.display(), ip, port))
    } else {
        Err(VaultError::Network(format!("HTTP {}", resp.status())))
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let bundle = r#"{"type":"test","key":"abc123"}"#;
        let password = "testpassword123";
        let dir = "/tmp/nullmagnet_vault_test";

        let _ = fs::remove_dir_all(dir);

        let path = save_encrypted_bundle(dir, bundle, password, "test_key")
            .expect("encrypt should succeed");

        assert!(path.exists());
        assert!(path.extension().unwrap() == "vault");

        let decrypted = read_encrypted_bundle(&path, password)
            .expect("decrypt should succeed");

        assert_eq!(decrypted, bundle);

        // Wrong password should fail
        let result = read_encrypted_bundle(&path, "wrongpassword");
        assert!(result.is_err());

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn test_list_vault_files() {
        let dir = "/tmp/nullmagnet_vault_list_test";
        let _ = fs::remove_dir_all(dir);
        fs::create_dir_all(dir).unwrap();

        // Create a test vault file
        save_encrypted_bundle(dir, "{}", "pass", "bundle_001").unwrap();
        save_encrypted_bundle(dir, "{}", "pass", "bundle_002").unwrap();

        let files = list_vault_files(dir);
        assert!(files.len() >= 2);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let key1 = derive_key("password", b"salt1234salt1234");
        let key2 = derive_key("password", b"salt1234salt1234");
        assert_eq!(key1, key2);

        let key3 = derive_key("password", b"differentsalt!!!");
        assert_ne!(key1, key3);
    }
}
