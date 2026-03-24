// TEE Attestation Service Agent
//
// Copyright 2025 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// This module provides the client application with the ability do cryptographic operations.

use base64::Engine;
use rsa::{
    pkcs1::EncodeRsaPrivateKey, pkcs1::EncodeRsaPublicKey, sha2::Sha256, Oaep, RsaPrivateKey,
    RsaPublicKey,
};

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce,
};

use sha2::{Digest, Sha512};
use std::error::Error;

//TODO: Add own error type, instead of using Box<dyn Error>
//TODO: Add logging
//TODO: Add tests
//TODO: Add documentation

#[derive(Debug, Clone)]

/// Struct to hold the RSA key pair
pub struct RsaKey {
    public_key: RsaPublicKey,
    private_key: RsaPrivateKey,
}
// Custom Display trait for RsaKey
impl std::fmt::Display for RsaKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RsaKey {{ public_key: {:?}, private_key: {:?} }}",
            self.public_key
                .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
                .unwrap(),
            self.private_key
                .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
                .unwrap()
        )
    }
}
impl RsaKey {
    /// Encrypt a message using the public key
    #[allow(dead_code)]
    fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let padding = Oaep::new::<Sha256>();
        let encrypted_message =
            self.public_key
                .encrypt(&mut rand::thread_rng(), padding, message)?;
        Ok(encrypted_message)
    }

    /// Decrypts a message using the private key
    #[allow(dead_code)]
    pub fn decrypt(&self, encrypted_message: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let padding = Oaep::new::<Sha256>();
        let decrypted_message = self.private_key.decrypt(padding, encrypted_message)?;
        Ok(decrypted_message)
    }

    /// Converts public key to DER format
    pub fn public_key_to_der(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let der = self
            .public_key
            .to_pkcs1_der()
            .map_err(|e| format!("Failed to convert public key to DER: {}", e))?;
        Ok(der.to_vec())
    }

    /// Encodes DER public key to base64
    pub fn public_key_to_base64(&self) -> Result<String, Box<dyn Error>> {
        let der = self.public_key_to_der()?;
        let base64 = Engine::encode(&base64::engine::general_purpose::STANDARD, &der);
        Ok(base64)
    }

    /// Unwraps the secret's AES encryption key
    pub fn unwrap_key(&self, encrypted_key: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let decrypted_key = self.decrypt(encrypted_key)?;
        Ok(decrypted_key)
    }
}

fn generate_key_pair(key_bits: usize) -> Result<(RsaPublicKey, RsaPrivateKey), Box<dyn Error>> {
    let mut rng = rand::thread_rng();
    // Return error is key bits is not 2048 or 3072 or 4096
    if key_bits != 2048 && key_bits != 3072 && key_bits != 4096 {
        return Err("Key bits must be 2048, 3072 or 4096".into());
    }

    let bits = key_bits;
    let private_key = RsaPrivateKey::new(&mut rng, bits)?;
    let public_key = RsaPublicKey::from(&private_key);
    Ok((public_key, private_key))
}

pub fn generate_wrapping_key() -> Result<RsaKey, Box<dyn Error>> {
    let (public_key, private_key) = generate_key_pair(2048)?;
    Ok(RsaKey {
        public_key,
        private_key,
    })
}
#[allow(dead_code)]
pub fn decrypt_secret_with_aes_key(
    aes_key: &[u8],
    iv: &[u8],
    ciphertext: &mut [u8],
    tag: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    // AES-256-GCM decryption
    // Check if the key length is 32 bytes (256 bits)
    if aes_key.len() != 32 {
        return Err("AES key length must be 32 bytes (256 bits)".into());
    }
    // Check if the IV length is 16 bytes (128 bits)
    if iv.len() != 12 {
        return Err("AES-GCM IV length must be 16 bytes (128 bits)".into());
    }

    let cipher = Aes256Gcm::new_from_slice(aes_key)?;
    let nonce = Nonce::from_slice(iv);
    cipher
        .decrypt_in_place_detached(nonce, b"", ciphertext, tag.into())
        .map_err(|e| format!("Decryption error: {:?}", e))?;
    Ok(ciphertext.to_vec())
}

#[allow(dead_code)]
pub fn encrypt_secret_with_aes_key(
    aes_key: &[u8],
    iv: &[u8],
    plaintext: &mut [u8],
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    // AES-256-GCM encryption
    // Check if the key length is 32 bytes (256 bits)
    if aes_key.len() != 32 {
        return Err("AES key length must be 32 bytes (256 bits)".into());
    }
    // Check if the IV (nonce) length is 12 bytes (96 bits) for GCM
    if iv.len() != 12 {
        return Err("AES-GCM IV length must be 12 bytes (96 bits)".into());
    }
    let cipher = Aes256Gcm::new_from_slice(aes_key)?;
    let nonce = Nonce::from_slice(iv);
    let tag = cipher
        .encrypt_in_place_detached(nonce, b"", plaintext)
        .map_err(|e| format!("Encryption error: {:?}", e))?;

    Ok((plaintext.to_vec(), tag.to_vec()))
}

/// Computes SHA-512(nonce || pubkey_der) for CPU-only key binding.
/// Returns raw 64-byte hash that fits exactly in REPORT_DATA (SEV-SNP / TDX).
pub fn compute_report_data_binding(nonce: &[u8], pubkey_der: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(nonce);
    hasher.update(pubkey_der);
    hasher.finalize().to_vec()
}

#[cfg(feature = "gpu-attestation")]
/// Computes SHA-512(nonce || pubkey_der || gpu_hashes) for composable attestation.
/// `gpu_hashes` is the pre-concatenated SHA-512 hashes of each GPU's evidence,
/// ordered by device index: SHA512(gpu0) || SHA512(gpu1) || ...
/// Returns raw 64-byte hash.
pub fn compute_report_data_binding_with_gpu(
    nonce: &[u8],
    pubkey_der: &[u8],
    gpu_hashes: &[u8],
) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(nonce);
    hasher.update(pubkey_der);
    hasher.update(gpu_hashes);
    hasher.finalize().to_vec()
}

#[cfg(feature = "gpu-attestation")]
/// Computes SHA-512 of a single GPU's raw attestation evidence.
/// Returns raw 64-byte hash. Called once per GPU before concatenation.
pub fn hash_gpu_evidence(raw_evidence: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(raw_evidence);
    hasher.finalize().to_vec()
}

//add tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_decryption() {
        let rsa_key = generate_wrapping_key().unwrap();
        let message = b"Hello, world!";
        let encrypted_message = rsa_key.encrypt(message).unwrap();
        let decrypted_message = rsa_key.decrypt(&encrypted_message).unwrap();
        assert_eq!(message.to_vec(), decrypted_message);
    }

    #[test]
    fn test_compute_report_data_binding_length() {
        let nonce = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let rsa_key = generate_wrapping_key().unwrap();
        let pubkey_der = rsa_key.public_key_to_der().unwrap();
        let binding = compute_report_data_binding(nonce, &pubkey_der);
        assert_eq!(
            binding.len(),
            64,
            "SHA-512 binding must be exactly 64 bytes"
        );
    }

    #[test]
    fn test_compute_report_data_binding_deterministic() {
        let nonce = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let rsa_key = generate_wrapping_key().unwrap();
        let pubkey_der = rsa_key.public_key_to_der().unwrap();
        let binding1 = compute_report_data_binding(nonce, &pubkey_der);
        let binding2 = compute_report_data_binding(nonce, &pubkey_der);
        assert_eq!(
            binding1, binding2,
            "Same inputs must produce the same binding"
        );
    }

    #[test]
    fn test_compute_report_data_binding_different_keys() {
        let nonce = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let key1 = generate_wrapping_key().unwrap();
        let key2 = generate_wrapping_key().unwrap();
        let der1 = key1.public_key_to_der().unwrap();
        let der2 = key2.public_key_to_der().unwrap();
        let binding1 = compute_report_data_binding(nonce, &der1);
        let binding2 = compute_report_data_binding(nonce, &der2);
        assert_ne!(
            binding1, binding2,
            "Different keys must produce different bindings"
        );
    }

    #[test]
    #[cfg(feature = "gpu-attestation")]
    fn test_compute_report_data_binding_with_gpu() {
        let nonce = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let rsa_key = generate_wrapping_key().unwrap();
        let pubkey_der = rsa_key.public_key_to_der().unwrap();
        let gpu0_evidence = b"gpu0_attestation_report_bytes";
        let gpu1_evidence = b"gpu1_attestation_report_bytes";
        let gpu0_hash = hash_gpu_evidence(gpu0_evidence);
        let gpu1_hash = hash_gpu_evidence(gpu1_evidence);
        let mut gpu_combined = gpu0_hash.clone();
        gpu_combined.extend_from_slice(&gpu1_hash);
        let binding = compute_report_data_binding_with_gpu(nonce, &pubkey_der, &gpu_combined);
        assert_eq!(binding.len(), 64, "Composable binding must be 64 bytes");
    }

    #[test]
    #[cfg(feature = "gpu-attestation")]
    fn test_hash_gpu_evidence_length() {
        let evidence = b"some_gpu_attestation_evidence";
        let hash = hash_gpu_evidence(evidence);
        assert_eq!(hash.len(), 64, "GPU evidence hash must be 64 bytes");
    }

    #[test]
    #[cfg(feature = "gpu-attestation")]
    fn test_gpu_binding_changes_cpu_hash() {
        let nonce = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let rsa_key = generate_wrapping_key().unwrap();
        let pubkey_der = rsa_key.public_key_to_der().unwrap();
        let cpu_only = compute_report_data_binding(nonce, &pubkey_der);
        let gpu_hash = hash_gpu_evidence(b"gpu_evidence");
        let with_gpu = compute_report_data_binding_with_gpu(nonce, &pubkey_der, &gpu_hash);
        assert_ne!(
            cpu_only, with_gpu,
            "Adding GPU evidence must change the CPU binding"
        );
    }

    #[test]
    fn test_aes_decryption() {
        let aes_key = [0u8; 32]; // 256-bit key
        let iv = [0u8; 12]; // 96-bit IV (nonce) for AES-GCM
        let plaintext = b"Hello, world!".to_vec();
        let (mut ciphertext, tag) =
            encrypt_secret_with_aes_key(&aes_key, &iv, &mut plaintext.clone()).unwrap();
        let decrypted_data =
            decrypt_secret_with_aes_key(&aes_key, &iv, &mut ciphertext, &tag).unwrap();
        assert_eq!(b"Hello, world!".to_vec(), decrypted_data);
    }

    // --- public_key_to_der tests ---

    #[test]
    fn test_public_key_to_der_returns_valid_der() {
        let rsa_key = generate_wrapping_key().unwrap();
        let der = rsa_key.public_key_to_der().unwrap();
        // DER-encoded RSA public keys start with 0x30 (SEQUENCE tag)
        assert_eq!(der[0], 0x30, "DER encoding must start with SEQUENCE tag");
    }

    // --- public_key_to_base64 tests ---

    #[test]
    fn test_public_key_to_base64_valid() {
        let rsa_key = generate_wrapping_key().unwrap();
        let b64 = rsa_key.public_key_to_base64().unwrap();
        // Must be valid base64 that decodes to the same DER
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .unwrap();
        let der = rsa_key.public_key_to_der().unwrap();
        assert_eq!(decoded, der);
    }

    // --- unwrap_key roundtrip test ---

    #[test]
    fn test_unwrap_key_roundtrip() {
        let rsa_key = generate_wrapping_key().unwrap();
        let aes_key = b"0123456789abcdef0123456789abcdef"; // 32-byte AES key
        let encrypted = rsa_key.encrypt(aes_key).unwrap();
        let unwrapped = rsa_key.unwrap_key(&encrypted).unwrap();
        assert_eq!(unwrapped, aes_key.to_vec());
    }

    // --- generate_key_pair with different sizes ---

    #[test]
    fn test_generate_key_pair_invalid_size() {
        let result = generate_key_pair(1024);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("2048") || err.contains("3072") || err.contains("4096"));
    }

    #[test]
    fn test_generate_key_pair_2048() {
        let result = generate_key_pair(2048);
        assert!(result.is_ok());
    }

    // --- AES validation tests ---

    #[test]
    fn test_aes_decrypt_wrong_key_length() {
        let bad_key = [0u8; 16]; // 128-bit, should be 256-bit
        let iv = [0u8; 12];
        let mut ciphertext = vec![0u8; 16];
        let tag = [0u8; 16];
        let result = decrypt_secret_with_aes_key(&bad_key, &iv, &mut ciphertext, &tag);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("32 bytes"));
    }

    #[test]
    fn test_aes_decrypt_wrong_iv_length() {
        let key = [0u8; 32];
        let bad_iv = [0u8; 16]; // 128-bit, should be 96-bit
        let mut ciphertext = vec![0u8; 16];
        let tag = [0u8; 16];
        let result = decrypt_secret_with_aes_key(&key, &bad_iv, &mut ciphertext, &tag);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_encrypt_wrong_key_length() {
        let bad_key = [0u8; 16];
        let iv = [0u8; 12];
        let mut plaintext = b"test data".to_vec();
        let result = encrypt_secret_with_aes_key(&bad_key, &iv, &mut plaintext);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("32 bytes"));
    }

    #[test]
    fn test_aes_encrypt_wrong_iv_length() {
        let key = [0u8; 32];
        let bad_iv = [0u8; 16];
        let mut plaintext = b"test data".to_vec();
        let result = encrypt_secret_with_aes_key(&key, &bad_iv, &mut plaintext);
        assert!(result.is_err());
    }

    // --- compute_report_data_binding edge cases ---

    #[test]
    fn test_binding_different_nonces_produce_different_hashes() {
        let rsa_key = generate_wrapping_key().unwrap();
        let pubkey_der = rsa_key.public_key_to_der().unwrap();
        let nonce1 = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let nonce2 = b"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
        let binding1 = compute_report_data_binding(nonce1, &pubkey_der);
        let binding2 = compute_report_data_binding(nonce2, &pubkey_der);
        assert_ne!(binding1, binding2);
    }

    #[test]
    fn test_binding_empty_nonce() {
        let rsa_key = generate_wrapping_key().unwrap();
        let pubkey_der = rsa_key.public_key_to_der().unwrap();
        let binding = compute_report_data_binding(b"", &pubkey_der);
        assert_eq!(binding.len(), 64);
    }
}
