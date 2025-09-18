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
    fn public_key_to_der(&self) -> Result<Vec<u8>, Box<dyn Error>> {
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
    fn test_aes_decryption() {
        let aes_key = [0u8; 32]; // 256-bit key
        let iv = [0u8; 12]; // 96-bit IV (nonce) for AES-GCM
        let  plaintext = b"Hello, world!".to_vec();
        let (mut ciphertext, tag) =
            encrypt_secret_with_aes_key(&aes_key, &iv, &mut plaintext.clone()).unwrap();
        let decrypted_data =
            decrypt_secret_with_aes_key(&aes_key, &iv, &mut ciphertext, &tag).unwrap();
        assert_eq!(b"Hello, world!".to_vec(), decrypted_data);
    }
}
