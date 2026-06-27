// TEE Attestation Service Agent
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// Feature-gated key generation support for the TAS certificate flow.

use rand::rngs::OsRng;
#[cfg(test)]
use rsa::pkcs8::EncodePublicKey;
use rsa::{
    pkcs1::EncodeRsaPublicKey,
    pkcs1v15::SigningKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding},
    RsaPrivateKey, RsaPublicKey,
};
use sha2::Sha256;
use std::error::Error;

const RSA_4096_BITS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(dead_code)]
pub enum KeyAlgorithm {
    #[default]
    Rsa4096,
    EccP384,
}

#[derive(Clone)]
pub struct AgentKey {
    public_key: RsaPublicKey,
    private_key: RsaPrivateKey,
}

impl AgentKey {
    pub fn generate(algorithm: KeyAlgorithm) -> Result<Self, Box<dyn Error>> {
        match algorithm {
            KeyAlgorithm::Rsa4096 => {
                let mut rng = OsRng;
                let private_key = RsaPrivateKey::new(&mut rng, RSA_4096_BITS)?;
                let public_key = RsaPublicKey::from(&private_key);
                Ok(Self {
                    public_key,
                    private_key,
                })
            }
            KeyAlgorithm::EccP384 => Err("ECC P-384 key generation is not implemented yet".into()),
        }
    }

    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, Box<dyn Error>> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(pem)
            .map_err(|e| format!("Failed to parse PKCS#8 private key PEM: {}", e))?;
        let public_key = RsaPublicKey::from(&private_key);
        Ok(Self {
            public_key,
            private_key,
        })
    }

    pub fn private_key_to_pkcs8_pem(&self) -> Result<String, Box<dyn Error>> {
        let pem = self
            .private_key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| format!("Failed to convert private key to PKCS#8 PEM: {}", e))?;
        Ok(pem.to_string())
    }

    pub fn public_key_to_der(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let der = self
            .public_key
            .to_pkcs1_der()
            .map_err(|e| format!("Failed to convert public key to DER: {}", e))?;
        Ok(der.to_vec())
    }

    #[cfg(test)]
    fn public_key_to_spki_der(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let der = self
            .public_key
            .to_public_key_der()
            .map_err(|e| format!("Failed to convert public key to SPKI DER: {}", e))?;
        Ok(der.as_bytes().to_vec())
    }

    pub fn rsa_4096_signing_key(&self) -> SigningKey<Sha256> {
        SigningKey::<Sha256>::new(self.private_key.clone())
    }

    #[cfg(test)]
    fn public_key(&self) -> &RsaPublicKey {
        &self.public_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::DecodePublicKey;
    use rsa::traits::PublicKeyParts;

    #[test]
    fn generates_rsa_4096_key() {
        let key = AgentKey::generate(KeyAlgorithm::Rsa4096).unwrap();
        assert_eq!(key.public_key().n().bits(), RSA_4096_BITS);
    }

    #[test]
    fn exports_pkcs1_public_key_der() {
        let key = AgentKey::generate(KeyAlgorithm::Rsa4096).unwrap();
        let der = key.public_key_to_der().unwrap();
        assert!(!der.is_empty());
        assert_eq!(der[0], 0x30);
    }

    #[test]
    fn exports_spki_public_key_der() {
        let key = AgentKey::generate(KeyAlgorithm::Rsa4096).unwrap();
        let spki_der = key.public_key_to_spki_der().unwrap();
        assert!(!spki_der.is_empty());
        assert_eq!(spki_der[0], 0x30);
        RsaPublicKey::from_public_key_der(&spki_der).unwrap();
        let pkcs1_der = key.public_key_to_der().unwrap();
        assert_ne!(spki_der, pkcs1_der);
    }

    #[test]
    fn private_key_pkcs8_roundtrip_preserves_public_key() {
        let original = AgentKey::generate(KeyAlgorithm::Rsa4096).unwrap();
        let pem = original.private_key_to_pkcs8_pem().unwrap();
        let restored = AgentKey::from_pkcs8_pem(&pem).unwrap();

        assert_eq!(
            original.public_key_to_spki_der().unwrap(),
            restored.public_key_to_spki_der().unwrap()
        );
    }

    #[test]
    fn rejects_reserved_ecc_algorithm() {
        let result = AgentKey::generate(KeyAlgorithm::EccP384);
        assert!(result.is_err());
        assert!(result
            .err()
            .unwrap()
            .to_string()
            .contains("not implemented"));
    }
}
