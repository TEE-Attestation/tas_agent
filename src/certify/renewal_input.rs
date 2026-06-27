// TEE Attestation Service Agent
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// Renewal input loading and framing checks.

use crate::certify::material_writer::{cert_path, key_path};
use anyhow::{anyhow, Context, Result};
use std::fs;
use std::path::Path;

pub fn load_renew_cert_from_dir(write_dir: &Path) -> Result<String> {
    let path = cert_path(write_dir);
    let cert_pem = fs::read_to_string(&path)
        .with_context(|| format!("failed to read renewal certificate {:?}", path))?;
    validate_leaf_cert_pem_framing(&cert_pem)?;
    Ok(cert_pem)
}

pub fn load_private_key_from_dir(write_dir: &Path) -> Result<String> {
    let path = key_path(write_dir);
    fs::read_to_string(&path)
        .with_context(|| format!("failed to read renewal private key {:?}", path))
}

pub fn validate_leaf_cert_pem_framing(cert_pem: &str) -> Result<()> {
    let trimmed = cert_pem.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("renew_cert PEM is empty"));
    }

    if !trimmed.starts_with("-----BEGIN CERTIFICATE-----") {
        return Err(anyhow!(
            "renew_cert PEM must start with BEGIN CERTIFICATE block"
        ));
    }

    if !trimmed.ends_with("-----END CERTIFICATE-----") {
        return Err(anyhow!(
            "renew_cert PEM must end with END CERTIFICATE block"
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_basic_leaf_certificate_framing() {
        let pem = "-----BEGIN CERTIFICATE-----\nZmFrZQo=\n-----END CERTIFICATE-----\n";
        assert!(validate_leaf_cert_pem_framing(pem).is_ok());
    }

    #[test]
    fn rejects_empty_or_invalid_framing() {
        assert!(validate_leaf_cert_pem_framing("").is_err());
        assert!(validate_leaf_cert_pem_framing("-----BEGIN FOO-----").is_err());
    }
}
