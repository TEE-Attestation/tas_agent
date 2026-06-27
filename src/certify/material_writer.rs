// TEE Attestation Service Agent
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// Certificate material writer utilities for certify/renew lifecycle.

use anyhow::{anyhow, Context, Result};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const KEY_FILE: &str = "key.pem";
pub const CERT_FILE: &str = "cert.pem";
pub const CHAIN_FILE: &str = "chain.pem";
pub const CA_BUNDLE_FILE: &str = "ca-bundle.pem";

pub fn key_path(dir: &Path) -> PathBuf {
    dir.join(KEY_FILE)
}

pub fn cert_path(dir: &Path) -> PathBuf {
    dir.join(CERT_FILE)
}

pub fn chain_path(dir: &Path) -> PathBuf {
    dir.join(CHAIN_FILE)
}

pub fn ca_bundle_path(dir: &Path) -> PathBuf {
    dir.join(CA_BUNDLE_FILE)
}

pub fn write_initial_materials(
    dir: &Path,
    key_pem: &str,
    cert_pem: &str,
    chain_pem: &str,
    ca_bundle_pem: &str,
    force: bool,
) -> Result<()> {
    fs::create_dir_all(dir)
        .with_context(|| format!("failed to create output directory {:?}", dir))?;

    let key_path = key_path(dir);
    if force {
        write_atomic(&key_path, key_pem.as_bytes())?;
    } else {
        write_create_new(&key_path, key_pem.as_bytes())?;
    }

    write_atomic(&cert_path(dir), cert_pem.as_bytes())?;
    write_atomic(&chain_path(dir), chain_pem.as_bytes())?;
    write_atomic(&ca_bundle_path(dir), ca_bundle_pem.as_bytes())?;
    Ok(())
}

pub fn write_renewed_materials(
    dir: &Path,
    cert_pem: &str,
    chain_pem: &str,
    ca_bundle_pem: &str,
) -> Result<()> {
    if !key_path(dir).exists() {
        return Err(anyhow!(
            "renewal key file {:?} is missing; run --certify first",
            key_path(dir)
        ));
    }

    fs::create_dir_all(dir)
        .with_context(|| format!("failed to create output directory {:?}", dir))?;
    write_atomic(&cert_path(dir), cert_pem.as_bytes())?;
    write_atomic(&chain_path(dir), chain_pem.as_bytes())?;
    write_atomic(&ca_bundle_path(dir), ca_bundle_pem.as_bytes())?;
    Ok(())
}

fn write_create_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| {
            format!(
                "refusing to overwrite existing key file {:?}; pass --force to replace it",
                path
            )
        })?;
    file.write_all(bytes)
        .with_context(|| format!("failed writing {:?}", path))?;
    Ok(())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("path {:?} has no parent directory", path))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create parent directory {:?}", parent))?;

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| anyhow!("system time error: {}", e))?
        .as_nanos();
    let tmp_path = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().unwrap().to_string_lossy(),
        nanos
    ));

    {
        let mut tmp = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .with_context(|| format!("failed to create temporary file {:?}", tmp_path))?;
        tmp.write_all(bytes)
            .with_context(|| format!("failed writing temporary file {:?}", tmp_path))?;
        tmp.sync_all()
            .with_context(|| format!("failed syncing temporary file {:?}", tmp_path))?;
    }

    fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "failed replacing {:?} with temporary file {:?}",
            path, tmp_path
        )
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn writes_initial_materials_and_refuses_key_overwrite_without_force() {
        let dir = TempDir::new().unwrap();
        write_initial_materials(dir.path(), "key-1", "cert-1", "chain-1", "ca-1", false).unwrap();

        let err = write_initial_materials(dir.path(), "key-2", "cert-2", "chain-2", "ca-2", false)
            .unwrap_err();
        assert!(err.to_string().contains("--force"));
    }

    #[test]
    fn renew_updates_cert_materials_but_preserves_key() {
        let dir = TempDir::new().unwrap();
        write_initial_materials(dir.path(), "key-1", "cert-1", "chain-1", "ca-1", false).unwrap();

        write_renewed_materials(dir.path(), "cert-2", "chain-2", "ca-2").unwrap();

        assert_eq!(fs::read_to_string(key_path(dir.path())).unwrap(), "key-1");
        assert_eq!(fs::read_to_string(cert_path(dir.path())).unwrap(), "cert-2");
        assert_eq!(
            fs::read_to_string(chain_path(dir.path())).unwrap(),
            "chain-2"
        );
        assert_eq!(
            fs::read_to_string(ca_bundle_path(dir.path())).unwrap(),
            "ca-2"
        );
    }
}
