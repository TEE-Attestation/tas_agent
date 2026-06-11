// TEE Attestation Service Agent
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// GPU attestation evidence collection using the NVIDIA Attestation SDK.

use log::debug;
use nv_attestation_sdk::{GpuEvidenceSource, Nonce, NvatSdk};
use serde::Serialize;
use serde_json::Value;

/// A single GPU's attestation evidence, ready to include in component-evidence.
#[derive(Debug, Clone, Serialize)]
pub struct GpuEvidence {
    #[serde(rename = "type")]
    pub device_type: String,
    #[serde(rename = "device-index")]
    pub device_index: u32,
    #[serde(rename = "evidence")]
    pub evidence: String,
}

/// Collect raw per-GPU evidence entries from the NVIDIA Attestation SDK.
///
/// Returns the parsed SDK JSON entries (one per GPU). Empty if no GPUs found.
fn collect_raw_entries(nonce_hex: &str) -> Result<Vec<serde_json::Value>, String> {
    let _sdk =
        NvatSdk::init_default().map_err(|e| format!("Failed to initialize NVAT SDK: {}", e))?;

    debug!("NVAT SDK version: {}", NvatSdk::version());

    let nonce = Nonce::from_hex(nonce_hex)
        .map_err(|e| format!("Failed to create nonce from hex: {}", e))?;

    let source = GpuEvidenceSource::from_nvml()
        .map_err(|e| format!("Failed to create GPU evidence source: {}", e))?;

    let collection = source
        .collect(&nonce)
        .map_err(|e| format!("Failed to collect GPU evidence: {}", e))?;

    if collection.is_empty() {
        debug!("No GPU evidence collected (no GPUs found)");
        return Ok(Vec::new());
    }

    debug!("Collected evidence from {} GPU(s)", collection.len());

    let json_str = collection
        .to_json()
        .map_err(|e| format!("Failed to serialize GPU evidence: {}", e))?;

    debug!("Raw GPU evidence JSON: {}", json_str);

    let entries: Vec<serde_json::Value> = serde_json::from_str(&json_str)
        .map_err(|e| format!("Failed to parse GPU evidence JSON: {}", e))?;

    Ok(entries)
}

/// Collect GPU attestation evidence and compute the per-GPU hash chain.
///
/// Returns `(evidence_json, component_hashes)` where `evidence_json` is the
/// JSON payload to send to TAS and `component_hashes` is the concatenated
/// SHA-512 hashes of each GPU's evidence (ordered by device index).
pub fn collect_and_hash_gpu_evidence(nonce_hex: &str) -> Result<(Value, Vec<u8>), String> {
    let entries = collect_raw_entries(nonce_hex)?;

    if entries.is_empty() {
        return Err("GPU attestation enabled but no GPUs found".to_string());
    }

    debug!("Collected evidence from {} GPU(s)", entries.len());

    let mut gpu_entries = Vec::new();
    let mut hashes: Vec<u8> = Vec::new();

    for (idx, entry) in entries.iter().enumerate() {
        // Extract the inner "evidence" field and decode to raw bytes for hashing
        let inner_b64 = entry["evidence"]
            .as_str()
            .ok_or_else(|| format!("GPU {} entry missing 'evidence' field", idx))?;

        let raw_evidence =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, inner_b64)
                .map_err(|e| format!("Failed to decode GPU {} evidence: {}", idx, e))?;

        let hash = crate::crypto::hash_evidence(&raw_evidence);
        debug!("GPU {} evidence hash: {}", idx, hex::encode(&hash));
        hashes.extend_from_slice(&hash);

        // Build the GpuEvidence entry (base64-encode the full SDK JSON object)
        let evidence_str = serde_json::to_string(entry)
            .map_err(|e| format!("Failed to serialize GPU {} evidence: {}", idx, e))?;
        let evidence_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            evidence_str.as_bytes(),
        );

        gpu_entries.push(GpuEvidence {
            device_type: "gpu-nvidia".to_string(),
            device_index: idx as u32,
            evidence: evidence_b64,
        });
    }

    let evidence_json = serde_json::json!({
        "gpu": gpu_entries
    });

    Ok((evidence_json, hashes))
}
