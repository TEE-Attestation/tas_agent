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
    hash_and_build_gpu_evidence(entries)
}

/// Transform raw per-GPU SDK evidence entries into the TAS component-evidence
/// payload and the concatenated SHA-512 hash chain.
///
/// Split out from `collect_and_hash_gpu_evidence` so the hardware-independent
/// parsing and hashing logic can be unit-tested without a GPU.
fn hash_and_build_gpu_evidence(
    entries: Vec<serde_json::Value>,
) -> Result<(Value, Vec<u8>), String> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    /// Standard-base64 encode, mirroring the engine used in production.
    fn b64(raw: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(raw)
    }

    /// Build a raw SDK entry shaped like the NVAT SDK JSON: an object whose
    /// `evidence` field is base64 of the raw per-GPU evidence bytes.
    fn raw_entry(raw_evidence: &[u8]) -> serde_json::Value {
        serde_json::json!({ "evidence": b64(raw_evidence) })
    }

    #[test]
    fn gpu_evidence_serializes_with_field_names() {
        let ev = GpuEvidence {
            device_type: "gpu-nvidia".to_string(),
            device_index: 3,
            evidence: "abc".to_string(),
        };
        let v = serde_json::to_value(&ev).unwrap();
        assert_eq!(v["type"].as_str(), Some("gpu-nvidia"));
        assert_eq!(v["device-index"].as_u64(), Some(3));
        assert_eq!(v["evidence"].as_str(), Some("abc"));
    }

    #[test]
    fn empty_entries_returns_no_gpus_error() {
        let err = hash_and_build_gpu_evidence(Vec::new()).unwrap_err();
        assert!(err.contains("no GPUs found"), "unexpected error: {err}");
    }

    #[test]
    fn single_gpu_hash_matches_and_payload_shape_is_correct() {
        let raw = b"raw-gpu-evidence-bytes";
        let entry = raw_entry(raw);
        let (json, hashes) = hash_and_build_gpu_evidence(vec![entry.clone()]).unwrap();

        // Hash chain is exactly one SHA-512 of the decoded inner evidence.
        assert_eq!(hashes.len(), 64);
        assert_eq!(hashes, crate::crypto::hash_evidence(raw));

        // Payload shape: one GPU entry, indexed 0, tagged gpu-nvidia.
        let gpus = json["gpu"].as_array().unwrap();
        assert_eq!(gpus.len(), 1);
        assert_eq!(gpus[0]["type"].as_str(), Some("gpu-nvidia"));
        assert_eq!(gpus[0]["device-index"].as_u64(), Some(0));

        // The emitted `evidence` is base64 of the whole original entry JSON.
        let emitted_b64 = gpus[0]["evidence"].as_str().unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(emitted_b64)
            .unwrap();
        let decoded_json: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(decoded_json, entry);
    }

    #[test]
    fn multiple_gpus_preserve_order_and_concatenate_hashes() {
        let raw0 = b"gpu-0-evidence";
        let raw1 = b"gpu-1-evidence";
        let (json, hashes) =
            hash_and_build_gpu_evidence(vec![raw_entry(raw0), raw_entry(raw1)]).unwrap();

        // Two SHA-512 hashes, concatenated in device order.
        assert_eq!(hashes.len(), 128);
        assert_eq!(&hashes[..64], crate::crypto::hash_evidence(raw0).as_slice());
        assert_eq!(&hashes[64..], crate::crypto::hash_evidence(raw1).as_slice());

        // Device indices are assigned by position.
        let gpus = json["gpu"].as_array().unwrap();
        assert_eq!(gpus.len(), 2);
        assert_eq!(gpus[0]["device-index"].as_u64(), Some(0));
        assert_eq!(gpus[1]["device-index"].as_u64(), Some(1));
    }

    #[test]
    fn missing_evidence_field_is_an_error() {
        let entry = serde_json::json!({ "not-evidence": "x" });
        let err = hash_and_build_gpu_evidence(vec![entry]).unwrap_err();
        assert!(
            err.contains("missing 'evidence' field"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn invalid_base64_evidence_is_an_error() {
        // '*' is not part of the standard base64 alphabet.
        let entry = serde_json::json!({ "evidence": "not*valid*base64" });
        let err = hash_and_build_gpu_evidence(vec![entry]).unwrap_err();
        assert!(err.contains("Failed to decode"), "unexpected error: {err}");
    }
}
