// TEE Attestation Service Agent
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// GPU TEE evidence gathering — pluggable provider trait and detection.

use log::debug;
use serde::Serialize;
use std::error::Error;

/// A single GPU's attestation evidence entry, sent to the TAS server.
#[derive(Debug, Clone, Serialize)]
pub struct GpuEvidenceEntry {
    /// GPU TEE type identifier (e.g. "nvidia-gpu-h100")
    #[serde(rename = "tee-type")]
    pub tee_type: String,
    /// Device index for deterministic ordering (0, 1, 2, …)
    #[serde(rename = "device-index")]
    pub device_index: u32,
    /// Base64-encoded GPU attestation report
    #[serde(rename = "tee-evidence")]
    pub tee_evidence: String,
}

/// Trait for pluggable GPU attestation evidence providers.
///
/// Each implementation represents a single GPU device capable of producing
/// attestation evidence.  Multiple instances (one per physical device) are
/// returned by [`detect_gpu_providers`].
#[allow(dead_code)]
pub trait GpuEvidenceProvider {
    /// Human-readable provider name (e.g. "nvidia-h100")
    fn provider_name(&self) -> &str;

    /// Device index — used for deterministic ordering of GPU evidence.
    fn device_id(&self) -> u32;

    /// Collect attestation evidence from this GPU.
    ///
    /// `nonce` is the raw TAS nonce (same value the CPU would receive).
    /// GPU report_data uses the raw nonce — no key binding on the GPU side
    /// (CPU binding covers the GPU evidence via the hash chain).
    fn get_evidence(&self, nonce: &str) -> Result<GpuEvidenceEntry, Box<dyn Error>>;
}

// ---------------------------------------------------------------------------
// Placeholder NVIDIA GPU provider (skeleton)
// ---------------------------------------------------------------------------

/// Skeleton provider for NVIDIA GPU TEE attestation.
///
/// Replace the body of `get_evidence` with the actual NVIDIA Attestation SDK
/// or local-verifier call when the SDK is available.
#[allow(dead_code)]
pub struct NvidiaGpuProvider {
    device_index: u32,
}

#[allow(dead_code)]
impl NvidiaGpuProvider {
    pub fn new(device_index: u32) -> Self {
        Self { device_index }
    }
}

impl GpuEvidenceProvider for NvidiaGpuProvider {
    fn provider_name(&self) -> &str {
        "nvidia-gpu"
    }

    fn device_id(&self) -> u32 {
        self.device_index
    }

    fn get_evidence(&self, _nonce: &str) -> Result<GpuEvidenceEntry, Box<dyn Error>> {
        // TODO: integrate with NVIDIA Attestation SDK / nvml / device file
        Err(format!(
            "NVIDIA GPU attestation not yet implemented for device {}",
            self.device_index
        )
        .into())
    }
}

/// Detect all available GPU TEE devices and return one provider per device,
/// sorted by device index.
///
/// Returns an empty Vec when no GPU TEE hardware is found (the CPU-only
/// binding path will be used).
pub fn detect_gpu_providers() -> Vec<Box<dyn GpuEvidenceProvider>> {
    let mut providers: Vec<Box<dyn GpuEvidenceProvider>> = Vec::new();

    // --- NVIDIA detection (placeholder) ---
    // In production this would enumerate /dev/nvidia* or use nvml to find
    // GPU TEE–capable devices.  For now we do not auto-detect: callers can
    // manually construct NvidiaGpuProvider instances when needed.
    debug!("GPU provider detection: no GPU TEE devices found (placeholder)");

    providers.sort_by_key(|p| p.device_id());
    providers
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- NvidiaGpuProvider tests ---

    #[test]
    fn test_nvidia_provider_name() {
        let provider = NvidiaGpuProvider::new(0);
        assert_eq!(provider.provider_name(), "nvidia-gpu");
    }

    #[test]
    fn test_nvidia_device_id() {
        let provider = NvidiaGpuProvider::new(5);
        assert_eq!(provider.device_id(), 5);
    }

    #[test]
    fn test_nvidia_get_evidence_returns_error() {
        let provider = NvidiaGpuProvider::new(2);
        let result = provider.get_evidence("some_nonce");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not yet implemented"));
        assert!(err.contains("device 2"));
    }

    // --- detect_gpu_providers tests ---

    #[test]
    fn test_detect_gpu_providers_returns_empty() {
        let providers = detect_gpu_providers();
        assert!(providers.is_empty());
    }

    // --- GpuEvidenceEntry serialization tests ---

    #[test]
    fn test_gpu_evidence_entry_serialization() {
        let entry = GpuEvidenceEntry {
            tee_type: "nvidia-gpu-h100".to_string(),
            device_index: 0,
            tee_evidence: "base64evidence==".to_string(),
        };
        let json = serde_json::to_value(&entry).unwrap();
        // Verify serde rename attributes
        assert_eq!(json["tee-type"], "nvidia-gpu-h100");
        assert_eq!(json["device-index"], 0);
        assert_eq!(json["tee-evidence"], "base64evidence==");
        // Original field names should NOT appear
        assert!(json.get("tee_type").is_none());
        assert!(json.get("device_index").is_none());
        assert!(json.get("tee_evidence").is_none());
    }

    #[test]
    fn test_gpu_evidence_entry_serialization_multiple() {
        let entries = vec![
            GpuEvidenceEntry {
                tee_type: "nvidia-gpu".to_string(),
                device_index: 0,
                tee_evidence: "ev0".to_string(),
            },
            GpuEvidenceEntry {
                tee_type: "nvidia-gpu".to_string(),
                device_index: 1,
                tee_evidence: "ev1".to_string(),
            },
        ];
        let json = serde_json::to_value(&entries).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["device-index"], 0);
        assert_eq!(arr[1]["device-index"], 1);
    }
}
