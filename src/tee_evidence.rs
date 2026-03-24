// TEE Attestation Service Agent
//
// Copyright 2025 - 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// This application interacts via a REST API with the TEE Attestation Service Key Broker Module.
//
// TEE Evidence gathering functionality.
//
use base64::{engine::general_purpose, Engine};
use log::debug;
use std::error::Error;
use std::fs;
use tempfile::{tempdir_in, TempDir};

// TODO : implement own error handling, use boxed errors for now

// Internal function to determine the TEE type
// This function returns the TEE type as a string (e.g., "amd-sev-snp").
fn get_tee_type(tsm_report_dir: &TempDir) -> Result<String, Box<dyn Error>> {
    // determine TEE type dynamically using tsm report/provider
    let provider = fs::read_to_string(tsm_report_dir.path().join("provider"))?;

    debug!("TSM provider: {}", provider.trim());
    match provider.trim() {
        "sev_guest" => {
            debug!("Determined TEE type: amd-sev-snp");
            Ok("amd-sev-snp".to_string())
        }
        "tdx_guest" => {
            debug!("Determined TEE type: intel-tdx");
            Ok("intel-tdx".to_string())
        }
        other => {
            debug!("Unknown TEE provider: {}", other);
            Err(format!("Unknown TEE provider: {}", other).into())
        }
    }
}

// Returns the VMPL level of the current process.
//
// This function reads the VMPL level from the `/sys/devices/system/cpu/sev/vmpl` file and returns
// it as a string.
// If the file cannot be read, it returns an error.
fn get_vmpl() -> Result<String, Box<dyn Error>> {
    let vmpl_file_path = "/sys/devices/system/cpu/sev/vmpl";
    let vmpl = fs::read_to_string(vmpl_file_path)?;
    Ok(vmpl)
}

/// Function to generate TEE evidence and return the TEE type
///
/// Requires config_tsm to be enabled in the kernel.
///
/// # Arguments
/// * `nonce` - A string slice that holds the nonce value (must be exactly 64 bytes long)
/// * `report_data` - Optional raw bytes (must be exactly 64 bytes) to write to inblob
///   instead of the nonce string. When `Some`, enables the caller to bind the RSA public
///   key (and optional GPU evidence hashes) into the TEE report via
///   `SHA-512(nonce || pubkey_der [|| gpu_hashes])`. When `None`, the original
///   nonce-as-string behaviour is used.
///
///   When GPU attestation is enabled, `gpu_hashes` is constructed as follows:
///   1. Each GPU's raw attestation evidence is hashed individually with SHA-512.
///   2. The per-GPU hashes are concatenated in device-index order:
///      `SHA-512(gpu0) || SHA-512(gpu1) || ...`
///   3. The concatenated result is appended to the binding input, producing:
///      `SHA-512(nonce || pubkey_der || gpu_hashes)`
///
/// # Returns
/// * `Result<(String, String), String>` - On success, returns a tuple containing the
///   Base64-encoded TEE evidence and the TEE type. On failure, returns an error message.
pub fn tee_get_evidence(
    nonce: &str,
    report_data: Option<&[u8]>,
) -> Result<(String, String), String> {
    // Setup temp_dir_path to the config tsm report path
    let temp_dir_path = "/sys/kernel/config/tsm/report";

    // Strip the nonce of any surrounding quotes
    let nonce = nonce.trim_matches('"');
    // Ensure the nonce is exactly 64 bytes long
    let nonce_bytes = nonce.as_bytes();
    if nonce_bytes.len() != 64 {
        return Err(format!(
            "Error: Nonce must be exactly 64 bytes long, but it is {} bytes",
            nonce_bytes.len()
        ));
    }

    // Determine what to write to inblob: custom report_data or the nonce string
    let inblob_bytes: Vec<u8> = match report_data {
        Some(rd) => {
            if rd.len() != 64 {
                return Err(format!(
                    "Error: report_data must be exactly 64 bytes, but it is {} bytes",
                    rd.len()
                ));
            }
            rd.to_vec()
        }
        None => nonce.as_bytes().to_vec(),
    };

    // Attempt to create a temporary directory inside the specified path
    let tmp_dir = tempdir_in(temp_dir_path)
        .map_err(|err| format!("Failed to create temp directory: {}", err))?;
    debug!("Temp dir created at: {:?}", tmp_dir.path());
    debug!("Inblob bytes (hex): {}", hex::encode(&inblob_bytes));

    // Determine TEE type
    let tee_type =
        get_tee_type(&tmp_dir).map_err(|err| format!("Failed to determine TEE type: {}", err))?;

    // Write inblob (report_data or nonce) to inblob file
    let inblob_file_path = tmp_dir.path().join("inblob");
    fs::write(&inblob_file_path, &inblob_bytes)
        .map_err(|err| format!("Failed to write to inblob file: {}", err))?;
    debug!("Wrote to inblob file at: {:?}", inblob_file_path);

    // if SEV get VMPL level dynamically else skip this step
    if tee_type == "amd-sev-snp" {
        debug!("TEE type is SEV-SNP, setting VMPL level");
        // Set VMPL level
        let vmpl = get_vmpl().map_err(|err| format!("Failed to get VMPL: {}", err))?;
        let privlevel_path = tmp_dir.path().join("privlevel");
        fs::write(privlevel_path, &vmpl).map_err(|err| format!("Failed to set VMPL: {}", err))?;
        debug!("Set VMPL level to: {}", vmpl);
    } else {
        debug!("TEE type is not SEV-SNP, skipping VMPL level setting");
    }

    // Read outblob file
    let outblob_file_path = tmp_dir.path().join("outblob");
    debug!("Reading outblob file at: {:?}", outblob_file_path);

    let tee_report = fs::read(&outblob_file_path)
        .map_err(|err| format!("Failed to read outblob file: {}", err))?;

    // Drop the temporary directory
    drop(tmp_dir);
    debug!("Temp dir dropped");

    // Base64 encode the SNP report using Engine::encode
    let encoded_report = general_purpose::STANDARD.encode(&tee_report);

    Ok((encoded_report, tee_type))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    // --- get_tee_type tests ---

    #[test]
    fn test_get_tee_type_sev_guest() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("provider"), "sev_guest\n").unwrap();
        // get_tee_type expects a &TempDir from tempfile::TempDir, so we
        // create one via tempdir_in.  But since get_tee_type only reads
        // provider, we can use the same TempDir (path matches).
        let result = get_tee_type(&dir);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "amd-sev-snp");
    }

    #[test]
    fn test_get_tee_type_tdx_guest() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("provider"), "tdx_guest\n").unwrap();
        let result = get_tee_type(&dir);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "intel-tdx");
    }

    #[test]
    fn test_get_tee_type_unknown_provider() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("provider"), "some_unknown\n").unwrap();
        let result = get_tee_type(&dir);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Unknown TEE provider"));
    }

    #[test]
    fn test_get_tee_type_missing_provider_file() {
        let dir = tempdir().unwrap();
        // No provider file written
        let result = get_tee_type(&dir);
        assert!(result.is_err());
    }

    // --- Nonce validation tests ---

    #[test]
    fn test_nonce_too_short() {
        let short_nonce = "abc"; // 3 bytes, not 64
        let result = tee_get_evidence(short_nonce, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("Nonce must be exactly 64 bytes"));
    }

    #[test]
    fn test_nonce_too_long() {
        let long_nonce = "a".repeat(65);
        let result = tee_get_evidence(&long_nonce, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("Nonce must be exactly 64 bytes"));
    }

    #[test]
    fn test_nonce_with_surrounding_quotes_trimmed() {
        // 66 chars with quotes, 64 after trimming
        let quoted_nonce = format!("\"{}\"", "A".repeat(64));
        // This will fail at the TSM directory step, but nonce validation should pass.
        // The error should NOT be about nonce length.
        let result = tee_get_evidence(&quoted_nonce, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(!err.contains("Nonce must be exactly 64 bytes"));
    }

    // --- report_data validation tests ---

    #[test]
    fn test_report_data_wrong_length() {
        let nonce = "B".repeat(64);
        let bad_rd = vec![0u8; 32]; // 32 bytes, not 64
        let result = tee_get_evidence(&nonce, Some(&bad_rd));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("report_data must be exactly 64 bytes"));
    }

    #[test]
    fn test_report_data_too_long() {
        let nonce = "C".repeat(64);
        let long_rd = vec![0u8; 128];
        let result = tee_get_evidence(&nonce, Some(&long_rd));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("report_data must be exactly 64 bytes"));
    }

    #[test]
    fn test_report_data_correct_length_passes_validation() {
        let nonce = "D".repeat(64);
        let good_rd = vec![0xABu8; 64];
        // Will fail at TSM directory step, but report_data validation should pass.
        let result = tee_get_evidence(&nonce, Some(&good_rd));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(!err.contains("report_data must be exactly 64 bytes"));
        assert!(!err.contains("Nonce must be exactly 64 bytes"));
    }
}
