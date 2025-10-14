// TEE Attestation Service Agent
//
// Copyright 2025 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// This application interacts via a REST API with the TEE Attestation Service Key Broker Module.
//
// TEE Evidence gathering functionality.
//
use base64::{engine::general_purpose, Engine};
use std::error::Error;
use std::fs;
use tempfile::tempdir_in;

// TODO : implement own error handling, use boxed errors for now

/// Prints debug messages to stdout if the debug flag (-d) is enabled.
macro_rules! debug_println {
    ($debug:expr, $($arg:tt)*) => {
        if $debug {
            println!($($arg)*);
        }
    };
}

/// Internal function to determine the TEE type
/// This function returns the TEE type as a string (e.g., "amd-sev-snp").
/// TODO: check the system's TEE capabilities and return the appropriate type either "amd-sev-snp" or "intel-sgx".
/// Currently, it always returns "amd-sev-snp".
fn get_tee_type(debug: bool) -> String {
    let tee_type = "amd-sev-snp".to_string();
    debug_println!(debug, "Determined TEE type: {}", tee_type);
    tee_type
}

/// Returns the VMPL level of the current process.
///
/// This function reads the VMPL level from the `/sys/devices/system/cpu/sev/vmpl` file and returns
/// it as a string.
/// If the file cannot be read, it returns an error.
fn get_vmpl() -> Result<String, Box<dyn Error>> {
    let vmpl_file_path = "/sys/devices/system/cpu/sev/vmpl";
    let vmpl = fs::read_to_string(vmpl_file_path)?;
    Ok(vmpl)
}

/// Function to generate TEE evidence and return the TEE type
/// This function takes the nonce as a parameter and returns a tuple:
/// - The Base64-encoded TEE evidence
/// - The TEE type (e.g., "amd-sev-snp")
///
/// TODO: Update to determine the TEE type dynamically based on the system's capabilities and gather the evidence accordingly.
pub fn tee_get_evidence(nonce: &str, debug: bool) -> Result<(String, String), String> {
    // Setup temp_dir_path to the config tsm report path
    let temp_dir_path = "/sys/kernel/config/tsm/report";

    // Get the TEE type using the internal function
    let tee_type = get_tee_type(debug);
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
    let nonce = String::from_utf8(nonce_bytes.to_vec())
        .map_err(|err| format!("Error converting nonce to string: {}", err))?;

    // Attempt to create a temporary directory inside the specified path
    let tmp_dir = tempdir_in(temp_dir_path)
        .map_err(|err| format!("Failed to create temp directory: {}", err))?;
    debug_println!(debug, "Temp dir created at: {:?}", tmp_dir.path());
    debug_println!(debug, "Nonce_bytes (hex): {}", hex::encode(nonce_bytes));

    // Write nonce to inblob file
    let inblob_file_path = tmp_dir.path().join("inblob");
    fs::write(&inblob_file_path, nonce)
        .map_err(|err| format!("Failed to write to inblob file: {}", err))?;
    debug_println!(debug, "Wrote to inblob file at: {:?}", inblob_file_path);

    // Set VMPL level
    let vmpl = get_vmpl().map_err(|err| format!("Failed to get VMPL: {}", err))?;
    let privlevel_path = tmp_dir.path().join("privlevel");
    fs::write(privlevel_path, &vmpl).map_err(|err| format!("Failed to set VMPL: {}", err))?;
    debug_println!(debug, "Set VMPL level to: {}", vmpl);

    // Read outblob file
    let outblob_file_path = tmp_dir.path().join("outblob");
    debug_println!(debug, "Reading outblob file at: {:?}", outblob_file_path);

    let snp_report = fs::read(&outblob_file_path)
        .map_err(|err| format!("Failed to read outblob file: {}", err))?;

    // Drop the temporary directory
    drop(tmp_dir);

    // Base64 encode the SNP report using Engine::encode
    let encoded_report = general_purpose::STANDARD.encode(&snp_report);

    Ok((encoded_report, tee_type))
}
