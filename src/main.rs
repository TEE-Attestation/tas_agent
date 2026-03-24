// TEE Attestation Service Agent
//
// Copyright 2025 -2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// This application interacts via a REST API with the TEE Attestation Service Key Broker Module.
//
// It gathers TEE Evidence from the platform and sends it to the TEE Attestation Service for
// verification. Upon successful verification, it retrieves the TEE Attestation Service's key
// to enable the mounting of a LUKS volume, for example.
//
// The application is designed to be run as a standalone executable.
//

use chrono::Utc;
use log::{debug, Level, LevelFilter, Metadata, Record};
use pretty_hex::PrettyHex;
use std::fs::read_to_string;
use std::path::PathBuf;

// Import the `tee_get_evidence` function from the `tee_evidence` module
mod crypto;
#[cfg(feature = "gpu-attestation")]
mod gpu_evidence;
mod tas_api;
mod tee_evidence;
mod utils;
use anyhow::{anyhow, Context, Result};
use clap::Parser;
use serde::Deserialize;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[allow(dead_code)]
enum GpuAttestationMode {
    Auto,
    Disabled,
}

impl fmt::Display for GpuAttestationMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auto => write!(f, "auto"),
            Self::Disabled => write!(f, "disabled"),
        }
    }
}

/// Resolve GPU attestation mode from CLI and config values.
/// CLI takes priority; config is the fallback; default is `Auto`.
fn resolve_gpu_attestation_mode(
    #[cfg(feature = "gpu-attestation")] cli_value: GpuAttestationMode,
    #[cfg(feature = "gpu-attestation")] cfg_value: Option<&str>,
) -> GpuAttestationMode {
    #[cfg(not(feature = "gpu-attestation"))]
    return GpuAttestationMode::Disabled;

    #[cfg(feature = "gpu-attestation")]
    {
        // CLI explicitly set (not the default) — use it directly
        if cli_value != GpuAttestationMode::Auto {
            return cli_value;
        }
        // Fall back to config file value
        match cfg_value {
            Some("disabled") => GpuAttestationMode::Disabled,
            _ => GpuAttestationMode::Auto,
        }
    }
}

#[cfg(feature = "gpu-attestation")]
use base64::{engine::general_purpose, Engine};
use crypto::{compute_report_data_binding, decrypt_secret_with_aes_key, generate_wrapping_key};
#[cfg(feature = "gpu-attestation")]
use crypto::{compute_report_data_binding_with_gpu, hash_gpu_evidence};
#[cfg(feature = "gpu-attestation")]
use gpu_evidence::detect_gpu_providers;
use tas_api::{tas_get_nonce, tas_get_secret_key, tas_get_version, RetryConfig};
use tee_evidence::tee_get_evidence;
use utils::SecretsPayload;

struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Debug
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let now = Utc::now().to_rfc3339();
            eprintln!("{} {} - {}", now, record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Display debugging messages
    #[arg(short, long)]
    debug: bool,

    /// Path to the config file (default: '/etc/tas_agent/config.toml')
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// The URI of the TAS REST service
    #[arg(long, value_name = "URI")]
    server_uri: Option<String>,

    /// Path to the API key for the TAS REST service
    #[arg(long, value_name = "FILE")]
    api_key: Option<PathBuf>,

    /// ID of the key to request from the TAS REST service
    #[arg(long, value_name = "ID")]
    key_id: Option<String>,

    /// Path to the CA root certificate signing the TAS REST service cert
    #[arg(long, value_name = "FILE")]
    cert_path: Option<PathBuf>,

    /// Maximum number of retry attempts for HTTP requests (default: 3)
    #[arg(long, value_name = "N")]
    max_retries: Option<u32>,

    /// Minimum backoff time in seconds between retries (default: 1)
    #[arg(long, value_name = "SECS")]
    retry_min_backoff_secs: Option<u64>,

    /// Maximum backoff time in seconds between retries (default: 30)
    #[arg(long, value_name = "SECS")]
    retry_max_backoff_secs: Option<u64>,

    /// GPU attestation mode: auto (default) or disabled
    #[cfg(feature = "gpu-attestation")]
    #[arg(long, value_enum, default_value_t = GpuAttestationMode::Auto)]
    gpu_attestation: GpuAttestationMode,
}

#[derive(Deserialize, Default)]
struct Config {
    server_uri: Option<String>,
    api_key: Option<PathBuf>,
    key_id: Option<String>,
    cert_path: Option<PathBuf>,
    max_retries: Option<u32>,
    retry_min_backoff_secs: Option<u64>,
    retry_max_backoff_secs: Option<u64>,
    /// GPU attestation mode: "auto", "disabled" (default: "auto")
    #[cfg(feature = "gpu-attestation")]
    gpu_attestation: Option<String>,
}

fn load_config(path: Option<PathBuf>) -> Result<Config> {
    let config_path = path
        .clone()
        .unwrap_or_else(|| PathBuf::from("/etc/tas_agent/config.toml"));
    if !config_path.exists() {
        if path.is_some() {
            return Err(anyhow!("config file {:?} does not exist", config_path));
        }
        return Ok(Config::default());
    }

    let data = std::fs::read_to_string(config_path.clone())
        .with_context(|| format!("unable to read {:?}", config_path))?;

    toml::from_str(&data).with_context(|| format!("unable to load {:?}", config_path))
}

static LOGGER: SimpleLogger = SimpleLogger;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Check if the debug flag (-d) is passed as a command-line argument
    if cli.debug {
        let _ = log::set_logger(&LOGGER).map(|()| log::set_max_level(LevelFilter::Debug));
    }

    let cfg = match load_config(cli.config) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("{:#}", e);
            std::process::exit(1);
        }
    };

    // Retrieve the REST server URI, API key, key ID, and root certificate path from
    // command line, falling back to environment variables if not given
    let server_uri = cli.server_uri.unwrap_or_else(|| {
        cfg.server_uri.unwrap_or_else(|| {
            eprintln!("server URI is required");
            std::process::exit(1)
        })
    });

    let api_key_path = cli.api_key.unwrap_or_else(|| {
        cfg.api_key
            .unwrap_or_else(|| PathBuf::from("/etc/tas_agent/api_key".to_string()))
    });
    let key_id = cli.key_id.unwrap_or_else(|| {
        cfg.key_id.unwrap_or_else(|| {
            eprintln!("server key ID is required");
            std::process::exit(1)
        })
    });

    let cert_path = cli.cert_path.unwrap_or_else(|| {
        cfg.cert_path
            .unwrap_or(PathBuf::from("/etc/tas_agent/root_cert.pem".to_string()))
    });

    let retry_config = RetryConfig {
        max_retries: cli.max_retries.or(cfg.max_retries).unwrap_or(3),
        min_backoff_secs: cli
            .retry_min_backoff_secs
            .or(cfg.retry_min_backoff_secs)
            .unwrap_or(1),
        max_backoff_secs: cli
            .retry_max_backoff_secs
            .or(cfg.retry_max_backoff_secs)
            .unwrap_or(30),
    };
    debug!("Retry config: {:?}", retry_config);

    let api_key = match read_to_string(api_key_path.clone()) {
        Ok(d) => d.trim().to_string(),
        Err(e) => {
            eprintln!("unable to read API key from {:?}: {}", api_key_path, e);
            std::process::exit(1)
        }
    };

    // Generate a wrapping key for the HSM to wrap the secret key with
    debug!("Generating wrapping key...");
    let rsa_wrapping_key = match generate_wrapping_key() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("failed to generate wrapping key: {}", e);
            std::process::exit(1);
        }
    };
    debug!("\nGenerated wrapping key: {}\n", rsa_wrapping_key);

    let wrapping_key = match rsa_wrapping_key.public_key_to_base64() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("failed to convert wrapping key to DER base64: {}", e);
            std::process::exit(1)
        }
    };

    debug!("Base64-encoded public wrapping key: {}\n", wrapping_key);

    // Call the function to get the TAS server version
    match tas_get_version(&server_uri, &api_key, cert_path.clone(), &retry_config).await {
        Ok(version) => debug!("TEE Attestation Server Version: {}", version),
        Err(err) => {
            eprintln!("TAS Version Error: {}", err);
            std::process::exit(1);
        }
    }

    // Call the function to get the nonce from the TAS server
    let nonce = match tas_get_nonce(&server_uri, &api_key, cert_path.clone(), &retry_config).await {
        Ok(nonce) => {
            debug!("Nonce: {}", nonce);
            nonce
        }
        Err(err) => {
            eprintln!("TAS Nonce Error: {}", err);
            std::process::exit(1);
        }
    };

    // Key binding is always enabled — the RSA public key is bound into
    // the TEE report_data via SHA-512(nonce || pubkey_der [|| gpu_hashes]).
    let key_binding_enabled = true;
    let gpu_attestation_mode = resolve_gpu_attestation_mode(
        #[cfg(feature = "gpu-attestation")]
        cli.gpu_attestation,
        #[cfg(feature = "gpu-attestation")]
        cfg.gpu_attestation.as_deref(),
    );

    debug!(
        "Key binding: {}, GPU attestation: {}",
        key_binding_enabled, gpu_attestation_mode
    );

    // --- GPU evidence collection (Phase 2: composable attestation) ---
    #[cfg(feature = "gpu-attestation")]
    let (gpu_entries, gpu_hashes_combined) = {
        let mut gpu_entries = Vec::new();
        let mut gpu_hashes_combined: Vec<u8> = Vec::new();
        if gpu_attestation_mode != GpuAttestationMode::Disabled {
            let providers = detect_gpu_providers();
            if !providers.is_empty() {
                debug!("Found {} GPU TEE provider(s)", providers.len());
                for provider in &providers {
                    match provider.get_evidence(&nonce) {
                        Ok(entry) => {
                            gpu_entries.push(entry);
                        }
                        Err(err) => {
                            eprintln!("GPU {} evidence error: {}", provider.device_id(), err);
                            std::process::exit(1);
                        }
                    }
                }
                // Ensure entries are in deterministic device_index order
                gpu_entries.sort_by_key(|e| e.device_index);

                // Build hash chain from sorted entries
                for entry in &gpu_entries {
                    let raw_evidence = general_purpose::STANDARD
                        .decode(&entry.tee_evidence)
                        .unwrap_or_else(|e| {
                            eprintln!(
                                "Failed to decode GPU {} evidence: {}",
                                entry.device_index, e
                            );
                            std::process::exit(1);
                        });
                    let gpu_hash = hash_gpu_evidence(&raw_evidence);
                    debug!(
                        "GPU {} ({}): evidence hash = {}",
                        entry.device_index,
                        entry.tee_type,
                        hex::encode(&gpu_hash)
                    );
                    gpu_hashes_combined.extend_from_slice(&gpu_hash);
                }
            }
        }
        (gpu_entries, gpu_hashes_combined)
    };
    #[cfg(not(feature = "gpu-attestation"))]
    let gpu_hashes_combined: Vec<u8> = Vec::new();
    let _ = &gpu_hashes_combined;

    // --- Compute CPU report_data binding ---
    let report_data: Option<Vec<u8>> = if key_binding_enabled {
        let pubkey_der = match rsa_wrapping_key.public_key_to_der() {
            Ok(der) => der,
            Err(e) => {
                eprintln!("Failed to get public key DER: {}", e);
                std::process::exit(1);
            }
        };

        let nonce_trimmed = nonce.trim_matches('"');
        #[cfg(feature = "gpu-attestation")]
        let binding = if gpu_hashes_combined.is_empty() {
            compute_report_data_binding(nonce_trimmed.as_bytes(), &pubkey_der)
        } else {
            compute_report_data_binding_with_gpu(
                nonce_trimmed.as_bytes(),
                &pubkey_der,
                &gpu_hashes_combined,
            )
        };
        #[cfg(not(feature = "gpu-attestation"))]
        let binding = compute_report_data_binding(nonce_trimmed.as_bytes(), &pubkey_der);
        debug!("Report data binding (hex): {}", hex::encode(&binding));
        Some(binding)
    } else {
        None
    };

    // Generate the TEE evidence with  key binding
    let (tee_evidence, tee_type) = match tee_get_evidence(&nonce, report_data.as_deref()) {
        Ok((evidence, tee_type)) => {
            debug!("Generated TEE Evidence (Base64-encoded): {}", evidence);
            debug!("TEE Type: {}", tee_type);
            (evidence, tee_type)
        }
        Err(err) => {
            eprintln!("TEE evidence Error: {}", err);
            std::process::exit(1);
        }
    };

    // Call the function to get the secret key using the nonce, tee_evidence, tee_type, and key_id
    #[cfg(feature = "gpu-attestation")]
    let gpu_evidence_ref = if gpu_entries.is_empty() {
        None
    } else {
        Some(serde_json::json!(gpu_entries))
    };
    let secret_string = match tas_get_secret_key(
        &server_uri,
        &api_key,
        &nonce,
        &tee_evidence,
        &tee_type,
        &key_id,
        &wrapping_key,
        cert_path.clone(),
        &retry_config,
        key_binding_enabled,
        #[cfg(feature = "gpu-attestation")]
        gpu_evidence_ref.as_ref(),
        #[cfg(not(feature = "gpu-attestation"))]
        None,
    )
    .await
    {
        Ok(secret_key) => {
            debug!("Secret Key/Payload: {}", secret_key);
            secret_key
        }
        Err(err) => {
            eprintln!("TAS Secret Error: {}", err);
            std::process::exit(1);
        }
    };

    // Deserialize the base64-encoded secret payload
    let mut secret: SecretsPayload = match serde_json::from_str(&secret_string) {
        Ok(secret) => {
            debug!("Deserialized secret payload: {:?}", secret);
            secret
        }
        Err(err) => {
            eprintln!("JSON Deserialize Error: {}", err);
            std::process::exit(1);
        }
    };

    // Unwrap the secret key using the wrapping key
    debug!("Unwrapping secret key...");
    let aes_key = match rsa_wrapping_key.unwrap_key(&secret.wrapped_key) {
        Ok(aes_key) => aes_key,
        Err(err) => {
            eprintln!("Crypto Unwrap Error: {}", err);
            std::process::exit(1);
        }
    };
    debug!("Unwrapped secret key: {:?}", aes_key.hex_dump());

    // Decrypt the secret payload using the unwrapped AES key
    debug!("Decrypting secret payload...");
    let decrypted_payload =
        match decrypt_secret_with_aes_key(&aes_key, &secret.iv, &mut secret.blob, &secret.tag) {
            Ok(decrypted_payload) => decrypted_payload,
            Err(err) => {
                eprintln!("Crypto Decrypt Error: {}", err);
                std::process::exit(1);
            }
        };
    println!("{}", String::from_utf8_lossy(&decrypted_payload));
}
