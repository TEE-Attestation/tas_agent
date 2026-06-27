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

#[cfg(feature = "askpass")]
mod askpass;
mod crypto;
// Any component feature
#[cfg(feature = "certify")]
mod certify;
#[cfg(feature = "gpu-nvidia")]
mod components;
#[cfg(feature = "passfifo")]
mod passfifo;
mod tas_api;
mod tee_evidence;
mod utils;
use anyhow::{anyhow, Context, Result};
use clap::Parser;
use serde::Deserialize;

use crypto::{
    compute_report_data_binding, decrypt_secret_with_aes_key, generate_wrapping_key,
    unwrap_secret_with_aes_key_wrap,
};
// Any component feature
#[cfg(feature = "gpu-nvidia")]
use crypto::compute_report_data_binding_with_components;
use tas_api::{tas_get_nonce, tas_get_secret_key, tas_get_version, RetryConfig};
use tee_evidence::tee_get_evidence;
use utils::SecretsPayload;
use zeroize::Zeroize;

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

    #[cfg(feature = "certify")]
    #[command(flatten)]
    certify_args: certify::CertifyArgs,

    /// Path to the config file (default: '/etc/tas_agent/config.toml')
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// The URI of the TAS REST service
    #[arg(long, value_name = "URI")]
    server_uri: Option<String>,

    /// Path to the API key for the TAS REST service
    #[arg(long, value_name = "FILE")]
    api_key: Option<PathBuf>,

    /// Policy ID to request from the TAS REST service
    #[arg(long, value_name = "ID")]
    policy_id: Option<String>,

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

    /// Disable GPU attestation (enabled by default when built with GPU support)
    // Any GPU feature
    #[cfg(feature = "gpu-nvidia")]
    #[arg(long)]
    no_gpu: bool,

    /// Enable systemd ask-password watcher mode for automatic LUKS unlock
    #[cfg(feature = "askpass")]
    #[arg(long)]
    askpass: bool,

    /// Enable initramfs-tools passfifo watcher mode for automatic LUKS unlock
    #[cfg(feature = "passfifo")]
    #[arg(long)]
    passfifo: bool,
}

#[derive(Deserialize, Default)]
struct Config {
    server_uri: Option<String>,
    api_key: Option<PathBuf>,
    policy_id: Option<String>,
    cert_path: Option<PathBuf>,
    max_retries: Option<u32>,
    retry_min_backoff_secs: Option<u64>,
    retry_max_backoff_secs: Option<u64>,
    /// Set to true to disable GPU attestation
    // Any GPU feature
    #[cfg(feature = "gpu-nvidia")]
    no_gpu: Option<bool>,
    #[cfg(feature = "certify")]
    #[serde(flatten)]
    certify_config: certify::CertifyConfig,
    /// Enable systemd ask-password watcher mode
    #[cfg(feature = "askpass")]
    askpass: Option<bool>,
    /// Enable initramfs-tools passfifo watcher mode
    #[cfg(feature = "passfifo")]
    passfifo: Option<bool>,
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

/// Optional CLI overrides for use when calling fetch_key() from askpass mode
/// or other non-CLI contexts.
pub struct CliOverrides {
    pub server_uri: Option<String>,
    pub api_key: Option<PathBuf>,
    pub policy_id: Option<String>,
    pub cert_path: Option<PathBuf>,
    pub max_retries: Option<u32>,
    pub retry_min_backoff_secs: Option<u64>,
    pub retry_max_backoff_secs: Option<u64>,
    #[cfg(feature = "gpu-nvidia")]
    pub no_gpu: bool,
}

/// Core key-fetch logic: loads config, contacts TAS, retrieves and decrypts key.
///
/// Returns the decrypted key as raw bytes. This function is used by both
/// the normal stdout mode and the askpass watcher mode.
pub async fn fetch_key(
    config_path: Option<PathBuf>,
    overrides: Option<CliOverrides>,
) -> Result<Vec<u8>> {
    let cfg = load_config(config_path)?;
    let ovr = overrides.unwrap_or(CliOverrides {
        server_uri: None,
        api_key: None,
        policy_id: None,
        cert_path: None,
        max_retries: None,
        retry_min_backoff_secs: None,
        retry_max_backoff_secs: None,
        #[cfg(feature = "gpu-nvidia")]
        no_gpu: false,
    });

    let server_uri = ovr
        .server_uri
        .or(cfg.server_uri)
        .ok_or_else(|| anyhow!("server URI is required"))?;

    if !server_uri.starts_with("http://") && !server_uri.starts_with("https://") {
        return Err(anyhow!(
            "server URI must start with http:// or https:// (got {:?})",
            server_uri
        ));
    }

    let api_key_path = ovr
        .api_key
        .or(cfg.api_key)
        .unwrap_or_else(|| PathBuf::from("/etc/tas_agent/api-key"));

    let policy_id = ovr
        .policy_id
        .or(cfg.policy_id)
        .ok_or_else(|| anyhow!("server policy ID is required"))?;

    let cert_path = ovr
        .cert_path
        .or(cfg.cert_path)
        .unwrap_or_else(|| PathBuf::from("/etc/tas_agent/root_cert.pem"));

    let retry_config = RetryConfig {
        max_retries: ovr.max_retries.or(cfg.max_retries).unwrap_or(3),
        min_backoff_secs: ovr
            .retry_min_backoff_secs
            .or(cfg.retry_min_backoff_secs)
            .unwrap_or(1),
        max_backoff_secs: ovr
            .retry_max_backoff_secs
            .or(cfg.retry_max_backoff_secs)
            .unwrap_or(30),
    };
    debug!("Retry config: {:?}", retry_config);

    let api_key = read_to_string(api_key_path.clone())
        .with_context(|| format!("unable to read API key from {:?}", api_key_path))?
        .trim()
        .to_string();

    // Generate a wrapping key for the HSM to wrap the secret key with
    debug!("Generating wrapping key...");
    let rsa_wrapping_key =
        generate_wrapping_key().map_err(|e| anyhow!("failed to generate wrapping key: {}", e))?;
    debug!("\nGenerated wrapping key: {}\n", rsa_wrapping_key);

    let wrapping_key = rsa_wrapping_key
        .public_key_to_base64()
        .map_err(|e| anyhow!("failed to convert wrapping key to DER base64: {}", e))?;
    debug!("Base64-encoded public wrapping key: {}\n", wrapping_key);

    // Call the function to get the TAS server version
    match tas_get_version(&server_uri, &api_key, cert_path.clone(), &retry_config).await {
        Ok(version) => debug!("TEE Attestation Server Version: {}", version),
        Err(err) => {
            return Err(anyhow!("TAS Version Error: {}", err));
        }
    }

    // Call the function to get the nonce from the TAS server
    let nonce = tas_get_nonce(&server_uri, &api_key, cert_path.clone(), &retry_config)
        .await
        .map_err(|e| anyhow!("TAS Nonce Error: {}", e))?;
    debug!("Nonce: {}", nonce);

    // Key binding is always enabled
    let key_binding_enabled = true;

    // --- GPU attestation evidence collection ---
    // Any GPU feature
    #[cfg(feature = "gpu-nvidia")]
    let gpu_enabled = !ovr.no_gpu && !cfg.no_gpu.unwrap_or(false);
    #[cfg(not(feature = "gpu-nvidia"))]
    let gpu_enabled = false;

    let (component_evidence, _component_hashes) = if gpu_enabled {
        #[cfg(feature = "gpu-nvidia")]
        {
            let nonce_trimmed = nonce.trim_matches('"');
            match components::gpu_nvidia::collect_and_hash_gpu_evidence(nonce_trimmed) {
                Ok((evidence_json, hashes)) => (Some(evidence_json), hashes),
                Err(e) => {
                    eprintln!("GPU attestation error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        #[cfg(not(feature = "gpu-nvidia"))]
        {
            debug!("No GPU attestation providers compiled in");
            (None, Vec::<u8>::new())
        }
    } else {
        debug!("GPU attestation not enabled");
        (None, Vec::<u8>::new())
    };

    // --- Compute CPU report_data binding ---
    let report_data: Option<Vec<u8>> = if key_binding_enabled {
        let pubkey_der = rsa_wrapping_key
            .public_key_to_der()
            .map_err(|e| anyhow!("Failed to get public key DER: {}", e))?;

        let nonce_trimmed = nonce.trim_matches('"');
        // Any component feature
        #[cfg(feature = "gpu-nvidia")]
        let binding = if _component_hashes.is_empty() {
            compute_report_data_binding(nonce_trimmed.as_bytes(), &pubkey_der)
        } else {
            compute_report_data_binding_with_components(
                nonce_trimmed.as_bytes(),
                &pubkey_der,
                &_component_hashes,
            )
        };
        #[cfg(not(feature = "gpu-nvidia"))]
        let binding = compute_report_data_binding(nonce_trimmed.as_bytes(), &pubkey_der);
        debug!("Report data binding (hex): {}", hex::encode(&binding));
        Some(binding)
    } else {
        None
    };

    // Generate the TEE evidence with key binding
    let (tee_evidence, tee_type) = tee_get_evidence(&nonce, report_data.as_deref())
        .map_err(|err| anyhow!("TEE evidence Error: {}", err))?;
    debug!("Generated TEE Evidence (Base64-encoded): {}", tee_evidence);
    debug!("TEE Type: {}", tee_type);

    // Call the function to get the secret key
    let secret_string = tas_get_secret_key(
        &server_uri,
        &api_key,
        &nonce,
        &tee_evidence,
        &tee_type,
        &policy_id,
        &wrapping_key,
        cert_path.clone(),
        &retry_config,
        key_binding_enabled,
        component_evidence.as_ref(),
    )
    .await
    .map_err(|e| anyhow!("TAS Secret Error: {}", e))?;
    debug!("Secret Key/Payload: {}", secret_string);

    // Deserialize the base64-encoded secret payload
    let mut secret: SecretsPayload =
        serde_json::from_str(&secret_string).context("JSON Deserialize Error")?;
    debug!("Deserialized secret payload: {:?}", secret);

    // Unwrap the secret key using the wrapping key
    debug!("Unwrapping secret key...");
    let aes_key = rsa_wrapping_key
        .unwrap_key(&secret.wrapped_key)
        .map_err(|err| anyhow!("Crypto Unwrap Error: {}", err))?;
    debug!("Unwrapped secret key: {:?}", aes_key.hex_dump());

    // Decrypt the secret using the algorithm that was used to wrap it
    debug!("Decrypting secret using algorithm: {}", secret.algorithm);
    let decrypted_payload = if secret.algorithm == "AES-KWP" {
        debug!("Using AES Key Wrap to unwrap secret");
        unwrap_secret_with_aes_key_wrap(&aes_key, &secret.blob)
            .map_err(|err| anyhow!("AES Key Wrap Decrypt Error: {}", err))?
    } else {
        debug!("Using AES-GCM to decrypt secret");
        decrypt_secret_with_aes_key(&aes_key, &secret.iv, &mut secret.blob, &secret.tag)
            .map_err(|err| anyhow!("AES-GCM Decrypt Error: {}", err))?
    };

    // Zeroize sensitive material from memory
    let mut aes_key_mut = aes_key;
    aes_key_mut.zeroize();
    secret.wrapped_key.zeroize();
    secret.iv.zeroize();
    secret.blob.zeroize();
    secret.tag.zeroize();

    Ok(decrypted_payload)
}

static LOGGER: SimpleLogger = SimpleLogger;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Always initialise the logger; -d bumps the level from INFO to DEBUG
    let level = if cli.debug {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };
    let _ = log::set_logger(&LOGGER).map(|()| log::set_max_level(level));

    // In askpass mode, dispatch to the askpass watcher and exit
    #[cfg(feature = "askpass")]
    {
        let cfg = match load_config(cli.config.clone()) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("{:#}", e);
                std::process::exit(1);
            }
        };
        if cli.askpass || cfg.askpass.unwrap_or(false) {
            if let Err(e) = askpass::run_askpass(cli.config).await {
                eprintln!("askpass error: {:#}", e);
            }
            // Always exit 0 — never block the TTY recovery prompt
            return;
        }
    }

    // In passfifo mode, dispatch to the passfifo watcher and exit
    #[cfg(feature = "passfifo")]
    {
        let cfg = match load_config(cli.config.clone()) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("{:#}", e);
                std::process::exit(1);
            }
        };
        if cli.passfifo || cfg.passfifo.unwrap_or(false) {
            if let Err(e) = passfifo::run_passfifo(cli.config).await {
                eprintln!("passfifo error: {:#}", e);
            }
            // Always exit 0 — never block the TTY recovery prompt
            return;
        }
    }

    #[cfg(feature = "certify")]
    {
        let cfg = match load_config(cli.config.clone()) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("{:#}", e);
                std::process::exit(1);
            }
        };
        match certify::run_if_requested(&cli, &cfg).await {
            Ok(true) => return,
            Ok(false) => {}
            Err(e) => {
                eprintln!("{:#}", e);
                std::process::exit(1);
            }
        }
    }
    let overrides = CliOverrides {
        server_uri: cli.server_uri,
        api_key: cli.api_key,
        policy_id: cli.policy_id,
        cert_path: cli.cert_path,
        max_retries: cli.max_retries,
        retry_min_backoff_secs: cli.retry_min_backoff_secs,
        retry_max_backoff_secs: cli.retry_max_backoff_secs,
        #[cfg(feature = "gpu-nvidia")]
        no_gpu: cli.no_gpu,
    };

    match fetch_key(cli.config, Some(overrides)).await {
        Ok(decrypted_payload) => {
            use std::io::Write;
            if let Err(e) = std::io::stdout().write_all(&decrypted_payload) {
                eprintln!("failed to write key to stdout: {:#}", e);
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("{:#}", e);
            std::process::exit(1);
        }
    }
}
