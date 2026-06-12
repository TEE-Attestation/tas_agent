// TEE Attestation Service Agent — experimental certify/renew lifecycle.
//
// Copyright 2025 -2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// EXPERIMENTAL: the certificate certify/renew lifecycle is gated behind the
// off-by-default `certify` Cargo feature and is not production-ready. Enabling
// the feature (`cargo build --features certify`) is the explicit opt-in.

use std::fs::read_to_string;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use clap::Args;
use log::{debug, warn};
use serde::Deserialize;

use crate::crypto::compute_report_data_binding;
use crate::tas_api::{tas_get_version, RetryConfig};
use crate::tee_evidence::tee_get_evidence;
use crate::{load_config, Cli, CliOverrides, Config};

mod api;
mod csr;
mod keygen;
mod material_writer;
mod renewal_input;

use api::{tas_certify, tas_get_alpha_nonce};
use csr::{build_plain_csr, generate_tee_common_name};
use keygen::{AgentKey, KeyAlgorithm};

/// Experimental certify/renew command-line flags.
///
/// Flattened into the top-level CLI so the flag names (`--certify`, `--renew`,
/// `--write-dir`, `--force`) and help text live entirely within this module.
#[derive(Args)]
pub struct CertifyArgs {
    /// Generate a plain CSR and bound TEE evidence for the TAS certify flow
    #[arg(long)]
    certify: bool,

    /// Renew an existing certificate (requires --write-dir)
    #[arg(long)]
    renew: bool,

    /// Directory to write/read certificate materials (key.pem, cert.pem, etc.)
    #[arg(long, value_name = "DIR")]
    write_dir: Option<PathBuf>,

    /// Allow overwriting existing key.pem during re-certification
    #[arg(long)]
    force: bool,
}

/// Experimental certify/renew configuration keys.
///
/// Flattened into the top-level config so the TOML keys (`certify`, `renew`,
/// `write_dir`, `force`) stay top-level while their definitions live here.
#[derive(Deserialize, Default)]
pub struct CertifyConfig {
    certify: Option<bool>,
    renew: Option<bool>,
    write_dir: Option<PathBuf>,
    force: Option<bool>,
}

#[derive(Debug, Clone, Copy)]
enum CertifyMode {
    Fresh { force: bool },
    Renew,
}

/// Pure predicate: is certify/renew mode requested from the resolved inputs?
fn mode_requested(
    cli_certify: bool,
    cli_renew: bool,
    cfg_certify: Option<bool>,
    cfg_renew: Option<bool>,
) -> bool {
    cli_certify || cli_renew || cfg_certify.unwrap_or(false) || cfg_renew.unwrap_or(false)
}

/// Whether the user requested certify or renew via CLI flags or config.
fn certify_mode_requested(cli: &Cli, cfg: &Config) -> bool {
    let args = &cli.certify_args;
    let cfg = &cfg.certify_config;
    mode_requested(args.certify, args.renew, cfg.certify, cfg.renew)
}

/// Run the certify/renew flow if requested.
///
/// Returns `Ok(false)` when certify/renew was not requested (caller continues
/// with the normal key-fetch flow), `Ok(true)` after the flow handled the run,
/// and `Err(_)` for input or flow failures (caller logs and exits).
pub(super) async fn run_if_requested(cli: &Cli, cfg: &Config) -> Result<bool> {
    if !certify_mode_requested(cli, cfg) {
        return Ok(false);
    }

    let args = &cli.certify_args;
    let cert_cfg = &cfg.certify_config;

    let write_dir = args
        .write_dir
        .clone()
        .or_else(|| cert_cfg.write_dir.clone())
        .ok_or_else(|| anyhow!("--write-dir is required for --certify or --renew"))?;

    let mode = if args.renew || cert_cfg.renew.unwrap_or(false) {
        CertifyMode::Renew
    } else {
        CertifyMode::Fresh {
            force: args.force || cert_cfg.force.unwrap_or(false),
        }
    };

    let overrides = CliOverrides {
        server_uri: cli.server_uri.clone(),
        api_key: cli.api_key.clone(),
        policy_id: cli.policy_id.clone(),
        cert_path: cli.cert_path.clone(),
        max_retries: cli.max_retries,
        retry_min_backoff_secs: cli.retry_min_backoff_secs,
        retry_max_backoff_secs: cli.retry_max_backoff_secs,
    };

    let cert_bundle_pem =
        certify_flow(cli.config.clone(), Some(overrides), Some(write_dir), mode).await?;

    if cli.debug {
        use std::io::Write;
        std::io::stdout()
            .write_all(cert_bundle_pem.as_bytes())
            .map_err(|e| anyhow!("failed to write certificate to stdout: {}", e))?;
    }

    Ok(true)
}

async fn certify_flow(
    config_path: Option<PathBuf>,
    overrides: Option<CliOverrides>,
    write_dir: Option<PathBuf>,
    mode: CertifyMode,
) -> Result<String> {
    warn!("EXPERIMENTAL: certify/renew lifecycle is not production-ready");
    let cfg = load_config(config_path)?;
    let ovr = overrides.unwrap_or(CliOverrides {
        server_uri: None,
        api_key: None,
        policy_id: None,
        cert_path: None,
        max_retries: None,
        retry_min_backoff_secs: None,
        retry_max_backoff_secs: None,
    });

    let write_dir = write_dir.ok_or_else(|| anyhow!("write_dir is required"))?;

    //TODO - refactor to share more code with fetch_key(), e.g. config loading, retry config, TAS version check, nonce retrieval, etc.

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

    let renew_cert = match mode {
        CertifyMode::Fresh { force: _ } => None,
        CertifyMode::Renew => {
            let cert_str = renewal_input::load_renew_cert_from_dir(&write_dir)
                .context("failed to load certificate for renewal")?;
            Some(cert_str)
        }
    };

    let agent_key = match mode {
        CertifyMode::Fresh { force: _ } => {
            debug!("Certify mode: Fresh");
            debug!("Generating RSA-4096 certify key (this can take a while in debug builds)...");
            AgentKey::generate(KeyAlgorithm::Rsa4096)
                .map_err(|e| anyhow!("failed to generate certify key: {}", e))?
        }
        CertifyMode::Renew => {
            debug!("Certify mode: Renew");
            let key_pem = renewal_input::load_private_key_from_dir(&write_dir)
                .context("failed to load private key for renewal")?;
            AgentKey::from_pkcs8_pem(&key_pem)
                .map_err(|e| anyhow!("failed to import private key from PKCS#8: {}", e))?
        }
    };
    debug!("Certify key obtained");
    let common_name = generate_tee_common_name();
    debug!("Building plain CSR for CN: {}", common_name);
    let csr_pem = build_plain_csr(&agent_key, &common_name)
        .map_err(|e| anyhow!("failed to build CSR: {}", e))?;
    debug!("Generated certify CSR subject CN: {}", common_name);

    match tas_get_version(&server_uri, &api_key, cert_path.clone(), &retry_config).await {
        Ok(version) => debug!("TEE Attestation Server Version: {}", version),
        Err(err) => return Err(anyhow!("TAS Version Error: {}", err)),
    }

    // The alpha API calls this field policy-domain; keep using the existing
    // policy_id config/CLI name for compatibility with the key-fetch flow.
    let policy_domain = ovr
        .policy_id
        .or(cfg.policy_id)
        .ok_or_else(|| anyhow!("policy-domain is required for certify flow"))?;

    let nonce = tas_get_alpha_nonce(&server_uri, &api_key, cert_path.clone(), &retry_config)
        .await
        .map_err(|e| anyhow!("TAS Alpha Nonce Error: {}", e))?;
    // Match TAS vm_verify(): report_data binding uses nonce || PKCS#1 public-key DER.
    let pubkey_der = agent_key
        .public_key_to_der()
        .map_err(|e| anyhow!("Failed to get public key DER: {}", e))?;
    let binding = compute_report_data_binding(nonce.as_bytes(), &pubkey_der);
    debug!(
        "Certify report data binding (hex): {}",
        hex::encode(&binding)
    );

    let (tee_evidence, tee_type) = tee_get_evidence(&nonce, Some(&binding))
        .map_err(|err| anyhow!("TEE evidence Error: {}", err))?;
    debug!(
        "Generated certify TEE Evidence (Base64-encoded): {}",
        tee_evidence
    );
    debug!("Certify TEE Type: {}", tee_type);

    let issued = tas_certify(
        &server_uri,
        &api_key,
        &nonce,
        &tee_evidence,
        &tee_type,
        renew_cert.as_deref(),
        &csr_pem,
        &policy_domain,
        cert_path,
        &retry_config,
        None,
    )
    .await
    .map_err(|e| anyhow!("TAS Certify Error: {}", e))?;

    debug!("Received issued certificate from TAS");

    // Persist certificate materials based on mode
    match mode {
        CertifyMode::Fresh { force } => {
            let key_pem = agent_key
                .private_key_to_pkcs8_pem()
                .map_err(|e| anyhow!("failed to serialize key to PKCS#8: {}", e))?;
            material_writer::write_initial_materials(
                &write_dir,
                &key_pem,
                &issued.certificate,
                &issued.ca_chain.join(
                    "
",
                ),
                &issued.ca_chain.join(
                    "
",
                ),
                force,
            )
            .context("failed to write initial certificate materials")?;
            debug!("Wrote initial certificate materials to {:?}", write_dir);
        }
        CertifyMode::Renew => {
            material_writer::write_renewed_materials(
                &write_dir,
                &issued.certificate,
                &issued.ca_chain.join(
                    "
",
                ),
                &issued.ca_chain.join(
                    "
",
                ),
            )
            .context("failed to write renewed certificate materials")?;
            debug!("Wrote renewed certificate materials to {:?}", write_dir);
        }
    }

    let mut output = issued.certificate;
    if !issued.ca_chain.is_empty() {
        output.push('\n');
        output.push_str(&issued.ca_chain.join("\n"));
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::mode_requested;

    #[test]
    fn mode_requested_none() {
        assert!(!mode_requested(false, false, None, None));
        assert!(!mode_requested(false, false, Some(false), Some(false)));
    }

    #[test]
    fn mode_requested_cli_certify() {
        assert!(mode_requested(true, false, None, None));
    }

    #[test]
    fn mode_requested_cli_renew() {
        assert!(mode_requested(false, true, None, None));
    }

    #[test]
    fn mode_requested_cfg_certify() {
        assert!(mode_requested(false, false, Some(true), None));
    }

    #[test]
    fn mode_requested_cfg_renew() {
        assert!(mode_requested(false, false, None, Some(true)));
    }
}
