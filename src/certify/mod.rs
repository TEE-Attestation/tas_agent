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
#[cfg(feature = "gpu-nvidia")]
use crate::crypto::compute_report_data_binding_with_components;
use crate::tas_api::{tas_get_version, RetryConfig};
use crate::tee_evidence::tee_get_evidence;
use crate::{Cli, Config};

mod api;
mod csr;
#[cfg(feature = "gpu-nvidia")]
mod gpu;
mod keygen;
mod material_writer;
mod renewal_input;

use api::{tas_certify, tas_get_alpha_nonce};
use csr::{build_plain_csr, generate_tee_common_name, parse_common_name, parse_san, SanEntry};
use keygen::{AgentKey, KeyAlgorithm};

/// Experimental certify/renew command-line flags for the `certify` subcommand.
#[derive(Args)]
pub struct CertifyArgs {
    /// Renew an existing certificate (requires --write-dir)
    #[arg(long)]
    renew: bool,

    /// Directory to write/read certificate materials (key.pem, cert.pem, etc.)
    #[arg(long, value_name = "DIR")]
    write_dir: Option<PathBuf>,

    /// Allow overwriting existing key.pem during re-certification
    #[arg(long)]
    force: bool,

    /// Subject Common Name for the CSR (default: auto-generated from hostname/UUID)
    #[arg(long = "common-name", visible_alias = "cn", value_name = "CN", value_parser = parse_common_name)]
    common_name: Option<String>,

    /// Subject Alternative Name to request; repeatable. Format: TYPE:VALUE
    /// where TYPE is one of DNS, IP, URI, email (e.g. --san DNS:host.example.com)
    #[arg(long = "san", value_name = "TYPE:VALUE", value_parser = parse_san)]
    sans: Vec<SanEntry>,
}

/// Experimental certify configuration keys.
///
/// Flattened into the top-level config so the TOML keys (`write_dir`, `force`,
/// `common_name`, `sans`) stay top-level while their definitions live here.
#[derive(Deserialize, Default)]
pub struct CertifyConfig {
    domain_policy: Option<String>,
    write_dir: Option<PathBuf>,
    force: Option<bool>,
    common_name: Option<String>,
    sans: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy)]
enum CertifyMode {
    Fresh { force: bool },
    Renew,
}

struct CertifySettings {
    server_uri: String,
    api_key_path: PathBuf,
    domain_policy: String,
    policy_id: Option<String>,
    cert_path: PathBuf,
    retry_config: RetryConfig,
    #[cfg(feature = "gpu-nvidia")]
    gpu_enabled: bool,
}

impl CertifySettings {
    fn resolve(cli: &Cli, cfg: &Config) -> Result<Self> {
        let server_uri = cli
            .server_uri
            .clone()
            .or_else(|| cfg.server_uri.clone())
            .ok_or_else(|| anyhow!("server URI is required"))?;

        if !server_uri.starts_with("http://") && !server_uri.starts_with("https://") {
            return Err(anyhow!(
                "server URI must start with http:// or https:// (got {:?})",
                server_uri
            ));
        }

        let api_key_path = cli
            .api_key
            .clone()
            .or_else(|| cfg.api_key.clone())
            .unwrap_or_else(|| PathBuf::from("/etc/tas_agent/api-key"));
        let domain_policy = cli
            .domain_policy
            .clone()
            .or_else(|| cfg.certify_config.domain_policy.clone())
            .ok_or_else(|| anyhow!("domain-policy is required for certify flow"))?;
        // Optional attestation policy id (global --policy-id), sent as `policy-id`.
        let policy_id = cli.policy_id.clone().or_else(|| cfg.policy_id.clone());
        let cert_path = cli
            .cert_path
            .clone()
            .or_else(|| cfg.cert_path.clone())
            .unwrap_or_else(|| PathBuf::from("/etc/tas_agent/root_cert.pem"));
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

        Ok(Self {
            server_uri,
            api_key_path,
            domain_policy,
            policy_id,
            cert_path,
            retry_config,
            #[cfg(feature = "gpu-nvidia")]
            gpu_enabled: !cli.no_gpu && !cfg.no_gpu.unwrap_or(false),
        })
    }
}

fn certify_report_data(
    nonce: &str,
    public_key_pkcs1_der: &[u8],
    component_hashes: &[u8],
) -> Vec<u8> {
    #[cfg(feature = "gpu-nvidia")]
    if !component_hashes.is_empty() {
        return compute_report_data_binding_with_components(
            nonce.as_bytes(),
            public_key_pkcs1_der,
            component_hashes,
        );
    }

    #[cfg(not(feature = "gpu-nvidia"))]
    debug_assert!(component_hashes.is_empty());

    compute_report_data_binding(nonce.as_bytes(), public_key_pkcs1_der)
}

/// Runs the certify/renew flow for the `certify` subcommand.
///
/// Resolves the write directory, mode, common name, and SANs from the CLI
/// arguments and config (CLI overrides config), then performs the certify or
/// renew flow. In debug mode the issued certificate bundle is written to stdout.
///
/// # Errors
///
/// Returns an error for missing required inputs, invalid common name or SAN
/// values, or any failure in the certify flow.
pub(super) async fn run(cli: &Cli, args: &CertifyArgs, cfg: &Config) -> Result<()> {
    let cert_cfg = &cfg.certify_config;

    let write_dir = args
        .write_dir
        .clone()
        .or_else(|| cert_cfg.write_dir.clone())
        .ok_or_else(|| anyhow!("--write-dir is required for the certify command"))?;

    let mode = if args.renew {
        CertifyMode::Renew
    } else {
        CertifyMode::Fresh {
            force: args.force || cert_cfg.force.unwrap_or(false),
        }
    };

    // Common name: CLI overrides config; validated here. None => auto-generated
    // in the certify flow, preserving the historical default behaviour.
    let common_name = match args
        .common_name
        .clone()
        .or_else(|| cert_cfg.common_name.clone())
    {
        Some(cn) => {
            Some(parse_common_name(&cn).map_err(|e| anyhow!("invalid common name: {}", e))?)
        }
        None => None,
    };

    // SANs: CLI overrides config (replace). Config strings are validated the
    // same way as CLI values via parse_san. Applied identically for fresh and
    // renew, so a configured SAN set is stable across renewals.
    let sans: Vec<SanEntry> = if !args.sans.is_empty() {
        args.sans.clone()
    } else if let Some(cfg_sans) = &cert_cfg.sans {
        cfg_sans
            .iter()
            .map(|s| parse_san(s).map_err(|e| anyhow!("invalid SAN in config: {}", e)))
            .collect::<Result<Vec<_>>>()?
    } else {
        Vec::new()
    };

    let settings = CertifySettings::resolve(cli, cfg)?;

    let cert_bundle_pem = certify_flow(settings, write_dir, mode, common_name, sans).await?;

    if cli.debug {
        use std::io::Write;
        std::io::stdout()
            .write_all(cert_bundle_pem.as_bytes())
            .map_err(|e| anyhow!("failed to write certificate to stdout: {}", e))?;
    }

    Ok(())
}

async fn certify_flow(
    settings: CertifySettings,
    write_dir: PathBuf,
    mode: CertifyMode,
    common_name: Option<String>,
    sans: Vec<SanEntry>,
) -> Result<String> {
    warn!("EXPERIMENTAL: certify/renew lifecycle is not production-ready");
    debug!("Retry config: {:?}", settings.retry_config);

    let api_key = read_to_string(settings.api_key_path.clone())
        .with_context(|| format!("unable to read API key from {:?}", settings.api_key_path))?
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
    let common_name = common_name.unwrap_or_else(generate_tee_common_name);
    debug!("Building plain CSR for CN: {}", common_name);
    let csr_pem = build_plain_csr(&agent_key, &common_name, &sans)
        .map_err(|e| anyhow!("failed to build CSR: {}", e))?;
    debug!("Generated certify CSR subject CN: {}", common_name);

    match tas_get_version(
        &settings.server_uri,
        &api_key,
        settings.cert_path.clone(),
        &settings.retry_config,
    )
    .await
    {
        Ok(version) => debug!("TEE Attestation Server Version: {}", version),
        Err(err) => return Err(anyhow!("TAS Version Error: {}", err)),
    }

    let nonce = tas_get_alpha_nonce(
        &settings.server_uri,
        &api_key,
        settings.cert_path.clone(),
        &settings.retry_config,
    )
    .await
    .map_err(|e| anyhow!("TAS Alpha Nonce Error: {}", e))?;
    // Match TAS vm_verify(): report_data binding uses nonce || PKCS#1 public-key DER.
    let pubkey_der = agent_key
        .public_key_to_der()
        .map_err(|e| anyhow!("Failed to get public key DER: {}", e))?;

    #[cfg(feature = "gpu-nvidia")]
    let (gpu_evidence, component_hashes) = if settings.gpu_enabled {
        let (entries, hashes) = gpu::collect(&nonce)?;
        (Some(entries), hashes)
    } else {
        (None, Vec::new())
    };
    #[cfg(not(feature = "gpu-nvidia"))]
    let component_hashes = Vec::new();

    let binding = certify_report_data(&nonce, &pubkey_der, &component_hashes);
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
        &settings.server_uri,
        &api_key,
        &nonce,
        &tee_evidence,
        &tee_type,
        renew_cert.as_deref(),
        &csr_pem,
        &settings.domain_policy,
        settings.policy_id.as_deref(),
        settings.cert_path,
        &settings.retry_config,
        #[cfg(feature = "gpu-nvidia")]
        gpu_evidence.as_deref(),
        #[cfg(not(feature = "gpu-nvidia"))]
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
                &issued.ca_chain.join("\n"),
                &issued.ca_chain.join("\n"),
                force,
            )
            .context("failed to write initial certificate materials")?;
            debug!("Wrote initial certificate materials to {:?}", write_dir);
        }
        CertifyMode::Renew => {
            material_writer::write_renewed_materials(
                &write_dir,
                &issued.certificate,
                &issued.ca_chain.join("\n"),
                &issued.ca_chain.join("\n"),
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
    use super::*;
    use clap::Parser;

    fn parse_cli(args: &[&str]) -> Cli {
        let mut all_args = vec!["tas_agent"];
        all_args.extend_from_slice(args);
        Cli::try_parse_from(all_args).unwrap()
    }

    #[test]
    fn certify_settings_cli_overrides_config() {
        let cli = parse_cli(&[
            "--server-uri",
            "https://cli.example",
            "--api-key",
            "/cli/api-key",
            "--policy-id",
            "cli-policy",
            "--domain-policy",
            "cli-domain",
            "--cert-path",
            "/cli/root.pem",
            "--max-retries",
            "9",
            "--retry-min-backoff-secs",
            "4",
            "--retry-max-backoff-secs",
            "40",
        ]);
        let cfg: Config = toml::from_str(
            r#"
server_uri = "https://config.example"
api_key = "/config/api-key"
policy_id = "config-policy"
domain_policy = "config-domain"
cert_path = "/config/root.pem"
max_retries = 2
retry_min_backoff_secs = 1
retry_max_backoff_secs = 10
"#,
        )
        .unwrap();

        let settings = CertifySettings::resolve(&cli, &cfg).unwrap();

        assert_eq!(settings.server_uri, "https://cli.example");
        assert_eq!(settings.api_key_path, PathBuf::from("/cli/api-key"));
        assert_eq!(settings.domain_policy, "cli-domain");
        assert_eq!(settings.policy_id.as_deref(), Some("cli-policy"));
        assert_eq!(settings.cert_path, PathBuf::from("/cli/root.pem"));
        assert_eq!(settings.retry_config.max_retries, 9);
        assert_eq!(settings.retry_config.min_backoff_secs, 4);
        assert_eq!(settings.retry_config.max_backoff_secs, 40);
    }

    #[test]
    fn certify_settings_use_config_and_builtin_defaults() {
        let cli = parse_cli(&[]);
        let cfg: Config = toml::from_str(
            r#"
server_uri = "http://config.example"
policy_id = "config-policy"
domain_policy = "config-domain"
"#,
        )
        .unwrap();

        let settings = CertifySettings::resolve(&cli, &cfg).unwrap();

        assert_eq!(settings.server_uri, "http://config.example");
        assert_eq!(
            settings.api_key_path,
            PathBuf::from("/etc/tas_agent/api-key")
        );
        assert_eq!(settings.domain_policy, "config-domain");
        assert_eq!(settings.policy_id.as_deref(), Some("config-policy"));
        assert_eq!(
            settings.cert_path,
            PathBuf::from("/etc/tas_agent/root_cert.pem")
        );
        assert_eq!(settings.retry_config.max_retries, 3);
        assert_eq!(settings.retry_config.min_backoff_secs, 1);
        assert_eq!(settings.retry_config.max_backoff_secs, 30);
    }

    #[test]
    fn certify_settings_validate_required_values() {
        let missing_server = CertifySettings::resolve(&parse_cli(&[]), &Config::default())
            .err()
            .unwrap();
        assert_eq!(missing_server.to_string(), "server URI is required");

        let malformed_server = CertifySettings::resolve(
            &parse_cli(&["--server-uri", "config.example"]),
            &Config::default(),
        )
        .err()
        .unwrap();
        assert!(malformed_server
            .to_string()
            .contains("server URI must start with http:// or https://"));

        let missing_policy = CertifySettings::resolve(
            &parse_cli(&["--server-uri", "https://config.example"]),
            &Config::default(),
        )
        .err()
        .unwrap();
        assert_eq!(
            missing_policy.to_string(),
            "domain-policy is required for certify flow"
        );
    }

    #[test]
    fn cpu_only_report_data_uses_plain_binding() {
        let nonce = "0123456789abcdef";
        let public_key = b"public-key";

        let actual = certify_report_data(nonce, public_key, &[]);
        let expected = compute_report_data_binding(nonce.as_bytes(), public_key);

        assert_eq!(actual, expected);
        assert_eq!(actual.len(), 64);
    }

    #[cfg(feature = "gpu-nvidia")]
    #[test]
    fn gpu_report_data_uses_component_hash_order() {
        let nonce = "0123456789abcdef";
        let public_key = b"public-key";
        let mut hashes = vec![1_u8; 64];
        hashes.extend(vec![2_u8; 64]);

        let actual = certify_report_data(nonce, public_key, &hashes);
        let expected =
            compute_report_data_binding_with_components(nonce.as_bytes(), public_key, &hashes);

        assert_eq!(actual, expected);
        assert_eq!(actual.len(), 64);

        let mut reversed = hashes.clone();
        reversed.reverse();
        assert_ne!(actual, certify_report_data(nonce, public_key, &reversed));
    }

    #[cfg(feature = "gpu-nvidia")]
    #[test]
    fn certify_settings_resolve_gpu_enablement() {
        for (cli_disabled, config_disabled, expected_enabled) in [
            (false, false, true),
            (true, false, false),
            (false, true, false),
            (true, true, false),
        ] {
            let mut args = vec![
                "--server-uri",
                "https://config.example",
                "--domain-policy",
                "domain",
            ];
            if cli_disabled {
                args.push("--no-gpu");
            }
            let cli = parse_cli(&args);
            let cfg = Config {
                no_gpu: Some(config_disabled),
                ..Default::default()
            };

            let settings = CertifySettings::resolve(&cli, &cfg).unwrap();

            assert_eq!(settings.gpu_enabled, expected_enabled);
        }
    }
}
