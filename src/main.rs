// TEE Attestation Service Agent
//
// Copyright 2025 Hewlett Packard Enterprise Development LP.
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

use pretty_hex::PrettyHex;
use std::env;
use std::path::PathBuf;

// Import the `tee_get_evidence` function from the `tee_evidence` module
mod crypto;
mod tas_api;
mod tee_evidence;
mod utils;
use clap::Parser;

use crypto::{decrypt_secret_with_aes_key, generate_wrapping_key};
use tas_api::{tas_get_nonce, tas_get_secret_key, tas_get_version};
use tee_evidence::tee_get_evidence;
use utils::SecretsPayload;

/// Prints debug messages to stdout if the debug flag (-d) is enabled.
macro_rules! debug_println {
    ($debug:expr, $($arg:tt)*) => {
        if $debug {
            println!($($arg)*);
        }
    };
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Display debugging messages
    #[arg(short, long)]
    debug: bool,

    /// Path to the config file (default: '/etc/tas_agent/config')
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Load environment variables from a `.env` file or the system environment
    match cli.config {
        Some(path) => {
            if !path.exists() {
                eprintln!("config file {:?} does not exist", path);
                std::process::exit(1);
            }
            dotenv::from_path(path).ok()
        }
        None => dotenv::from_path("/etc/tas_agent/config").ok(),
    };

    // Retrieve the REST server URI, API key, key ID, and root certificate path from environment variables
    let server_uri = env::var("TAS_SERVER_URI").expect("TAS_SERVER_URI must be set");
    let api_key = env::var("TAS_SERVER_API_KEY").expect("TAS_SERVER_API_KEY must be set");
    let key_id = env::var("TAS_KEY_ID").expect("TAS_KEY_ID must be set");
    let cert_path = env::var("TAS_SERVER_ROOT_CERT").expect("TAS_SERVER_ROOT_CERT must be set");

    // Generate a wrapping key for the HSM to wrap the secret key with
    debug_println!(cli.debug, "Generating wrapping key...");
    let rsa_wrapping_key = generate_wrapping_key().expect("Failed to generate wrapping key");
    debug_println!(
        cli.debug,
        "\nGenerated wrapping key: {}\n",
        rsa_wrapping_key
    );

    let wrapping_key = rsa_wrapping_key
        .public_key_to_base64()
        .expect("Failed to convert wrapping key to DER base64");
    debug_println!(
        cli.debug,
        "Base64-encoded public wrapping key: {}\n",
        wrapping_key
    );

    // Call the function to get the TAS server version
    match tas_get_version(&server_uri, &api_key, &cert_path).await {
        Ok(version) => debug_println!(cli.debug, "TEE Attestation Server Version: {}", version),
        Err(err) => {
            eprintln!("TAS Version Error: {}", err);
            std::process::exit(1);
        }
    }

    // Call the function to get the nonce from the TAS server
    let nonce = match tas_get_nonce(&server_uri, &api_key, &cert_path).await {
        Ok(nonce) => {
            debug_println!(cli.debug, "Nonce: {}", nonce);
            nonce
        }
        Err(err) => {
            eprintln!("TAS Nonce Error: {}", err);
            std::process::exit(1);
        }
    };

    // Generate the TEE evidence and get the TEE type using the nonce
    let (tee_evidence, tee_type) = match tee_get_evidence(&nonce, cli.debug) {
        Ok((evidence, tee_type)) => {
            debug_println!(
                cli.debug,
                "Generated TEE Evidence (Base64-encoded): {}",
                evidence
            );
            debug_println!(cli.debug, "TEE Type: {}", tee_type);
            (evidence, tee_type)
        }
        Err(err) => {
            eprintln!("TEE evidence Error: {}", err);
            std::process::exit(1);
        }
    };

    // Call the function to get the secret key using the nonce, tee_evidence, tee_type, and key_id
    let secret_string = match tas_get_secret_key(
        &server_uri,
        &api_key,
        &nonce,
        &tee_evidence,
        &tee_type,
        &key_id,
        &wrapping_key,
        &cert_path,
    )
    .await
    {
        Ok(secret_key) => {
            debug_println!(cli.debug, "Secret Key/Payload: {}", secret_key);
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
            debug_println!(cli.debug, "Deserialized secret payload: {:?}", secret);
            secret
        }
        Err(err) => {
            eprintln!("JSON Deserialize Error: {}", err);
            std::process::exit(1);
        }
    };

    // Unwrap the secret key using the wrapping key
    debug_println!(cli.debug, "Unwrapping secret key...");
    let aes_key = match rsa_wrapping_key.unwrap_key(&secret.wrapped_key) {
        Ok(aes_key) => aes_key,
        Err(err) => {
            eprintln!("Crypto Unwrap Error: {}", err);
            std::process::exit(1);
        }
    };
    debug_println!(cli.debug, "Unwrapped secret key: {:?}", aes_key.hex_dump());

    // Decrypt the secret payload using the unwrapped AES key
    debug_println!(cli.debug, "Decrypting secret payload...");
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
