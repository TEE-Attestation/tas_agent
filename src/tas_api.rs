// TEE Attestation Service Agent
//
// Copyright 2025 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// This application interacts via a REST API with the TEE Attestation Service Key Broker Module.
//
// TAS REST API functionality.
//
use reqwest::{Certificate, Client};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

/// Helper function to create a `reqwest::Client` with a custom root certificate
fn create_client_with_root_cert(cert_path: PathBuf) -> Result<Client, String> {
    // Load the root certificate from the specified file
    let cert_data =
        fs::read(cert_path).map_err(|err| format!("Error reading certificate file: {}", err))?;
    let cert = Certificate::from_pem(&cert_data)
        .map_err(|err| format!("Error parsing certificate: {}", err))?;

    // Build the client with the custom root certificate
    Client::builder()
        .add_root_certificate(cert)
        //.danger_accept_invalid_certs(true) // For Testing: Disable cert validation including hostname verification
        .build()
        .map_err(|err| format!("Error creating HTTP client: {}", err))
}

/// Function to make the GET request to the version API and return the server version
pub async fn tas_get_version(
    server_uri: &str,
    api_key: &str,
    cert_path: PathBuf,
) -> Result<String, String> {
    let version_url = format!("{}/version", server_uri);
    let client = create_client_with_root_cert(cert_path)?;

    match client
        .get(&version_url)
        .header("X-API-KEY", api_key)
        .send()
        .await
    {
        Ok(response) => {
            if response.status().is_success() {
                match response.json::<Value>().await {
                    Ok(json) => {
                        if let Some(version) = json.get("version") {
                            Ok(version.to_string())
                        } else {
                            Err("Error: 'version' field not found in response".to_string())
                        }
                    }
                    Err(err) => Err(format!("Error parsing JSON response: {}", err)),
                }
            } else {
                Err(format!("Error: Received HTTP {}", response.status()))
            }
        }
        Err(err) => Err(format!("Error making request: {}", err)),
    }
}

/// Function to make the GET request to the get_nonce API and return the nonce
pub async fn tas_get_nonce(
    server_uri: &str,
    api_key: &str,
    cert_path: PathBuf,
) -> Result<String, String> {
    let nonce_url = format!("{}/kb/v0/get_nonce", server_uri);
    let client = create_client_with_root_cert(cert_path)?;

    match client
        .get(&nonce_url)
        .header("X-API-KEY", api_key)
        .send()
        .await
    {
        Ok(response) => {
            if response.status().is_success() {
                match response.json::<Value>().await {
                    Ok(json) => {
                        if let Some(nonce) = json.get("nonce") {
                            Ok(nonce.to_string())
                        } else {
                            Err("Error: 'nonce' field not found in response".to_string())
                        }
                    }
                    Err(err) => Err(format!("Error parsing JSON response: {}", err)),
                }
            } else {
                Err(format!("Error: Received HTTP {}", response.status()))
            }
        }
        Err(err) => Err(format!("Error making request: {}", err)),
    }
}

/// Function to make the POST request to the get_secret API and return the secret key
#[allow(clippy::too_many_arguments)]
pub async fn tas_get_secret_key(
    server_uri: &str,
    api_key: &str,
    nonce: &str,
    tee_evidence: &str,
    tee_type: &str,
    key_id: &str,
    wrapping_key: &str,
    cert_path: PathBuf,
) -> Result<String, String> {
    let secret_url = format!("{}/kb/v0/get_secret", server_uri);
    let client = create_client_with_root_cert(cert_path)?;

    // Create the JSON body for the POST request
    let body = serde_json::json!({
        "tee-type": tee_type,
        "nonce": nonce,
        "tee-evidence": tee_evidence,
        "key-id": key_id,
        "wrapping-key": wrapping_key
    });

    match client
        .post(&secret_url)
        .header("X-API-KEY", api_key)
        .json(&body)
        .send()
        .await
    {
        Ok(response) => {
            if response.status().is_success() {
                match response.json::<Value>().await {
                    Ok(json) => {
                        if let Some(secret_key) = json.get("secret_key") {
                            Ok(secret_key.to_string())
                        } else {
                            Err("Error: 'secret_key' field not found in response".to_string())
                        }
                    }
                    Err(err) => Err(format!("Error parsing JSON response: {}", err)),
                }
            } else {
                Err(format!(
                    "Error: Received HTTP {} with message: {}",
                    response.status(),
                    response
                        .text()
                        .await
                        .unwrap_or_else(|_| "Unable to read response body".to_string())
                ))
            }
        }
        Err(err) => Err(format!("Error making request: {}", err)),
    }
}

// Test module for the tas_get_version, tas_get_nonce, and tas_get_secret_key functions
// This module contains unit tests for the tas_get_version, tas_get_nonce, and tas_get_secret_key functions.
// It uses the `mockito` crate to mock HTTP requests and responses.
// The tests cover various scenarios, including successful responses, missing fields,
// and HTTP errors. Each test simulates a different response from the server
// and verifies that the functions behave as expected.
// The tests are asynchronous and use the `tokio` runtime for handling async operations.
// The tests are marked with the `#[tokio::test]` attribute to indicate that they are asynchronous tests.
#[cfg(test)]
mod tests {
    use super::*;
    use mockito::{mock, server_url};
    //use std::fs;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Helper function to create a temporary PEM file for testing
    fn create_test_cert() -> NamedTempFile {
        let mut temp_file = NamedTempFile::new().expect("Failed to create temporary file");
        let cert_content = r#"
-----BEGIN CERTIFICATE-----
MIIFATCCAumgAwIBAgIRANd0Vl3DsRLwMPsH2hKdJAwwDQYJKoZIhvcNAQELBQAw
WjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAlRYMQ8wDQYDVQQHEwZBdXN0aW4xDzAN
BgNVBAoTBlRoYWxlczEcMBoGA1UEAxMTQ2lwaGVyVHJ1c3QgUm9vdCBDQTAeFw0y
NTA1MTIwOTU4MDlaFw0zNTAzMjQxODA2MTBaMGQxCzAJBgNVBAYTAlVTMREwDwYD
VQQIEwhDb2xvcmFkbzEVMBMGA1UEBxMMRm9ydCBDb2xsaW5zMR0wGwYDVQQKExRI
ZXdsZXR0IFBhY2thcmQgTGFiczEMMAoGA1UEAxMDVEFTMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEAhaPsSZPmVO8Mpd8OjWxZqWAWjLhBCVWUwR2hVF6C
JJgPQijUsQt3Dyx0MZWfgb1qLwrzWTGWKnq8LvhUj/xmWvDL9YmLTBlqq0s5HcwI
9QVm+UtKLXBQzMi4zhELhydkUFvy3qysM1x6VQVNeG9qhKXfonOwFvDsJYD01FiC
447guAUoqIVecrEZUJA/m8EpU8dMhMdjLqswFLi9bVtg6F65Nb4YyQNnCRVsr0hA
JYeZv42CEd4HINK2n7xXmLcAsW6uoBY8qXcEbE2jqs4274vXZ74trfJrWj/GW8uL
jzuxsc6Nh3t5coTnuBQjebSPeX7DaJbLZ9M15ASnuVfj1QIDAQABo4G3MIG0MA4G
A1UdDwEB/wQEAwIDiDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAA
MB8GA1UdIwQYMBaAFAtzTvWEmr72yaVeWNW0mjrVZlZmMF4GA1UdHwRXMFUwU6BR
oE+GTWh0dHA6Ly9jaXBoZXJ0cnVzdG1hbmFnZXIubG9jYWwvY3Jscy8xOTcyNTVm
Ny1mNmRjLTQ0YTUtYWNiOC1mNTEyZDMyYWEyNjMuY3JsMA0GCSqGSIb3DQEBCwUA
A4ICAQDEt3PUqsMNP5PI2iB4z2QXbBa9B3ndYEbFl16L0b4quI1mONM4VeKbTUQk
k1aXC1Q8Wbhfi5GrtESp/Gac0CGM3w8oX9yLYWO9e/XJO5MIfxprgS2IgKRNVa81
1gDjdAnxMhzcIy5iV7p6atprITdyKTj07VuU9qmbJKPDNeUjdKfujvbUFYInRUDd
n6FkGOeK0lzzNxxby/z1qdI3WlLFioq1HvAeHQVueH54vePI3QwnTk6qmcl8RHn0
pWeOkiqgnincMCnsnhyrnMDsX/DNSF7mwynIJQxBfOOp7pFBpzubY4gvhRQ3lkmV
Uc2wNeK9M9uiPTBJAwRmialJHogIfQbKgL/iWTWdw2O1JIVta+oXHiTgLJVsJz7P
NQSfBe+CfcAYe6cQzUkUQT5hJVvLoQM+hJrITehQWKrSdokhJwkbpPweNeGAAlEy
d7/kIkP8k/rsQz7Da9GjUjGhS+VMkAz9BBU6FiDXJZyJFmeEJe5fgsbRGX8wvuqn
uBIrBSk/RT5n1J62+FQOhb9NbcwyYKza9rmYahSRlmXe5Ct5LwPz3AZXlSfbsFOn
MRYTnHVgon3F8Lk6ZsKGQ27CXYFMt9iIUAmkg6LmbJDqNR8NLqigo+Nfhq4rPUfP
43Pv68i6IWf8wqoiBgOIsHaauphoZjoOIDRWYmb9OQ9yI0+eUw==
-----END CERTIFICATE-----
"#;
        temp_file
            .write_all(cert_content.as_bytes())
            .expect("Failed to write to temporary file");
        temp_file
    }

    #[tokio::test]
    async fn test_tas_get_version_success() {
        let _mock = mock("GET", "/version")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"version": "1.2.3"}"#)
            .create();

        let server_uri = server_url();
        let api_key = "test_api_key";
        let cert_file = create_test_cert();
        let cert_path = cert_file.path().to_path_buf();
        let result = tas_get_version(&server_uri, api_key, cert_path).await;

        assert_eq!(result.unwrap(), "\"1.2.3\"");
    }

    #[tokio::test]
    async fn test_tas_get_nonce_success() {
        let _mock = mock("GET", "/kb/v0/get_nonce")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"nonce": "abc123"}"#)
            .create();

        let server_uri = server_url();
        let api_key = "test_api_key";
        let cert_file = create_test_cert();
        let cert_path = cert_file.path().to_path_buf();
        let result = tas_get_nonce(&server_uri, api_key, cert_path).await;

        assert_eq!(result.unwrap(), "\"abc123\"");
    }

    #[tokio::test]
    async fn test_tas_get_secret_key_success() {
        let _mock = mock("POST", "/kb/v0/get_secret")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"secret_key": "xyz789"}"#)
            .create();

        let server_uri = server_url();
        let api_key = "test_api_key";
        let nonce = "abc123";
        let tee_evidence = "base64_encoded_report";
        let tee_type = "amd-sev-snp";
        let key_id = "key123";
        let wrapping_key = "wrapping_key";
        let cert_file = create_test_cert();
        let cert_path = cert_file.path().to_path_buf();
        let result = tas_get_secret_key(
            &server_uri,
            api_key,
            nonce,
            tee_evidence,
            tee_type,
            key_id,
            wrapping_key,
            cert_path,
        )
        .await;

        assert_eq!(result.unwrap(), "\"xyz789\"");
    }

    #[tokio::test]
    async fn test_tas_get_version_missing_version_field() {
        // Explanation:
        // This test simulates a response from the `/version` endpoint where the "version"
        // field is missing. The mocked response contains a different field ("other_field").
        // The test verifies that the `tas_get_version` function returns an appropriate
        // error message indicating that the "version" field was not found.

        // Mock the /version endpoint with a response missing the "version" field
        let _mock = mock("GET", "/version")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"other_field": "value"}"#)
            .create();

        // Call the function with the mock server URL
        let server_uri = server_url();
        let api_key = "test_api_key";
        let cert_file = create_test_cert();
        let cert_path = cert_file.path().to_path_buf();
        let result = tas_get_version(&server_uri, api_key, cert_path).await;

        // Assert the result
        assert_eq!(
            result.unwrap_err(),
            "Error: 'version' field not found in response"
        );
    }

    #[tokio::test]
    async fn test_tas_get_version_http_error() {
        // Explanation:
        // This test simulates an HTTP error response from the `/version` endpoint.
        // The mocked response has a status code of 500 (Internal Server Error).
        // The test verifies that the `tas_get_version` function returns an error
        // message indicating the HTTP status code of the failed request.

        // Mock the /version endpoint with an HTTP error
        let _mock = mock("GET", "/version")
            .with_status(500)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error": "Internal Server Error"}"#)
            .create();

        // Call the function with the mock server URL
        let server_uri = server_url();
        let api_key = "test_api_key";
        let cert_file = create_test_cert();
        let cert_path = cert_file.path().to_path_buf();
        let result = tas_get_version(&server_uri, api_key, cert_path).await;

        // Assert the result
        assert!(result.unwrap_err().contains("Error: Received HTTP 500"));
    }

    #[tokio::test]
    async fn test_tas_get_nonce_missing_nonce_field() {
        // Explanation:
        // This test simulates a response from the `/kb/get_nonce` endpoint where the "nonce"
        // field is missing. The mocked response contains a different field ("other_field").
        // The test verifies that the `tas_get_nonce` function returns an appropriate
        // error message indicating that the "nonce" field was not found.

        // Mock the /kb/get_nonce endpoint with a response missing the "nonce" field
        let _mock = mock("GET", "/kb/v0/get_nonce")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"other_field": "value"}"#)
            .create();

        // Call the function with the mock server URL
        let server_uri = server_url();
        let api_key = "test_api_key";
        let cert_file = create_test_cert();
        let cert_path = cert_file.path().to_path_buf();
        println!("cert_path: {:?}", cert_path);
        println!("server_uri: {}", server_uri);
        let result = tas_get_nonce(&server_uri, api_key, cert_path).await;

        // Assert the result
        assert_eq!(
            result.unwrap_err(),
            "Error: 'nonce' field not found in response"
        );
    }

    #[tokio::test]
    async fn test_tas_get_nonce_http_error() {
        // Explanation:
        // This test simulates an HTTP error response from the `/kb/get_nonce` endpoint.
        // The mocked response has a status code of 500 (Internal Server Error).
        // The test verifies that the `tas_get_nonce` function returns an error
        // message indicating the HTTP status code of the failed request.

        // Mock the /kb/get_nonce endpoint with an HTTP error
        let _mock = mock("GET", "/kb/v0/get_nonce")
            .with_status(500)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error": "Internal Server Error"}"#)
            .create();

        // Call the function with the mock server URL
        let server_uri = server_url();
        let api_key = "test_api_key";
        let cert_file = create_test_cert();
        let cert_path = cert_file.path().to_path_buf();
        let result = tas_get_nonce(&server_uri, api_key, cert_path).await;

        // Assert the result
        assert!(result.unwrap_err().contains("Error: Received HTTP 500"));
    }

    #[tokio::test]
    async fn test_tas_get_secret_key_missing_secret_key_field() {
        // Mock the /kb/get_secret endpoint with a response missing the "secret_key" field
        let _mock = mock("POST", "/kb/v0/get_secret")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"other_field": "value"}"#)
            .create();

        // Call the function with the mock server URL
        let server_uri = server_url();
        let api_key = "test_api_key";
        let nonce = "abc123";
        let tee_evidence = "base64_encoded_report";
        let tee_type = "amd-sev-snp";
        let key_id = "key123";
        let wrapping_key = "wrapping_key";
        let cert_file = create_test_cert();
        let cert_path = cert_file.path().to_path_buf();
        let result = tas_get_secret_key(
            &server_uri,
            api_key,
            nonce,
            tee_evidence,
            tee_type,
            key_id,
            wrapping_key,
            cert_path,
        )
        .await;

        // Assert the result
        assert_eq!(
            result.unwrap_err(),
            "Error: 'secret_key' field not found in response"
        );
    }

    #[tokio::test]
    async fn test_tas_get_secret_key_http_error() {
        // Mock the /kb/get_secret endpoint with an HTTP error
        let _mock = mock("POST", "/kb/v0/get_secret")
            .with_status(500)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error": "Internal Server Error"}"#)
            .create();

        // Call the function with the mock server URL
        let server_uri = server_url();
        let api_key = "test_api_key";
        let nonce = "abc123";
        let tee_evidence = "base64_encoded_report";
        let tee_type = "amd-sev-snp";
        let key_id = "key123";
        let wrapping_key = "wrapping_key";
        let cert_file = create_test_cert();
        let cert_path = cert_file.path().to_path_buf();
        let result = tas_get_secret_key(
            &server_uri,
            api_key,
            nonce,
            tee_evidence,
            tee_type,
            key_id,
            wrapping_key,
            cert_path,
        )
        .await;

        // Assert the result
        assert!(result.unwrap_err().contains("Error: Received HTTP 500"));
    }
}
