// TEE Attestation Service Agent
//
// Copyright 2025 - 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// EXPERIMENTAL: certify/renew-specific TAS REST API calls and payload types.
// Gated behind the off-by-default `certify` Cargo feature. The core TAS API
// lives in `src/tas_api.rs`; this module reuses its `create_client` helper.

use std::path::PathBuf;

use base64::{engine::general_purpose, Engine};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use x509_cert::der::{DecodePem, Encode};
use x509_cert::request::CertReq;

use crate::tas_api::{create_client, RetryConfig};

#[derive(Debug, Deserialize)]
pub struct CertifyResponse {
    pub certificate: String,
    #[serde(default)]
    pub ca_chain: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CertifyRequest<'a> {
    #[serde(rename = "tee-type")]
    tee_type: &'a str,
    nonce: &'a str,
    #[serde(rename = "tee-evidence")]
    tee_evidence: &'a str,
    csr: String,
    #[serde(rename = "policy-domain")]
    policy_domain: &'a str,
    #[serde(skip_serializing_if = "Option::is_none", rename = "renew_cert")]
    renew_cert: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "gpu-evidence")]
    gpu_evidence: Option<&'a serde_json::Value>,
}

pub async fn tas_get_alpha_nonce(
    server_uri: &str,
    api_key: &str,
    cert_path: PathBuf,
    retry_config: &RetryConfig,
) -> Result<String, String> {
    let nonce_url = format!("{}/alphav1/nonce", server_uri);
    let client = create_client(server_uri, cert_path, retry_config)?;

    match client
        .get(&nonce_url)
        .header("X-API-KEY", api_key)
        .send()
        .await
    {
        Ok(response) => {
            if response.status().is_success() {
                match response.json::<Value>().await {
                    Ok(json) => json
                        .get("nonce")
                        .and_then(Value::as_str)
                        .map(|nonce| nonce.to_string())
                        .ok_or_else(|| "Error: 'nonce' field not found in response".to_string()),
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

#[allow(clippy::too_many_arguments)]
pub async fn tas_certify(
    server_uri: &str,
    api_key: &str,
    nonce: &str,
    tee_evidence: &str,
    tee_type: &str,
    renew_cert: Option<&str>,
    csr_pem: &str,
    policy_domain: &str,
    cert_path: PathBuf,
    retry_config: &RetryConfig,
    gpu_evidence: Option<&serde_json::Value>,
) -> Result<CertifyResponse, String> {
    let certify_url = format!("{}/alphav1/certify", server_uri);
    let client = create_client(server_uri, cert_path, retry_config)?;

    let cert_req = CertReq::from_pem(csr_pem)
        .map_err(|err| format!("Failed to parse CSR PEM for certify request: {}", err))?;
    let csr_der = cert_req
        .to_der()
        .map_err(|err| format!("Failed to encode CSR DER for certify request: {}", err))?;
    let csr_der_b64 = general_purpose::STANDARD.encode(csr_der);

    let body = CertifyRequest {
        tee_type,
        nonce,
        renew_cert,
        tee_evidence,
        csr: csr_der_b64,
        policy_domain,
        gpu_evidence,
    };

    match client
        .post(&certify_url)
        .header("X-API-KEY", api_key)
        .json(&body)
        .send()
        .await
    {
        Ok(response) => {
            if response.status().as_u16() == 200 || response.status().as_u16() == 201 {
                response
                    .json::<CertifyResponse>()
                    .await
                    .map_err(|err| format!("Error parsing JSON response: {}", err))
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

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn no_retry_config() -> RetryConfig {
        RetryConfig {
            max_retries: 0,
            min_backoff_secs: 0,
            max_backoff_secs: 0,
        }
    }

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

    fn sample_csr_pem() -> &'static str {
        r#"-----BEGIN CERTIFICATE REQUEST-----
MIICYDCCAUgCAQAwGzEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMR4qWlFXawpabqezK5iwuxUcJL8yHe/
RGBKi5nueLWRaV8169T5diNeXI5DXxKv/RV+hPzeJcAsPoZxiRJdMBecImLW4N4L
tYFdoguiPacZoZEGNLu9ntANN1E+MYkAw9RHq+ynyhh4EUxEZFDNVOHxQ3Kf4DoK
q/b0ByUnKucNI3WSB1AfBG+wqqmRza5BnDuHubZ+18Pib9xIlBlAio6PltrfRACB
dFQ2SjDqQksWRzNJ3/+Q60po+HtnhW3CduKDNzmh5E3gPFrt5Ami5qos4w4ddcsD
J1EmL7xeC4avsnoXqoXA10chX7Ze2tV41WCzh9ImR3925owhcF09tckCAwEAAaAA
MA0GCSqGSIb3DQEBCwUAA4IBAQBk0pgsolCfzTdCOXkvP4qZQwfAyIIgm2qClAyC
LH5YGbecanqHE9VQWU/JVGcsNkQcyed8vZ8Sf/IoTdKWbKFozRoglmk7+piWnkCL
A5Fc4yyg1wx3TW6HFRR2Z7YMZpvAVln3qymOpxUvsEkg2o2f/R8VwDhJ3ubAuEFM
SOA6EhgFE5Dwieu7o/Vt092EyH2gMcllM2We2Zg89QVKbmqJLzMBXsdgGov36zgH
ISXfQJBHHM6UgrnAWYpTzlsCF1ZC1BHOi2ZG20BGaIRvFNMjLMeDCBY6EydUgsPy
CzWyyc0J/7PWdmvFVgXukRznKqZp/d4xAaQIKxLcxGwwDNp1
-----END CERTIFICATE REQUEST-----
"#
    }

    #[tokio::test]
    async fn test_tas_get_alpha_nonce_success() {
        let mut server = Server::new_async().await;
        let _mock = server
            .mock("GET", "/alphav1/nonce")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"nonce":"alpha-nonce-123"}"#)
            .create_async()
            .await;

        let cert_file = create_test_cert();
        let result = tas_get_alpha_nonce(
            &server.url(),
            "key",
            cert_file.path().to_path_buf(),
            &no_retry_config(),
        )
        .await;

        assert_eq!(result.unwrap(), "alpha-nonce-123");
    }

    #[tokio::test]
    async fn test_tas_get_alpha_nonce_missing_nonce_field() {
        let mut server = Server::new_async().await;
        let _mock = server
            .mock("GET", "/alphav1/nonce")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"wrong":"value"}"#)
            .create_async()
            .await;

        let cert_file = create_test_cert();
        let result = tas_get_alpha_nonce(
            &server.url(),
            "key",
            cert_file.path().to_path_buf(),
            &no_retry_config(),
        )
        .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("'nonce' field not found"));
    }

    #[tokio::test]
    async fn test_tas_certify_success_and_request_fields() {
        let csr_der = CertReq::from_pem(sample_csr_pem())
            .unwrap()
            .to_der()
            .unwrap();
        let expected_csr_b64 = general_purpose::STANDARD.encode(csr_der);
        let expected_body = format!(
            r#"{{"tee-type":"amd-sev-snp","nonce":"nonce123","tee-evidence":"dGVzdC1ldmlkZW5jZQ==","csr":"{}","policy-domain":"tenant-a"}}"#,
            expected_csr_b64
        );

        let mut server = Server::new_async().await;
        let mock = server
            .mock("POST", "/alphav1/certify")
            .match_body(mockito::Matcher::JsonString(expected_body))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"certificate":"-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----","ca_chain":["-----BEGIN CERTIFICATE-----\nca1\n-----END CERTIFICATE-----"]}"#,
            )
            .create_async()
            .await;

        let cert_file = create_test_cert();
        let result = tas_certify(
            &server.url(),
            "key",
            "nonce123",
            "dGVzdC1ldmlkZW5jZQ==",
            "amd-sev-snp",
            None,
            sample_csr_pem(),
            "tenant-a",
            cert_file.path().to_path_buf(),
            &no_retry_config(),
            None,
        )
        .await
        .unwrap();

        assert!(result.certificate.contains("BEGIN CERTIFICATE"));
        assert_eq!(result.ca_chain.len(), 1);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_tas_certify_http_error() {
        let mut server = Server::new_async().await;
        let _mock = server
            .mock("POST", "/alphav1/certify")
            .with_status(400)
            .with_body("bad request")
            .create_async()
            .await;

        let cert_file = create_test_cert();
        let result = tas_certify(
            &server.url(),
            "key",
            "nonce123",
            "dGVzdC1ldmlkZW5jZQ==",
            "amd-sev-snp",
            None,
            sample_csr_pem(),
            "tenant-a",
            cert_file.path().to_path_buf(),
            &no_retry_config(),
            None,
        )
        .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Received HTTP 400"));
    }
}
