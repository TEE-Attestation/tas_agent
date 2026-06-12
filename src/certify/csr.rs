// TEE Attestation Service Agent
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// Plain PKCS#10 CSR construction for the TAS certificate flow.

use crate::certify::keygen::AgentKey;
use rsa::pkcs1v15::Signature;
use rsa::signature::{Keypair, Signer};
use std::error::Error;
use std::str::FromStr;
use uuid::Uuid;
use x509_cert::der::pem::LineEnding;
use x509_cert::der::{Encode, EncodePem};
use x509_cert::name::Name;
use x509_cert::request::{CertReq, CertReqInfo};
use x509_cert::spki::{
    DynSignatureAlgorithmIdentifier, SignatureBitStringEncoding, SubjectPublicKeyInfoOwned,
};

const MAX_FQDN_COMPONENT_LEN: usize = 47;
const MAX_HOSTNAME_COMPONENT_LEN: usize = 32;
const UUID_SUFFIX_HEX_LEN: usize = 12;

pub fn generate_tee_common_name() -> String {
    let uuid = Uuid::new_v4();

    if let Some(fqdn) = preferred_fqdn_for_cn() {
        return generate_tee_common_name_from_fqdn(Some(&fqdn), uuid);
    }

    let hostname = hostname::get()
        .ok()
        .and_then(|name| name.into_string().ok())
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty());
    generate_tee_common_name_from_hostname(hostname.as_deref(), uuid)
}

fn preferred_fqdn_for_cn() -> Option<String> {
    #[cfg(unix)]
    {
        if let Some(fqdn) = try_get_fqdn_from_hostname_command() {
            return Some(fqdn);
        }
    }

    None
}

#[cfg(unix)]
fn try_get_fqdn_from_hostname_command() -> Option<String> {
    use std::process::Command;

    let output = Command::new("hostname").arg("-f").output().ok()?;
    if !output.status.success() {
        return None;
    }

    let fqdn = String::from_utf8(output.stdout).ok()?;
    let fqdn = fqdn.trim();
    if fqdn.is_empty() || !fqdn.contains('.') {
        return None;
    }

    Some(fqdn.to_string())
}

fn generate_tee_common_name_from_fqdn(hostname: Option<&str>, uuid: Uuid) -> String {
    let hostname = hostname
        .map(sanitize_fqdn_component)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    let uuid_simple = uuid.simple().to_string();
    let suffix = &uuid_simple[..UUID_SUFFIX_HEX_LEN];
    format!("tee.{}-{}", hostname, suffix)
}

fn generate_tee_common_name_from_hostname(hostname: Option<&str>, uuid: Uuid) -> String {
    let hostname = hostname
        .map(sanitize_hostname_component)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    let uuid_simple = uuid.simple().to_string();
    let suffix = &uuid_simple[..UUID_SUFFIX_HEX_LEN];
    format!("tas.{}-{}", hostname, suffix)
}

fn sanitize_hostname_component(hostname: &str) -> String {
    let mut sanitized = String::with_capacity(hostname.len().min(MAX_HOSTNAME_COMPONENT_LEN));
    let mut last_was_hyphen = false;

    for ch in hostname.chars().flat_map(char::to_lowercase) {
        let mapped = if ch.is_ascii_alphanumeric() { ch } else { '-' };

        if mapped == '-' {
            if sanitized.is_empty() || last_was_hyphen {
                continue;
            }
            last_was_hyphen = true;
        } else {
            last_was_hyphen = false;
        }

        sanitized.push(mapped);

        if sanitized.len() >= MAX_HOSTNAME_COMPONENT_LEN {
            break;
        }
    }

    while sanitized.ends_with('-') {
        sanitized.pop();
    }

    sanitized
}

fn sanitize_fqdn_component(hostname: &str) -> String {
    let mut sanitized = String::with_capacity(hostname.len().min(MAX_FQDN_COMPONENT_LEN));
    let mut last_was_separator = false;

    for ch in hostname.chars().flat_map(char::to_lowercase) {
        let mapped = if ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' {
            ch
        } else {
            '-'
        };

        if mapped == '-' || mapped == '.' {
            if sanitized.is_empty() || last_was_separator {
                continue;
            }
            last_was_separator = true;
        } else {
            last_was_separator = false;
        }

        sanitized.push(mapped);

        if sanitized.len() >= MAX_FQDN_COMPONENT_LEN {
            break;
        }
    }

    while sanitized.ends_with('-') || sanitized.ends_with('.') {
        sanitized.pop();
    }

    sanitized
}

pub fn build_plain_csr(key: &AgentKey, common_name: &str) -> Result<String, Box<dyn Error>> {
    let subject = Name::from_str(&format!("CN={}", common_name))?;
    let signing_key = key.rsa_4096_signing_key();
    let verifying_key = signing_key.verifying_key();
    let public_key = SubjectPublicKeyInfoOwned::from_key(verifying_key)?;
    let info = CertReqInfo {
        version: Default::default(),
        subject,
        public_key,
        attributes: Default::default(),
    };
    let info_der = info.to_der()?;
    let signature: Signature = signing_key.sign(&info_der);
    let csr = CertReq {
        info,
        algorithm: signing_key.signature_algorithm_identifier()?,
        signature: signature.to_bitstring()?,
    };
    Ok(csr.to_pem(LineEnding::LF)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1v15::VerifyingKey;
    use rsa::signature::Verifier;
    use x509_cert::der::{DecodePem, Encode};
    use x509_cert::request::CertReq;
    use x509_cert::spki::SubjectPublicKeyInfoRef;

    #[test]
    fn sanitizes_hostname_component() {
        assert_eq!(sanitize_hostname_component("CVM_Prod.01"), "cvm-prod-01");
        assert_eq!(sanitize_hostname_component("---bad///name---"), "bad-name");
        assert_eq!(sanitize_hostname_component(""), "");
    }

    #[test]
    fn sanitizes_fqdn_component() {
        assert_eq!(
            sanitize_fqdn_component("Node1.Dev_Prod.Example.Com"),
            "node1.dev-prod.example.com"
        );
        assert_eq!(sanitize_fqdn_component("...bad///name..."), "bad-name");
    }

    #[test]
    fn generated_common_name_uses_fqdn_when_available() {
        let uuid = Uuid::parse_str("3f2a9c14-8b7d-4e21-a9f0-1c2d3e4f5a6b").unwrap();
        let cn = generate_tee_common_name_from_fqdn(Some("node1.dev.example.com"), uuid);
        assert_eq!(cn, "tee.node1.dev.example.com-3f2a9c148b7d");
    }

    #[test]
    fn generated_common_name_uses_current_scheme_when_not_fqdn() {
        let uuid = Uuid::parse_str("3f2a9c14-8b7d-4e21-a9f0-1c2d3e4f5a6b").unwrap();
        let cn = generate_tee_common_name_from_hostname(Some("CVM_Prod.01"), uuid);
        assert_eq!(cn, "tas.cvm-prod-01-3f2a9c148b7d");
    }

    #[test]
    fn generated_common_name_falls_back_to_unknown() {
        let uuid = Uuid::parse_str("3f2a9c14-8b7d-4e21-a9f0-1c2d3e4f5a6b").unwrap();
        let cn = generate_tee_common_name_from_hostname(Some("////"), uuid);
        assert_eq!(cn, "tas.unknown-3f2a9c148b7d");
    }

    #[test]
    fn generated_common_names_have_distinct_suffixes() {
        let first = generate_tee_common_name();
        let second = generate_tee_common_name();
        assert_ne!(first, second);
        assert!(first.starts_with("tee.") || first.starts_with("tas."));
        assert!(second.starts_with("tee.") || second.starts_with("tas."));
    }

    #[test]
    fn builds_plain_pem_csr() {
        let key = AgentKey::generate(crate::certify::keygen::KeyAlgorithm::Rsa4096).unwrap();
        let cn = generate_tee_common_name_from_fqdn(
            Some("node1.dev.example.com"),
            Uuid::parse_str("3f2a9c14-8b7d-4e21-a9f0-1c2d3e4f5a6b").unwrap(),
        );
        let pem = build_plain_csr(&key, &cn).unwrap();

        assert!(pem.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
        let csr = CertReq::from_pem(&pem).unwrap();
        assert!(csr.info.attributes.is_empty());
        assert!(csr.info.subject.to_string().contains(&cn));

        let public_key_der = csr.info.public_key.to_der().unwrap();
        let public_key_ref = SubjectPublicKeyInfoRef::try_from(public_key_der.as_slice()).unwrap();
        let verifying_key = VerifyingKey::<sha2::Sha256>::try_from(public_key_ref).unwrap();
        let signature = Signature::try_from(csr.signature.raw_bytes()).unwrap();
        verifying_key
            .verify(&csr.info.to_der().unwrap(), &signature)
            .unwrap();
    }
}
