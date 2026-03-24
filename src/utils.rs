// TEE Attestation Service Agent
//
// Copyright 2025 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// This module provides the client application with utility functions.

use base64::{engine::general_purpose, Engine};
use serde::{de::DeserializeOwned, Deserialize, Deserializer};

#[derive(Debug, Deserialize)]
pub struct SecretsPayload {
    #[serde(deserialize_with = "deserialize_base64")]
    pub wrapped_key: Vec<u8>,
    #[serde(deserialize_with = "deserialize_base64")]
    pub blob: Vec<u8>,
    #[serde(deserialize_with = "deserialize_base64")]
    pub iv: Vec<u8>,
    #[serde(deserialize_with = "deserialize_base64")]
    pub tag: Vec<u8>,
}

fn deserialize_base64<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned + From<Vec<u8>>,
{
    let base64_string = String::deserialize(d)?;
    let decoded_bytes = general_purpose::STANDARD
        .decode(&base64_string)
        .map_err(|e| serde::de::Error::custom(format!("Base64 decoding error: {}", e)))?;
    Ok(T::from(decoded_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secrets_payload_deserialize_valid() {
        let json = serde_json::json!({
            "wrapped_key": base64::engine::general_purpose::STANDARD.encode(b"wrapped_key_bytes"),
            "blob": base64::engine::general_purpose::STANDARD.encode(b"encrypted_blob_data"),
            "iv": base64::engine::general_purpose::STANDARD.encode(b"twelve_byte!"),
            "tag": base64::engine::general_purpose::STANDARD.encode(b"sixteen_byte_tag")
        });
        let payload: SecretsPayload = serde_json::from_value(json).unwrap();
        assert_eq!(payload.wrapped_key, b"wrapped_key_bytes");
        assert_eq!(payload.blob, b"encrypted_blob_data");
        assert_eq!(payload.iv, b"twelve_byte!");
        assert_eq!(payload.tag, b"sixteen_byte_tag");
    }

    #[test]
    fn test_secrets_payload_invalid_base64() {
        let json = serde_json::json!({
            "wrapped_key": "not-valid-base64!!!",
            "blob": base64::engine::general_purpose::STANDARD.encode(b"data"),
            "iv": base64::engine::general_purpose::STANDARD.encode(b"iv"),
            "tag": base64::engine::general_purpose::STANDARD.encode(b"tag")
        });
        let result: Result<SecretsPayload, _> = serde_json::from_value(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Base64 decoding error"));
    }

    #[test]
    fn test_secrets_payload_missing_field() {
        let json = serde_json::json!({
            "wrapped_key": base64::engine::general_purpose::STANDARD.encode(b"key"),
            "blob": base64::engine::general_purpose::STANDARD.encode(b"blob")
            // missing iv and tag
        });
        let result: Result<SecretsPayload, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_secrets_payload_empty_base64() {
        let json = serde_json::json!({
            "wrapped_key": base64::engine::general_purpose::STANDARD.encode(b""),
            "blob": base64::engine::general_purpose::STANDARD.encode(b""),
            "iv": base64::engine::general_purpose::STANDARD.encode(b""),
            "tag": base64::engine::general_purpose::STANDARD.encode(b"")
        });
        let payload: SecretsPayload = serde_json::from_value(json).unwrap();
        assert!(payload.wrapped_key.is_empty());
        assert!(payload.blob.is_empty());
        assert!(payload.iv.is_empty());
        assert!(payload.tag.is_empty());
    }
}
