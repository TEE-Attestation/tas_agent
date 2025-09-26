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
