# Certificate Issuance & Renewal (`certify`) — EXPERIMENTAL

> **⚠️ EXPERIMENTAL — NOT FOR PRODUCTION USE**
>
> The `certify` feature and its certificate issuance/renewal lifecycle are
> experimental and under active development. The command-line flags, on-disk
> file layout, configuration keys, and TAS API payloads described here are
> **subject to change without notice**. This feature has not been hardened or
> audited for production deployments. Do not rely on it for production
> workloads or to protect production secrets.

## Overview

The `certify` feature enables the TAS Agent to obtain an X.509 certificate from
the TEE Attestation Service (TAS) by submitting a CSR together with bound TEE
evidence, and to later renew that certificate while reusing the original private
key.

Two lifecycle operations are supported:

- **Initial certification** (`--certify`): generates a fresh RSA-4096 key,
  builds a CSR, gathers TEE evidence, and requests a new certificate.
- **Renewal** (`--renew`): reuses the previously generated private key and the
  previously issued certificate to request a refreshed certificate.

The agent sets the CSR subject Common Name (CN) from the host's identity: it
uses the host's fully-qualified domain name (FQDN) when one is available, and
otherwise falls back to the short hostname. A short random suffix is appended to
the CN.

The certificate identity (SPIFFE ID / UUID) is minted server-side by TAS. The
agent's CSR only contributes the public key and this CN; the agent never asserts
its own identity.

## Building

The feature is gated behind the `certify` Cargo feature and is **off by
default**. Build the agent with the feature enabled:

```bash
# Debug build
cargo build --features certify

# Release build
cargo build --release --features certify
```

The resulting binary is at `target/debug/tas_agent` (or
`target/release/tas_agent`).

> Note: RSA-4096 key generation is slow in debug builds. Use a release build
> for faster key generation.

## Source layout

All certify/renew code lives under the feature-gated `src/certify/` module and
is compiled only with `--features certify`. The rest of the codebase contains no
certify-specific logic, so the feature can be developed in isolation:

- `src/certify/mod.rs` — flow orchestration (`certify_flow`), CLI/config
  dispatch (`run_if_requested`), the experimental runtime warning, and the
  `CertifyArgs` / `CertifyConfig` structs that define the certify CLI flags and
  config keys.
- `src/certify/api.rs` — certify/renew TAS REST calls (`tas_certify`,
  `tas_get_alpha_nonce`) and their request/response payload types.
- `src/certify/keygen.rs` — RSA-4096 key generation.
- `src/certify/csr.rs` — CSR construction and Common Name derivation.
- `src/certify/material_writer.rs` — atomic on-disk material writes.
- `src/certify/renewal_input.rs` — loading existing key/cert for renewal.

The certify CLI flags and config keys are defined as `CertifyArgs` /
`CertifyConfig` inside the module and flattened (`#[command(flatten)]` /
`#[serde(flatten)]`) into the top-level `Cli` / `Config` in `src/main.rs`. The
flag names (`--certify`, `--renew`, `--write-dir`, `--force`) and TOML keys stay
identical; only their definitions moved into the module.

The core `src/tas_api.rs` holds only the non-experimental endpoints. The certify
API in `src/certify/api.rs` reuses its `pub(crate)` `create_client` helper, so
core API code is never touched by certify development.

## Runtime warning

Because the lifecycle is experimental, every certify/renew run logs the
following warning before contacting the TAS server:

```text
EXPERIMENTAL: certify/renew lifecycle is not production-ready
```

## Command-line flags

The following flags are only available when compiled with `--features certify`:

| Flag | Argument | Description |
| --- | --- | --- |
| `--certify` | _(none)_ | Initial certification mode. Generates a new key and requests a certificate. |
| `--renew` | _(none)_ | Renewal mode. Reuses the existing key and certificate from `--write-dir`. |
| `--write-dir <DIR>` | directory | **Required** for `--certify` and `--renew`. Directory where key/certificate materials are written and read. |
| `--force` | _(none)_ | Allow overwriting an existing `key.pem` during initial certification. |

These shared flags also apply:

| Flag | Argument | Description |
| --- | --- | --- |
| `-d`, `--debug` | _(none)_ | Enable debug logging. Also writes the issued certificate bundle to stdout. |
| `-c`, `--config <FILE>` | file | Path to the config file (default: `/etc/tas_agent/config.toml`). |
| `--server-uri <URI>` | URI | TAS REST service URI. Must start with `http://` or `https://`. **Required.** |
| `--api-key <FILE>` | file | Path to the API key file (default: `/etc/tas_agent/api-key`). |
| `--policy-id <ID>` | ID | Policy domain to request. **Required** for the certify flow. |
| `--cert-path <FILE>` | file | CA root certificate that signs the TAS service certificate (default: `/etc/tas_agent/root_cert.pem`). |
| `--max-retries <N>` | integer | Maximum HTTP retry attempts (default: 3). |
| `--retry-min-backoff-secs <SECS>` | integer | Minimum retry backoff in seconds (default: 1). |
| `--retry-max-backoff-secs <SECS>` | integer | Maximum retry backoff in seconds (default: 30). |

## Configuration file

The lifecycle flags may also be set in the TOML config file instead of (or in
addition to) the command line. CLI flags take precedence over config values.

```toml
# Enable certificate certification mode
certify = true

# Enable renewal mode (mutually exclusive intent with certify; renew takes priority)
# renew = true

# Directory for certificate materials (equivalent to --write-dir)
write_dir = "/var/lib/tas_agent/certs"

# Allow overwriting an existing key.pem during certification
# force = false
```

The existing `server_uri`, `api_key`, `policy_id`, `cert_path`, and retry
settings are shared with the normal key-fetch flow.

## On-disk file layout

All materials are written to the directory given by `--write-dir`. The agent
creates the directory if it does not exist.

| File | Description | Initial certify | Renewal |
| --- | --- | --- | --- |
| `key.pem` | PKCS#8 private key | Created (once) | Preserved (reused) |
| `cert.pem` | Issued leaf certificate | Written | Replaced |
| `chain.pem` | CA chain | Written | Replaced |
| `ca-bundle.pem` | CA bundle | Written | Replaced |

Certificate materials are written atomically (temp file + rename). During
initial certification, `key.pem` is created with an exclusive (no-overwrite)
flag and the agent refuses to overwrite an existing key unless `--force` is
given.

## Usage

### Initial certification

Generates a new key, requests a certificate, and writes all materials to the
write directory.

```bash
sudo target/debug/tas_agent -d \
  -c ~/config.toml \
  --certify \
  --write-dir /var/lib/tas_agent/certs
```

To overwrite an existing `key.pem` (re-certify from scratch), add `--force`:

```bash
sudo target/debug/tas_agent -d \
  -c ~/config.toml \
  --certify --force \
  --write-dir /var/lib/tas_agent/certs
```

### Renewal

Reuses the existing `key.pem` and `cert.pem` from the write directory, requests
a refreshed certificate, and atomically updates `cert.pem`, `chain.pem`, and
`ca-bundle.pem`. The private key is preserved.

```bash
sudo target/debug/tas_agent -d \
  -c ~/config.toml \
  --renew \
  --write-dir /var/lib/tas_agent/certs
```

## Verification

After initial certification, inspect the issued material:

```bash
ls -l /var/lib/tas_agent/certs/
openssl x509 -in /var/lib/tas_agent/certs/cert.pem -noout -text
```

After renewal, confirm the certificate changed while the key was preserved. The
key modulus should be identical before and after renewal; the certificate
serial number should differ:

```bash
# Key modulus (should be identical before and after renewal)
openssl rsa -in /var/lib/tas_agent/certs/key.pem -noout -modulus | openssl md5

# Certificate serial (should change after renewal)
openssl x509 -in /var/lib/tas_agent/certs/cert.pem -noout -serial
```

## Requirements

- A reachable TAS server exposing the `alphav1` certify and nonce endpoints,
  with support for the renewal payload field.
- A valid API key file.
- A policy domain (policy ID) configured on the TAS server.
- A CA root certificate for validating the TAS service certificate (for HTTPS).
- The host must be able to produce TEE evidence (e.g., running inside a
  supported confidential VM).

## Limitations

- Experimental: flags, file layout, config keys, and API payloads may change.
- The renewal flow requires that `key.pem` and `cert.pem` already exist in the
  write directory from a prior successful certification.
- RSA-4096 key generation is slow in debug builds.
- Not hardened or audited for production use.
