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

- **Initial certification** (`certify`): generates a fresh RSA-4096 key,
  builds a CSR, gathers TEE evidence, and requests a new certificate.
- **Renewal** (`certify --renew`): reuses the previously generated private key
  and the previously issued certificate to request a refreshed certificate.

By default the agent sets the CSR subject Common Name (CN) from the configured
system hostname. A hostname containing a dot is treated as a fully-qualified
domain name (FQDN); otherwise the agent uses the short hostname. A short random
suffix is appended in either case. The CN can be overridden with `--common-name`
(alias `--cn`) or the `common_name` config key. Optional Subject Alternative
Names may be requested with repeatable `--san TYPE:VALUE` flags or the `sans`
config key; both apply identically to initial certification and renewal.

The certificate identity (SPIFFE ID / UUID) is minted server-side by TAS. The
agent's CSR only contributes the public key, CN, and any requested SANs; the
agent never asserts its own identity, and TAS remains authoritative over what it
signs.

The request carries two policy inputs. The **domain policy** (`--domain-policy`
or the `domain_policy` config key) is **required** and is sent as the
`domain-policy` field. An optional **policy id** (`--policy-id` or
the `policy_id` config key) is sent as the `policy-id` field — the same field
the standard key-fetch request uses — and is omitted when not provided. Both are
global flags, so they may appear before or after the `certify` token.

## Building

The feature is gated behind the `certify` Cargo feature and is **off by
default**. Build the agent with the feature enabled:

```bash
# Debug build
cargo build --features certify

# Release build
cargo build --release --features certify

# Release build with NVIDIA GPU attestation
NVAT_USE_SYSTEM_LIB=1 cargo build --release --features certify,gpu-nvidia
```

The resulting binary is at `target/debug/tas_agent` (or
`target/release/tas_agent`).

> Note: RSA-4096 key generation is slow in debug builds. Use a release build
> for faster key generation.

## Source layout

All certify/renew code lives under the feature-gated `src/certify/` module and
is compiled only with `--features certify`. The rest of the codebase contains no
certify-specific logic, so the feature can be developed in isolation:

- `src/certify/mod.rs` — flow orchestration (`certify_flow`), the `certify`
  subcommand entry point (`run`), the experimental runtime warning, and the
  `CertifyArgs` / `CertifyConfig` structs that define the certify CLI flags and
  config keys.
- `src/certify/api.rs` — certify/renew TAS REST calls (`tas_certify`,
  `tas_get_alpha_nonce`) and their request/response payload types.
- `src/certify/gpu.rs` — certify-specific adaptation of NVIDIA evidence to the
  `gpu-evidence` API payload.
- `src/certify/keygen.rs` — RSA-4096 key generation.
- `src/certify/csr.rs` — CSR construction, Common Name derivation, and SAN/CN
  parsing and validation (`parse_san`, `parse_common_name`).
- `src/certify/material_writer.rs` — atomic on-disk material writes.
- `src/certify/renewal_input.rs` — loading existing key/cert for renewal.

The certify flow is exposed as the `certify` subcommand: `CertifyArgs` is the
subcommand body (`Commands::Certify` in `src/main.rs`) and `CertifyConfig` is
flattened (`#[serde(flatten)]`) into the top-level `Config` to supply defaults.
Shared connection flags (`--server-uri`, `--policy-id`, ...) are global, so they
may appear before or after the `certify` token.

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

The certify flow is invoked as a subcommand: `tas_agent certify [OPTIONS]`. The
following flags are available on the `certify` subcommand (only when compiled
with `--features certify`):

| Flag | Argument | Description |
| --- | --- | --- |
| `--renew` | _(none)_ | Renewal mode. Reuses the existing key and certificate from `--write-dir`. Without it, `certify` performs initial certification. |
| `--write-dir <DIR>` | directory | **Required.** Directory where key/certificate materials are written and read. |
| `--force` | _(none)_ | Allow overwriting an existing `key.pem` during initial certification. |
| `--common-name <CN>`, `--cn` | string | Override the CSR subject Common Name (default: auto-generated). Max 64 chars; RFC 4514 DN metacharacters and control characters are rejected. |
| `--san <TYPE:VALUE>` | repeatable | Request a Subject Alternative Name. `TYPE` is one of `DNS`, `IP`, `URI`, `email` (case-insensitive). Overrides the `sans` config key when given. |

These shared flags also apply:

| Flag | Argument | Description |
| --- | --- | --- |
| `-d`, `--debug` | _(none)_ | Enable debug logging. Also writes the issued certificate bundle to stdout. |
| `-c`, `--config <FILE>` | file | Path to the config file (default: `/etc/tas_agent/config.toml`). |
| `--server-uri <URI>` | URI | TAS REST service URI. Must start with `http://` or `https://`. **Required.** |
| `--api-key <FILE>` | file | Path to the API key file (default: `/etc/tas_agent/api-key`). |
| `--domain-policy <DOMAIN>` | domain | Domain policy to request, sent as `domain-policy`. **Required** for the certify flow. Global — may appear before or after the `certify` token. |
| `--policy-id <ID>` | ID | Optional policy id, sent as `policy-id` (the same field the standard key-fetch request uses). Omitted when unset. |
| `--cert-path <FILE>` | file | CA root certificate that signs the TAS service certificate (default: `/etc/tas_agent/root_cert.pem`). |
| `--max-retries <N>` | integer | Maximum HTTP retry attempts (default: 3). |
| `--retry-min-backoff-secs <SECS>` | integer | Minimum retry backoff in seconds (default: 1). |
| `--retry-max-backoff-secs <SECS>` | integer | Maximum retry backoff in seconds (default: 30). |
| `--no-gpu` | _(none)_ | Disable GPU attestation in a `certify,gpu-nvidia` build. |

## Configuration file

Config keys supply defaults for the `certify` subcommand; CLI flags take
precedence over config values. The mode is always chosen with the `certify`
subcommand and its command-line options.

```toml
# Domain policy to request (required; equivalent to --domain-policy)
domain_policy = "..."

# Directory for certificate materials (equivalent to --write-dir)
write_dir = "/var/lib/tas_agent/certs"

# Allow overwriting an existing key.pem during initial certification
# force = false

# Override the CSR subject Common Name (default: auto-generated)
# common_name = "tee.host.example.com"

# Subject Alternative Names to request (OpenSSL TYPE:VALUE form). A --san flag on
# the command line overrides this list. Applied for both fresh and renew.
# sans = ["DNS:host.example.com", "IP:10.0.0.1", "URI:spiffe://td/workload"]
```

The existing `server_uri`, `api_key`, `cert_path`, and retry settings are shared
with the normal key-fetch flow. `policy_id` is shared too, but for the certify
flow it is **optional** and is sent as the `policy-id` field; the required domain
is supplied separately via `domain_policy` / `--domain-policy`.

## GPU attestation

When built with both `certify` and `gpu-nvidia`, GPU attestation is enabled by
default for initial certification and renewal. The agent collects up to 16
NVIDIA GPU evidence entries and submits them as the certify API's bare
`gpu-evidence` array. It binds their ordered SHA-512 hashes into the CPU TEE
report data together with the nonce and certificate public key.

GPU collection is fail-closed: collection, payload validation, or attestation
failure stops the certify operation before certificate material is written.
Use `--no-gpu` or `no_gpu = true` in `config.toml` for CPU-only certification.
This opt-out does not override TAS policy; a policy requiring GPU components
rejects a CPU-only request.

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

The domain policy is required: pass `--domain-policy <DOMAIN>` (global, so it may
appear before or after `certify`) or set `domain_policy` in `config.toml`. The
remaining examples assume it is set in the config file.

```bash
sudo target/debug/tas_agent -d \
  -c ~/config.toml \
  certify \
  --domain-policy my-domain \
  --write-dir /var/lib/tas_agent/certs
```

To overwrite an existing `key.pem` (re-certify from scratch), add `--force`:

```bash
sudo target/debug/tas_agent -d \
  -c ~/config.toml \
  certify --force \
  --write-dir /var/lib/tas_agent/certs
```

To set a custom Common Name and request Subject Alternative Names:

```bash
sudo target/debug/tas_agent -d \
  -c ~/config.toml \
  certify \
  --write-dir /var/lib/tas_agent/certs \
  --common-name tee.web.example.com \
  --san DNS:web.example.com --san IP:10.0.0.1 --san URI:spiffe://td/workload
```

### Renewal

Reuses the existing `key.pem` and `cert.pem` from the write directory, requests
a refreshed certificate, and atomically updates `cert.pem`, `chain.pem`, and
`ca-bundle.pem`. The private key is preserved.

```bash
sudo target/debug/tas_agent -d \
  -c ~/config.toml \
  certify --renew \
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
- GPU-enabled certification additionally requires `libnvat`, a supported
  NVIDIA GPU, and a TAS policy compatible with the submitted GPU evidence.

## Limitations

- Experimental: flags, file layout, config keys, and API payloads may change.
- The renewal flow requires that `key.pem` and `cert.pem` already exist in the
  write directory from a prior successful certification.
- RSA-4096 key generation is slow in debug builds.
- Not hardened or audited for production use.
