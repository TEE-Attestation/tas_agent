# TAS Agent
TAS Agent is a Rust program that runs inside a
Confidential Virtual Machine (CVM). It attests the state of the CVM to a
remote [TAS server](https://github.com/TEE-Attestation/tas) using a
hardware Trusted Execution Environment (TEE) attestation report, and receives encrypted secrets in return.

The TAS Server is configured such that a CVM only receives the secrets, such as a LUKS passphrase to unlock the root volume, if it is successfully verified.

**How it works:**

1. The agent creates a temporary key pair.
2. It collects a hardware TEE attestation report from the CPU (AMD SEV-SNP or Intel TDX).
3. It sends the report and the public key to the TAS server.
4. The server checks the report. If valid, it encrypts the secrets with the public key and sends them back.

TAS Agent uses the Linux [configfs/tsm](https://www.kernel.org/doc/Documentation/ABI/testing/configfs-tsm) subsystem to collect attestation reports. This kernel interface works the same way for all supported CPU types, so the agent does not need vendor-specific code. It currently supports AMD SEV-SNP and Intel TDX TEE attestation. Nvidia GPU attestation is coming soon.




## Use Cases

- **[LUKS volume unlocking](docs/LUKS.md)** — Automatically unlock
  LUKS-encrypted volumes at boot using TEE attestation instead of a
  password. Supports dracut, initramfs-tools, and systemd.
- **Secret retrieval** — Fetch any TAS-managed secret for use by
  applications running inside a CVM.
- **X.509 certificate issuance** *(coming soon)* — Generate a CSR and
  submit it alongside a TEE attestation report to a compatible TAS server.
  After passing verification, the server issues an X.509 certificate that
  can be used for (m)TLS and to fetch secrets.

## Configuration

### Configuration File

Default path: `/etc/tas_agent/config.toml`

```toml
# The URI of the TAS REST service (http:// or https://)
server_uri = "https://tas.example.com:5000"

# Path to the API key for the TAS REST service
api_key = "/etc/tas_agent/api-key"

# Path to the CA root certificate signing the TAS REST service cert
# (only required for https:// URIs)
cert_path = "/etc/tas_agent/root_cert.pem"

# Policy ID to request from the TAS REST service
policy_id = "..."

# Maximum number of retry attempts for HTTP requests (default: 3)
# max_retries = 3

# Minimum backoff time in seconds between retries (default: 1)
# retry_min_backoff_secs = 1

# Maximum backoff time in seconds between retries (default: 30)
# retry_max_backoff_secs = 30
```

### Command-Line Options

| Option | Description |
|---|---|
| `-d`, `--debug` |  Display debugging messages (do not use in production — logs sensitive data) |
| `-c`, `--config <FILE>` | Path to the config file (default: `/etc/tas_agent/config.toml`) |
| `--server-uri <URI>` | The URI of the TAS REST service |
| `--api-key <FILE>` | Path to the API key for the TAS REST service |
| `--policy-id <ID>` | Policy ID to request from the TAS REST service |
| `--cert-path <FILE>` | Path to the CA root certificate signing the TAS REST service cert (HTTPS only) |
| `--max-retries <N>` | Maximum number of retry attempts for HTTP requests (default: 3) |
| `--retry-min-backoff-secs <SECS>` | Minimum backoff time in seconds between retries (default: 1) |
| `--retry-max-backoff-secs <SECS>` | Maximum backoff time in seconds between retries (default: 30) |
| `--no-key-binding` | Disable public-key binding in TEE report data (for legacy TAS servers) |
| `--gpu-attestation <MODE>` | GPU attestation mode: `auto` (default) or `disabled` (requires `gpu-attestation` feature) |
| `--askpass` | systemd ask-password watcher mode (requires `askpass` feature) |
| `--passfifo` | initramfs-tools passfifo watcher mode (requires `passfifo` feature) |

## Build Instructions

### Default (CPU-only attestation)

```bash
cargo build --release
```

### With Askpass Support (LUKS unlock via dracut/systemd)

```bash
cargo build --release --features askpass
```
Policy-ID: 771e76e7924348899ef751d0754c9060dd805928d03043f29a065275f4f883c8
Value: "30786465616462656566"

### With Passfifo Support (LUKS unlock via initramfs-tools)

```bash
cargo build --release --features passfifo
```

### With GPU Attestation Support

```bash
cargo build --release --features gpu-attestation
```

> **Note:** GPU attestation is currently a stub. The `GpuEvidenceProvider`
> trait is in place, but no concrete GPU provider is functional yet.

### Package Build

Package installation is the preferred deployment method. The `.deb` and
`.rpm` packages include the expected initramfs and systemd integration
artifacts and run the usual package-manager lifecycle hooks.

#### Prerequisites

```bash
# Debian/Ubuntu — install build dependencies (for .deb packages)
sudo apt-get install -y dpkg-dev debhelper fakeroot cargo rustc pkg-config libssl-dev

# Debian/Ubuntu — install additional dependencies for .rpm builds
sudo apt-get install -y rpm elfutils

# Fedora/RHEL — install build dependencies
sudo dnf install -y rpm-build cargo rust pkg-config openssl-devel
```

#### Build Packages

```bash
# Debian/Ubuntu (.deb)
./build.sh --deb

# Fedora/RHEL (.rpm)
./build.sh --rpm
```

### Tarball Build

Running `./build.sh --tarball` produces a tarball at
`target/package/tas_agent.tar.gz`.

The `-d`, `-r`, `-e`, and `-a` options apply to the tarball build. Use them
to change the tarball output directory or the config files bundled into the
tarball build.

Use the tarball only for manual installation, local testing, or debugging.
It is not the preferred installation path; package installs are preferred
because they better match the supported deployment flow.

## Testing

### Unit Tests

```bash
cargo test --features askpass,passfifo
```

### Integration Tests

Integration tests live in a separate repository: [TEE-Attestation/tas_agent_tests](https://github.com/TEE-Attestation/tas_agent_tests).

Clone it under the project root:

```bash
cd tas_agent
git clone git@github.com:TEE-Attestation/tas_agent_tests.git testing
```

Then follow the instructions in `testing/README.md`:

```bash
# Chroot-based VM tests (SEV-SNP / TDX)
cd testing && python3 run_tests.py --initrd ubuntu-dracut --test all

# Interactive VM launcher (for debugging, manual passphrase entry)
cd testing && python3 launch_tdx.py --console --image tas-agent-test-ubuntu-dracut.qcow2
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
