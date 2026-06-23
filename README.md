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

TAS Agent uses the Linux [configfs/tsm](https://www.kernel.org/doc/Documentation/ABI/testing/configfs-tsm) subsystem to collect CPU attestation reports. This kernel interface works the same way for all supported CPU types, so the agent does not need vendor-specific code. It currently supports AMD SEV-SNP and Intel TDX TEE attestation. Optional NVIDIA GPU attestation can be enabled at build time with the `gpu-nvidia` feature (see [With GPU Attestation Support](#with-gpu-attestation-support)).




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

## Quick Start

```bash
cargo build --release
```

The `tas_agent` application is configured via a configuration file (`config.toml`) and/or command-line arguments. Command-line arguments take precedence over the configuration file.

Run the `tas_agent` program with a config file:

```bash
sudo ./target/debug/tas_agent -c config/config.toml
```

Example output:

```
Policy-ID: 771e76e7924348899ef751d0754c9060dd805928d03043f29a065275f4f883c8
Value: "30786465616462656566"
```


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

# Disable NVIDIA GPU attestation (default: false). Only applies to a
# 'gpu-nvidia' build, where GPU attestation is enabled by default.
# no_gpu = false
```

If using TLS, ensure that `server_uri` specifies `https`.

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
| `--no-gpu` | Disable NVIDIA GPU attestation (enabled by default in a `gpu-nvidia` build; requires the `gpu-nvidia` feature) |
| `--askpass` | systemd ask-password watcher mode (requires `askpass` feature) |
| `--passfifo` | initramfs-tools passfifo watcher mode (requires `passfifo` feature) |

## Build Instructions

### Default (CPU-only attestation)

The default build includes CPU TEE attestation (AMD SEV-SNP / Intel TDX) with
public-key binding. This produces the smallest binary, suitable for
resource-constrained environments such as pre-boot attestation from an initrd

```bash
cargo build --release
```

### With Askpass Support (LUKS unlock via dracut/systemd)

Adds a systemd ask-password watcher that polls `/run/systemd/ask-password`
during early boot, fetches the LUKS passphrase from the TAS server, and
replies via the systemd socket. Used with dracut-based initrd on Fedora
and Ubuntu.

```bash
cargo build --release --features askpass
```

### With Passfifo Support (LUKS unlock via initramfs-tools)

Adds an initramfs-tools passfifo watcher that detects the cryptsetup FIFO
and writes the LUKS passphrase directly. Used with initramfs-tools-based
initrd on Ubuntu.

```bash
cargo build --release --features passfifo
```

### With GPU Attestation Support

Adds NVIDIA GPU attestation via the
[NVIDIA Attestation SDK](https://github.com/NVIDIA/attestation-sdk). The agent
collects per-GPU evidence, sends it to the TAS server as `component-evidence`
alongside the CPU TEE report, and binds the GPU evidence into the CPU report
data so the CPU and GPU attestations are cryptographically linked.

GPU attestation is **enabled by default** in a `gpu-nvidia` build and is
**fail-closed**: if evidence cannot be collected the agent exits with an error
instead of falling back to a CPU-only request. Disable it at runtime with the
`--no-gpu` flag or `no_gpu = true` in `config.toml`.

This feature links the NVIDIA Attestation SDK C library, `libnvat`, which must
be available both at build time and at run time.

**1. Install `libnvat`.** Either install NVIDIA's `nvattest` package, or build
it from source (pinned to the tag referenced in `Cargo.toml`) and install it to
`/usr`:

```bash
# Build dependencies (Debian/Ubuntu):
sudo apt-get install -y build-essential cmake pkg-config git perl \
  clang libclang-dev libxml2-dev zlib1g-dev

SDK_TAG=$(grep 'nv-attestation-sdk' Cargo.toml | grep -oP 'tag\s*=\s*"\K[^"]+')
git clone --depth 1 --branch "$SDK_TAG" https://github.com/NVIDIA/attestation-sdk.git
cmake -S attestation-sdk/nv-attestation-sdk-cpp -B /tmp/nvat-build \
  -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON \
  -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_LIBDIR=lib
cmake --build /tmp/nvat-build -j"$(nproc)"
sudo cmake --install /tmp/nvat-build && sudo ldconfig
```

**2. Build the agent** with the `gpu-nvidia` feature, telling the SDK bindings
to link the system `libnvat`:

```bash
NVAT_USE_SYSTEM_LIB=1 cargo build --release --features gpu-nvidia
```

`NVAT_USE_SYSTEM_LIB=1` makes the SDK's `-sys` crate link the system-installed
`libnvat` (`/usr/include/nvat.h`, `-lnvat`) and generate bindings from it;
`clang`/`libclang` is required for that binding generation. Without the
variable, the crate instead expects a local C++ SDK build tree.

> **Runtime requirements:** an NVIDIA GPU with the driver installed (NVML), and
> `libnvat.so` reachable by the loader (e.g. installed under `/usr/lib`). For
> confidential-computing attestation the GPU must be in CC mode. The `.deb`,
> `.rpm`, and tarball build scripts do not yet enable `gpu-nvidia`, so a
> GPU-enabled agent is currently produced with `cargo` directly.

### Package Build

Package installation is the preferred deployment method with `askpass` and `passfifo`. The `.deb` and
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
