# TAS Agent

## Build Instructions

To build the application, run the following command:

```bash
cargo build
```

To build a package for installation (e.g. in /opt/tas), run the following command:

```bash
./build.sh
```

The tas_agent package will be created in the ./target/package directory.
Copy the .tgz file generated to the target VM's /opt/tas directory.

## Unit Tests

Unit tests are run via the `cargo test` command.

## Execution Instructions

The `tas_agent` application is configured via a configuration file (`config.toml`) and/or command-line arguments. Command-line arguments take precedence over the configuration file.

### Configuration File

The default configuration file path is `/etc/tas_agent/config.toml`. An example configuration file is provided in `config/config.toml.sample`:

```toml
# The URI of the TAS REST service
server_uri = "http://X.X.X.X:5000"

# Path to the API key for the TAS REST service
api_key = "/etc/tas_agent/api-key"

# Path to the CA root certificate signing the TAS REST service cert
cert_path = "/etc/tas_agent/root_cert.pem"

# ID of the key to request from the TAS REST service
key_id = "..."

# Maximum number of retry attempts for HTTP requests (default: 3)
# max_retries = 3

# Minimum backoff time in seconds between retries (default: 1)
# retry_min_backoff_secs = 1

# Maximum backoff time in seconds between retries (default: 30)
# retry_max_backoff_secs = 30
```

If using TLS, ensure that `server_uri` specifies `https`.

### Command-Line Options

| Option | Description |
|---|---|
| `-d`, `--debug` | Display debugging messages |
| `-c`, `--config <FILE>` | Path to the config file (default: `/etc/tas_agent/config.toml`) |
| `--server-uri <URI>` | The URI of the TAS REST service |
| `--api-key <FILE>` | Path to the API key for the TAS REST service |
| `--key-id <ID>` | ID of the key to request from the TAS REST service |
| `--cert-path <FILE>` | Path to the CA root certificate signing the TAS REST service cert |
| `--max-retries <N>` | Maximum number of retry attempts for HTTP requests (default: 3) |
| `--retry-min-backoff-secs <SECS>` | Minimum backoff time in seconds between retries (default: 1) |
| `--retry-max-backoff-secs <SECS>` | Maximum backoff time in seconds between retries (default: 30) |

### Running

Run the `tas_agent` program with a config file:

```bash
sudo ./target/debug/tas_agent -c config/config.toml
```

Example output:

```
Key-ID: 771e76e7924348899ef751d0754c9060dd805928d03043f29a065275f4f883c8
Value: "30786465616462656566"
```
## HTTP Retry Strategy

The TAS agent automatically retries HTTP requests that fail with transient errors using
**exponential backoff with full jitter**.

### Retryable Status Codes

The following HTTP status codes are considered transient and will be retried:

| Status Code | Meaning |
|---|---|
| 408 | Request Timeout |
| 429 | Too Many Requests |
| 500 | Internal Server Error |
| 502 | Bad Gateway |
| 503 | Service Unavailable |
| 504 | Gateway Timeout |

Non-transient errors (e.g. 400 Bad Request, 401 Unauthorized, 404 Not Found) are **not** retried.

### Backoff Strategy

The retry delay between attempts follows an **exponential backoff** pattern with **full jitter**:

- The base delay doubles with each retry attempt (1s, 2s, 4s, 8s, ...)
- **Full jitter** randomizes the actual delay between 0 and the calculated backoff value,
  reducing the chance of multiple clients retrying at the same instant
- The delay is clamped between `retry_min_backoff_secs` and `retry_max_backoff_secs`

### Configuration

Retry behavior is configurable via `config.toml` or command-line arguments.
Command-line arguments take precedence over the configuration file.

| Parameter | Config Key | CLI Flag | Default | Description |
|---|---|---|---|---|
| Max retries | `max_retries` | `--max-retries` | 3 | Number of retry attempts after the initial request fails |
| Min backoff | `retry_min_backoff_secs` | `--retry-min-backoff-secs` | 1 second | Lower bound for the retry delay |
| Max backoff | `retry_max_backoff_secs` | `--retry-max-backoff-secs` | 30 seconds | Upper bound for the retry delay |

With the defaults (3 retries, 1–30s backoff), worst-case total additional delay is approximately
1s + 2s + 4s = 7s before jitter. The full jitter randomization means actual delays will typically
be shorter.

To disable retries entirely, set `max_retries = 0`.

### Example

```toml
# Retry up to 5 times with backoff between 2s and 60s
max_retries = 5
retry_min_backoff_secs = 2
retry_max_backoff_secs = 60
```

## Contributing
Contributing to the project is simple! Just send a pull request through GitHub. For detailed instructions on formatting your changes and following our contribution guidelines, take a look at the [CONTRIBUTING](./CONTRIBUTING.md) file.
