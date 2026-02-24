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
## Contributing
Contributing to the project is simple! Just send a pull request through GitHub. For detailed instructions on formatting your changes and following our contribution guidelines, take a look at the [CONTRIBUTING](./CONTRIBUTING.md) file.
