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

The `tas_agent` application takes its initial configuration via environment variables that can be set in a `.env` file.
The required environment variables can also be exported in a script that calls the `tas_kbm_ctl` application without requiring a `.env` file.

The mandatory environment variables are as follows:

- `TAS_SERVER_URI=http://<IP address of TAS>:<Port number of TAS>`
- `TAS_SERVER_ROOT_CERT=<TAS Server Root Certificate>`
- `TAS_KEY_ID=<KMIP ID of secret required>`

The API key default path is `/etc/tas_agent/api-key`, but this can
be overridden with:

- `TAS_SERVER_API_KEY=<Path to file containing API key for TAS>`

If using TLS, ensure that TAS_SERVER_URI has specified 'https'.
Set the 'TAS_SERVER_ROOT_CERT' environment variable to the path location of the Root Certificate.

Run the `tas_agent` program:

```bash
sudo ./target/debug/tas_agent
```

Example output:

```
Key-ID: 771e76e7924348899ef751d0754c9060dd805928d03043f29a065275f4f883c8
Value: "30786465616462656566"
```
## Contributing
Contributing to the project is simple! Just send a pull request through GitHub. For detailed instructions on formatting your changes and following our contribution guidelines, take a look at the [CONTRIBUTING](./CONTRIBUTING.md) file.
