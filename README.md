Voidphone Onion Module
======================

## Building and Running
Rust and Cargo (version 1.45.0 or newer) are required for building.
If not installed already, install both with [rustup](https://rustup.rs/).

After cloning the repository, build and run the project with:
```
$ cargo run --release -- [ARGS]
```
Alternatively the steps of building and running can be done separately with:
```
$ cargo build --release
$ target/release/voidphone-onion [ARGS]
```

Substitute `[ARGS]` with the following command line parameters:
* `[config file path]`: (optional) Specify the path to the configuration file. Defaults to `config.ini`.

## Configuration

The configuration file must be in `*.ini` or `*.toml` format.
Example `ini`-configuration:
```ini
[onion]
; The address and port on which the onion module is listening for API connections
api_address = 127.0.0.1:4200
; The port on which connections from other onion peers are accepted
p2p_port = 4201
; The address on which connections from other onion peers are accepted
p2p_hostname = 127.0.0.1
; The path to a PEM-encoded RSA keypair used for proving this module's identity to peers
hostkey = testkey.pem
; The number of hops (excluding the destination) in each tunnel (should be at least 2)
hops = 2
; Enable or disable cover traffic
cover_traffic = true 

[rps]
; The address and port the RPS module is listening on
api_address = 127.0.0.1:4100
```

## Hostkey
A suitable RSA keypair can be generated with OpenSSL:
```
$ openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out testkey.pkcs8.pem
$ openssl rsa -in testkey.pkcs8.pem -out testkey.pem
```

The public key supplied in a `BUILD` message must be in the DER-encoded `SubjectPublicKeyInfo` format which can be obtained like this:
```
$ openssl rsa -in testkey.pem -outform DER -pubout -out testkey_pub.der
```

## CLI example
For testing purposes, a command-line interface is provided which can be run like this:
```
$ cargo run --example cli
```
Additionally, the logging level can be specified like this:
```
$ RUST_LOG=trace cargo run --example cli
```

## Tests
Tests can be run with
```
cargo test
```