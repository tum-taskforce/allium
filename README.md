[![crates.io](https://img.shields.io/crates/v/allium.svg)](https://crates.io/crates/allium)
[![docs](https://docs.rs/allium/badge.svg)](https://docs.rs/allium)

Allium
======

> Allium is a genus of monocotyledonous flowering plants that includes hundreds of species, including the cultivated onion, garlic, scallion, shallot, leek, and chives.
> — [Wikipedia](https://en.wikipedia.org/wiki/Allium)

Allium is a onion routing library written in Rust.
It allows the communication over tunnels constructed with layered encryption across peers chosen from a provided pool.
Apart from being used as a Rust library, Allium can also be run as a stand-alone daemon controlled over a unix socket. 

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
$ target/release/allium-daemon [ARGS]
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
; Duration of each round in seconds.
round_duration = 120 

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

## CLI Example
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

## Installing
Install the binary to `~/.cargo/bin/` by running the following command inside the cloned directory.
```
cargo install --path .
```

## Known Issues
* During switchover we kill the old tunnel without draining any possibly leftover Data messages. This may cause packet loss.
* Circuit IDs (and to some degree tunnel IDs) are generated randomly. Although unlikely, there might be duplicates.
* We don't sanitize the output from the RPS, so tunnels with loops or random cover tunnels with ourselves as destination might be possible, depending on the implementation of the RPS.

## Future Work
* Write benchmarks and tune the performance
    * Reduce the number of allocations and copy operations
* Tunnels are generally torn down forcefully instead of being deconstructed iteratively, despite the necessary functionality being partially implemented