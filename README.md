[![crates.io](https://img.shields.io/crates/v/allium.svg)](https://crates.io/crates/allium)
[![docs](https://docs.rs/allium/badge.svg)](https://docs.rs/allium)

![logo](logo.svg)

Allium 🧅
=========

> Allium is a genus of monocotyledonous flowering plants that includes hundreds of species, including the cultivated onion, garlic, scallion, shallot, leek, and chives.
> — [Wikipedia](https://en.wikipedia.org/wiki/Allium)

Allium is a implementation of [onion routing](https://en.wikipedia.org/wiki/Onion_routing) written in Rust.
It enables anonymous communication over encrypted tunnels.
In addition to being used as a Rust library, Allium can also be run as a stand-alone daemon, which can be controlled over a TCP socket.

## Features

- Asynchronous design based on the Tokio runtime
- Periodic, seamless tunnel reconstruction
- Fixed-size packets
- Cover traffic

## Getting started

The [documentation](https://docs.rs/allium/#getting-started) contains a short section on how to get started with the Allium library.

## Daemon

The daemon can be installed with:

```
$ cargo install --bin allium-daemon allium
```

After installation, the daemon can be run like this:

```
$ allium-daemon [config file path]
```

The Allium daemon requires a configuration file, which defaults to `config.ini` in the current working directory.
A different path can be specified via an optional command line parameter.
The configuration file must be in `*.ini` or `*.toml` format.
Example `ini`-configuration:
```ini
[onion]
; The address and port on which the daemon listening for API connections
api_address = 127.0.0.1:4200
; The port on which connections from other peers in the onion network are accepted
p2p_port = 4201
; The address on which connections from other peers in the onion network are accepted
p2p_hostname = 127.0.0.1
; The path to a PEM-encoded RSA keypair used for signing messages
hostkey = testkey.pem
; The number of hops (excluding the destination) in each tunnel (should be at least 2)
hops = 2
; Enable or disable cover traffic
cover_traffic = true
; Duration of each round in seconds.
round_duration = 120 

[rps]
; The address and port the random-peer-sampling module is listening on
api_address = 127.0.0.1:4100
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

## Known Issues
* During switchover we kill the old tunnel without draining any possibly leftover Data messages. This may cause packet loss.
* Circuit IDs (and to some degree tunnel IDs) are generated randomly. Although unlikely, there might be duplicates.
* We don't sanitize the output from the RPS, so tunnels with loops or random cover tunnels with ourselves as destination might be possible, depending on the implementation of the RPS.

## Future Work
* Write benchmarks and tune the performance
    * Reduce the number of allocations and copy operations
* Tunnels are generally torn down forcefully instead of being deconstructed iteratively, despite the necessary functionality being partially implemented