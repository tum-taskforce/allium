use crate::Result;
use serde::Deserialize;
use std::fs::File;
use std::io::{BufReader, Read};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
pub struct Config {
    /// Path to file containing PEM-encoded RSA hostkey in PKCS#8 format.
    ///
    /// Generated with:
    /// ```text
    /// openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out testkey.pem
    /// ```
    pub hostkey: PathBuf,
    pub onion: OnionConfig,
    pub rps: RpsConfig,
}

#[derive(Debug, Deserialize)]
pub struct OnionConfig {
    pub api_address: SocketAddr,
    /// This is the port for Onion’s P2P protocol i.e., the port number on which Onion accepts
    /// tunnel connections from Onion modules of other peers. This is different from the port where
    /// it listens for API connections. This value is used by the RPS module to advertise the socket
    /// the onion module is listening on, so that other peers onion modules can connect to it.
    pub p2p_port: u16,
    /// Similar to p2p port this parameter determines the interface on which Onion listens for
    /// incoming P2P connections.
    pub p2p_hostname: IpAddr,
}

#[derive(Debug, Deserialize)]
pub struct RpsConfig {
    pub api_address: Option<SocketAddr>,
    pub peers: Option<Vec<PeerConfig>>,
}

#[derive(Debug, Deserialize)]
pub struct PeerConfig {
    pub p2p_address: SocketAddr,
    pub hostkey: PathBuf,
}

impl Config {
    pub fn from_str(string: &str) -> Result<Self> {
        Ok(toml::from_str(string)?)
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut buf = String::new();
        File::open(path)?.read_to_string(&mut buf)?;
        Self::from_str(&buf)
    }
}
