use crate::Result;
use anyhow::anyhow;
use ini::Ini;
use serde::Deserialize;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
pub struct Config {
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
    /// Path to file containing PEM-encoded RSA hostkey in DER format.
    ///
    /// Generated with:
    /// ```text
    /// openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out testkey.pkcs8.pem
    /// openssl rsa -in testkey.pkcs8.pem -out testkey.pem
    /// ```
    pub hostkey: PathBuf,
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
    pub fn from_toml(string: &str) -> Result<Self> {
        Ok(toml::from_str(string)?)
    }

    pub fn from_ini(string: &str) -> Result<Self> {
        let ini = Ini::load_from_str(string)?;

        let onion = ini
            .section(Some("onion"))
            .and_then(|sec| {
                Some(OnionConfig {
                    api_address: sec.get("api_address")?.parse().ok()?,
                    p2p_port: sec.get("p2p_port")?.parse().ok()?,
                    p2p_hostname: sec.get("p2p_hostname")?.parse().ok()?,
                    hostkey: sec.get("hostkey")?.into(),
                })
            })
            .ok_or(anyhow!("Could not parse onion config"))?;

        let rps = ini
            .section(Some("rps"))
            .and_then(|sec| {
                Some(RpsConfig {
                    api_address: Some(sec.get("api_address")?.parse().ok()?),
                    peers: None,
                })
            })
            .ok_or(anyhow!("Could not parse rps config"))?;

        Ok(Config { onion, rps })
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut buf = String::new();
        File::open(&path)?.read_to_string(&mut buf)?;
        match path.as_ref().extension() {
            Some(ext) if ext == "toml" => Self::from_toml(&buf),
            Some(ext) if ext == "ini" => Self::from_ini(&buf),
            _ => Err(anyhow!("Unsupported config format")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn test_read_config() {
        let config = Config::from_file("config.ini").unwrap();
        println!("{:#?}", config);
    }
}
