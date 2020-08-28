use crate::Result;
use anyhow::anyhow;
use ini::ini::Properties;
use ini::Ini;
use serde::Deserialize;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;

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
    /// The number of hops in each tunnel (excluding the final peer).
    pub hops: usize,
    /// Enable cover traffic
    pub cover_traffic: Option<bool>,
    /// Duration of each round in seconds.
    /// After each round connections will seamlessly switchover to a new tunnel.
    pub round_duration: Option<u64>,
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
        fn required<F: FromStr>(sec: &Properties, key: &str) -> Result<F> {
            sec.get(key)
                .ok_or(anyhow!("Missing required property {}", key))?
                .parse()
                .map_err(|_| anyhow!("Could not parse property {}", key))
        }

        fn optional<F: FromStr>(sec: &Properties, key: &str) -> Result<Option<F>> {
            match sec.get(key) {
                Some(s) => match s.parse() {
                    Ok(v) => Ok(Some(v)),
                    Err(_) => Err(anyhow!("Could not parse property {}", key)),
                },
                None => Ok(None),
            }
        }

        let ini = Ini::load_from_str(string)?;
        let onion = ini
            .section(Some("onion"))
            .ok_or(anyhow!("Missing onion section"))
            .and_then(|sec| {
                Ok(OnionConfig {
                    api_address: required(sec, "api_address")?,
                    p2p_port: required(sec, "p2p_port")?,
                    p2p_hostname: required(sec, "p2p_hostname")?,
                    hostkey: required(sec, "hostkey")?,
                    hops: required(sec, "hops")?,
                    cover_traffic: optional(sec, "cover_traffic")?,
                    round_duration: optional(sec, "round_duration")?,
                })
            })?;
        let rps = ini
            .section(Some("rps"))
            .ok_or(anyhow!("Missing rps section"))
            .and_then(|sec| {
                Ok(RpsConfig {
                    api_address: optional(sec, "api_address")?,
                    peers: None,
                })
            })?;
        Ok(Config { onion, rps })
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut buf = String::new();
        File::open(&path)?.read_to_string(&mut buf)?;
        match path.as_ref().extension() {
            Some(ext) if ext == "toml" => Self::from_toml(&buf),
            _ => Self::from_ini(&buf),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn test_read_config() {
        let _ = Config::from_file("config.ini").unwrap();
        let _ = Config::from_file("config.toml").unwrap();
    }
}
