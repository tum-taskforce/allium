use anyhow::{anyhow, Context};
use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use async_std::sync::{Arc, Mutex};
use async_std::task;
use futures::io::{ReadHalf, WriteHalf};
use futures::AsyncReadExt;
use serde::Deserialize;

#[allow(dead_code)]
mod api_protocol;

use api_protocol::*;
use onion::messages::*;
use onion::*;

#[derive(Debug, Deserialize)]
struct Config {
    hostkey: String,
    onion: OnionConfig,
    rps: RpsConfig,
}

#[derive(Debug, Deserialize)]
struct OnionConfig {
    api_address: String,
    p2p_port: u16,
    p2p_hostname: String,
}

#[derive(Debug, Deserialize)]
struct RpsConfig {
    api_address: String,
}

struct RpsModule {
    reader: MessageReader<ReadHalf<TcpStream>>,
    writer: MessageWriter<WriteHalf<TcpStream>>,
}

impl RpsModule {
    async fn connect(api_address: &str) -> Result<Self> {
        let stream = TcpStream::connect(api_address).await?;
        let (reader, writer) = stream.split();
        let reader = MessageReader::new(reader);
        let writer = MessageWriter::new(writer);
        Ok(RpsModule { reader, writer })
    }

    async fn query(&mut self) -> Result<Peer> {
        self.writer.write(RpsRequest::Query).await?;
        if let Some(msg) = self.reader.read_next().await? {
            match msg {
                RpsResponse::Peer(port, portmap, peer_addr, peer_hostkey) => {
                    let (_, peer_port) = portmap
                        .iter()
                        .find(|(m, _)| *m == Module::Onion)
                        .ok_or(anyhow!("Peer does not expose onion port"))?;
                    Ok(Peer::new(peer_addr, *peer_port, peer_hostkey))
                }
            }
        } else {
            Err(anyhow!("rps query failed"))
        }
    }
}

struct OnionModule {
    onion: Onion,
    config: Config,
    rps: Mutex<RpsModule>,
}

impl OnionModule {
    async fn init(config: Config) -> Result<Self> {
        let onion = Onion::new(config.onion.p2p_hostname.clone(), config.onion.p2p_port);
        let rps = RpsModule::connect(&config.rps.api_address)
            .await
            .context("Failed to connect to RPS module")?;
        let rps = Mutex::new(rps);
        Ok(OnionModule { onion, config, rps })
    }

    async fn listen_api(self: Arc<Self>) -> Result<()> {
        let api_address = &self.config.onion.api_address;
        let listener = TcpListener::bind(api_address).await?;
        println!("Listening fo api connections on {}", listener.local_addr()?);
        let mut incoming = listener.incoming();
        while let Some(stream) = incoming.next().await {
            let stream = stream?;
            let handler = self.clone();
            task::spawn(async move {
                handler.handle_api(stream).await.unwrap();
            });
        }
        Ok(())
    }

    async fn handle_api(&self, stream: TcpStream) -> Result<()> {
        println!("Accepted api connection from: {}", stream.peer_addr()?);
        let (reader, writer) = (&stream, &stream);
        let mut reader = MessageReader::new(reader);
        let mut writer = MessageWriter::new(writer);

        while let Some(msg) = reader.read_next().await? {
            match msg {
                OnionRequest::Build(onion_port, dst_addr, dst_hostkey) => {
                    let mut peers = self.select_hops(3).await?;
                    peers.push(Peer::new(dst_addr, onion_port, dst_hostkey));
                    task::spawn(async move {
                        self.onion.build_tunnel(3, peers.iter()).await?;
                    });
                }
                OnionRequest::Destroy(tunnel_id) => {
                    self.onion.destroy_tunnel(tunnel_id).await?;
                }
                OnionRequest::Data(tunnel_id, tunnel_data) => {
                    self.onion.send_data(tunnel_id, &tunnel_data).await?;
                }
                OnionRequest::Cover(cover_size) => {
                    unimplemented!();
                }
            }
        }
        Ok(())
    }

    async fn select_hops(&self, n_hops: usize) -> Result<Vec<Peer>> {
        let mut peers = Vec::with_capacity(n_hops);
        let mut rps = self.rps.lock().await;
        for _ in 0..n_hops {
            peers.push(rps.query().await?);
        }
        Ok(peers)
    }
}

#[async_std::main]
async fn main() -> Result<()> {
    #[rustfmt::skip]
    let config: Config = toml::from_str(r#"
        hostkey = ""

        [onion]
        api_address = "127.0.0.1:4201"
        p2p_port = 4202
        p2p_hostname = "127.0.0.1"

        [rps]
        api_address = "127.0.0.1:4203"
    "#)?;

    let onion_module = OnionModule::init(dbg!(config)).await?;
    let onion_module = Arc::new(onion_module);
    onion_module.listen_api().await?;
    Ok(())
}
