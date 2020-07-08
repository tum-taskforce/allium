use crate::api::config::Config;
use crate::api::rps::RpsModule;
use crate::api::socket::ApiSocket;
use anyhow::Context;
use api::protocol::*;
use futures::stream::StreamExt;
use log::{info, trace};
use onion::*;
use std::env;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::stream;
use tokio::sync::Mutex;

mod api;
mod utils;

struct OnionModule {
    onion: Onion,
    config: Config,
    rps: Mutex<RpsModule>,
}

impl OnionModule {
    async fn init(config: Config) -> Result<Self> {
        let rps = RpsModule::new(&config.rps)
            .await
            .context("Failed to connect to RPS module")?;
        let rps = Mutex::new(rps);
        // TODO construct peer provider from rps (use buffering)
        let peer_provider = stream::empty();

        let hostkey =
            RsaPrivateKey::from_pem_file("testkey.pem").context("Could not read hostkey")?;
        let onion = Onion::new(hostkey, peer_provider)?;
        /*task::spawn(async {
            let addr = SocketAddr::new(config.onion.p2p_hostname.parse().unwrap(), config.onion.p2p_port);
            onion.listen(addr).await.unwrap();
        });*/
        Ok(OnionModule { onion, config, rps })
    }

    async fn listen_api(self: Arc<Self>) -> Result<()> {
        let api_address = &self.config.onion.api_address;
        let mut listener = TcpListener::bind(api_address).await?;
        info!(
            "Listening for API connections on {:?}",
            listener.local_addr()
        );
        let mut incoming = listener.incoming();
        while let Some(stream) = incoming.next().await {
            let stream = stream?;
            let handler = self.clone();
            tokio::spawn(async move {
                handler.handle_api(stream).await.unwrap();
            });
        }
        Ok(())
    }

    async fn handle_api(self: Arc<Self>, stream: TcpStream) -> Result<()> {
        trace!("Accepted API connection from: {:?}", stream.peer_addr());
        let mut socket = ApiSocket::new(stream);

        while let Some(msg) = socket.read_next::<OnionRequest>().await? {
            trace!("Handling {:?}", msg);
            let _msg_id = msg.id();
            match msg {
                OnionRequest::Build(dst_addr, dst_hostkey) => {
                    let handler = self.clone();
                    let dest = Peer::new(dst_addr, RsaPublicKey::new(dst_hostkey.to_vec()));
                    let _tunnel = handler.onion.build_tunnel(dest, 3).await?;
                }
                OnionRequest::Destroy(tunnel_id) => {
                    self.onion.destroy_tunnel(tunnel_id).await?;
                }
                OnionRequest::Data(tunnel_id, tunnel_data) => {
                    self.onion.send_data(tunnel_id, &tunnel_data).await?;
                }
                OnionRequest::Cover(_cover_size) => {
                    // unimplemented!();
                }
            }
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    info!(
        "{} version {}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    );

    let config_path = env::args().nth(1).unwrap_or("config.ini".to_string());
    let config = Config::from_file(config_path)?;

    let onion_module = OnionModule::init(config)
        .await
        .context("Failed to initialize onion module")?;
    let onion_module = Arc::new(onion_module);
    onion_module.listen_api().await?;
    Ok(())
}
