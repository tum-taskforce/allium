use crate::api::config::Config;
use crate::api::rps::RpsModule;
use crate::api::socket::ApiSocket;
use anyhow::Context;
use api::protocol::*;
use futures::stream::StreamExt;
use log::{info, trace};
use onion::*;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::join;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::stream;
use tokio::stream::Stream;
use tokio::sync::Mutex;

mod api;
mod utils;

struct OnionModule {
    connections: Mutex<Vec<ApiSocket<OwnedWriteHalf>>>,
}

impl OnionModule {
    pub fn new() -> Self {
        OnionModule {
            connections: Mutex::new(Vec::new()),
        }
    }

    async fn listen_api(self: Arc<Self>, addr: SocketAddr, onion: Onion) -> Result<()> {
        let mut listener = TcpListener::bind(addr).await?;
        info!(
            "Listening for API connections on {:?}",
            listener.local_addr()
        );
        let mut incoming = listener.incoming();
        while let Some(stream) = incoming.next().await {
            let handler = self.clone();
            let stream = stream?;
            let onion = onion.clone();
            tokio::spawn(async move {
                handler.handle_api(stream, onion).await.unwrap();
            });
        }
        Ok(())
    }

    async fn handle_api(&self, stream: TcpStream, onion: Onion) -> Result<()> {
        trace!("Accepted API connection from: {:?}", stream.peer_addr());
        let (read_stream, write_stream) = stream.into_split();
        self.connections
            .lock()
            .await
            .push(ApiSocket::new(write_stream));
        let mut socket = ApiSocket::new(read_stream);

        while let Some(msg) = socket.read_next::<OnionRequest>().await? {
            trace!("Handling {:?}", msg);
            let _msg_id = msg.id();
            match msg {
                OnionRequest::Build(dst_addr, dst_hostkey) => {
                    let dest = Peer::new(dst_addr, RsaPublicKey::new(dst_hostkey.to_vec()));
                    let _tunnel = onion.build_tunnel(dest, 3).await?;
                }
                OnionRequest::Destroy(tunnel_id) => {
                    onion.destroy_tunnel(tunnel_id).await?;
                }
                OnionRequest::Data(tunnel_id, tunnel_data) => {
                    onion.send_data(tunnel_id, &tunnel_data).await?;
                }
                OnionRequest::Cover(_cover_size) => {
                    // unimplemented!();
                }
            }
        }
        Ok(())
    }

    async fn handle_events<E>(&self, mut events: E) -> Result<()>
    where
        E: Stream<Item = Event> + Unpin,
    {
        while let Some(event) = events.next().await {
            match event {
                Event::Data { tunnel_id, data } => {
                    // TODO only send messages to clients which have subscribed to this tunnel
                    for conn in self.connections.lock().await.iter_mut() {
                        let res = OnionResponse::Data(tunnel_id, data.as_ref());
                        conn.write(res).await?;
                    }
                }
                _ => unimplemented!(),
            }
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();
    info!(
        "{} version {}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    );

    let config_path = env::args().nth(1).unwrap_or("config.ini".to_string());
    let config = Config::from_file(config_path)?;

    let rps = RpsModule::new(&config.rps)
        .await
        .context("Failed to connect to RPS module")?;
    let rps = Mutex::new(rps);
    // TODO construct peer provider from rps (use buffering)
    let peer_provider = stream::empty();

    let onion_addr = SocketAddr::new(config.onion.p2p_hostname, config.onion.p2p_port);
    let hostkey =
        RsaPrivateKey::from_pem_file(&config.onion.hostkey).context("Could not read hostkey")?;

    let (onion, events) = Onion::new(onion_addr, hostkey, peer_provider)?;
    let onion_module = Arc::new(OnionModule::new());

    let api_listen_task = tokio::spawn({
        let api_handler = onion_module.clone();
        let api_addr = config.onion.api_address.clone();
        async move {
            api_handler.listen_api(api_addr, onion).await.unwrap();
        }
    });

    let event_task = tokio::spawn({
        let event_handler = onion_module.clone();
        async move {
            event_handler.handle_events(events).await.unwrap();
        }
    });

    join!(api_listen_task, event_task);
    Ok(())
}
