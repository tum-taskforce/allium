use crate::api::config::Config;
use crate::api::rps::RpsModule;
use crate::api::socket::ApiSocket;
use crate::utils::ToBytes;
use anyhow::Context;
use api::protocol::*;
use bytes::Bytes;
use futures::stream::StreamExt;
use log::{info, trace};
use onion::*;
use ring::rand;
use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::join;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::stream::Stream;
use tokio::sync::Mutex;

mod api;
mod utils;

struct OnionModule {
    connections: Mutex<HashMap<SocketAddr, ApiSocket<OwnedWriteHalf>>>,
    tunnels: Mutex<HashMap<TunnelId, Vec<SocketAddr>>>,
    hostkeys: Mutex<HashMap<TunnelId, Bytes>>,
    rng: rand::SystemRandom,
}

impl OnionModule {
    pub fn new() -> Self {
        OnionModule {
            connections: Default::default(),
            tunnels: Default::default(),
            hostkeys: Default::default(),
            rng: rand::SystemRandom::new(),
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

    /// Translates API request to the corresponding methods on the onion handle.
    async fn handle_api(&self, stream: TcpStream, onion: Onion) -> Result<()> {
        let client_addr = stream.peer_addr()?;
        trace!("Accepted API connection from: {}", client_addr);
        let (read_stream, write_stream) = stream.into_split();
        self.connections
            .lock()
            .await
            .insert(client_addr.clone(), ApiSocket::new(write_stream));
        let mut socket = ApiSocket::new(read_stream);

        while let Some(msg) = socket.read_next::<OnionRequest>().await? {
            trace!("Handling {:?}", msg);
            let _msg_id = msg.id();
            match msg {
                OnionRequest::Build(dst_addr, dst_hostkey) => {
                    let dest = Peer::new(dst_addr, RsaPublicKey::new(dst_hostkey.to_vec()));

                    let tunnel_id = loop {
                        let tunnel_id = random_id(&self.rng);
                        if !self.tunnels.lock().await.contains_key(&tunnel_id) {
                            break tunnel_id;
                        }
                    };

                    onion.build_tunnel(tunnel_id, dest, 3);

                    self.tunnels
                        .lock()
                        .await
                        .insert(tunnel_id, vec![client_addr]);

                    self.hostkeys.lock().await.insert(tunnel_id, dst_hostkey);
                }
                OnionRequest::Destroy(tunnel_id) => {
                    let mut tunnels = self.tunnels.lock().await;
                    if let Some(clients) = tunnels.get_mut(&tunnel_id) {
                        clients.retain(|x| x != &client_addr);
                        if clients.is_empty() {
                            onion.destroy_tunnel(tunnel_id);
                        }
                    } else {
                        self.write_to_client(
                            &client_addr,
                            OnionResponse::Error(ErrorReason::Destroy, tunnel_id),
                        )
                        .await?;
                    }
                }
                OnionRequest::Data(tunnel_id, tunnel_data) => {
                    if self.tunnels.lock().await.contains_key(&tunnel_id) {
                        onion.send_data(tunnel_id, &tunnel_data);
                    } else {
                        self.write_to_client(
                            &client_addr,
                            OnionResponse::Error(ErrorReason::Data, tunnel_id),
                        )
                        .await?;
                    }
                }
                OnionRequest::Cover(_cover_size) => {
                    // TODO unimplemented!();
                }
            }
        }
        Ok(())
    }

    /// Handles P2P protocol events and notifies interested API clients
    async fn handle_events<E>(&self, mut events: E) -> Result<()>
    where
        E: Stream<Item = Event> + Unpin,
    {
        while let Some(event) = events.next().await {
            match event {
                Event::Ready { tunnel_id } => {
                    for client in self.clients_for_tunnel(&tunnel_id).await {
                        self.write_to_client(
                            &client,
                            OnionResponse::Ready(
                                tunnel_id,
                                self.hostkeys.lock().await.remove(&tunnel_id).unwrap(),
                            ),
                        )
                        .await?;
                    }
                }
                Event::Incoming { tunnel_id } => {
                    let all_conns = self.connections.lock().await.keys().cloned().collect();
                    self.tunnels.lock().await.insert(tunnel_id, all_conns);

                    for client in self.clients_for_tunnel(&tunnel_id).await {
                        self.write_to_client(&client, OnionResponse::Incoming(tunnel_id))
                            .await?;
                    }
                }
                Event::Data { tunnel_id, data } => {
                    for client in self.clients_for_tunnel(&tunnel_id).await {
                        self.write_to_client(&client, OnionResponse::Data(tunnel_id, data.clone()))
                            .await?;
                    }
                }
                Event::Error { tunnel_id, reason } => {
                    for client in self.clients_for_tunnel(&tunnel_id).await {
                        self.write_to_client(&client, OnionResponse::Error(reason, tunnel_id))
                            .await?;

                        if reason == ErrorReason::Build {
                            self.tunnels.lock().await.remove(&tunnel_id);
                            self.hostkeys.lock().await.remove(&tunnel_id);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn clients_for_tunnel(&self, tunnel_id: &TunnelId) -> Vec<SocketAddr> {
        self.tunnels
            .lock()
            .await
            .get(tunnel_id)
            .iter()
            .flat_map(|x| x.iter().cloned())
            .collect::<Vec<SocketAddr>>()
    }

    async fn write_to_client<M: ToBytes>(&self, client: &SocketAddr, msg: M) -> Result<()> {
        self.connections
            .lock()
            .await
            .get_mut(client)
            .unwrap()
            .write(msg)
            .await
    }
}

/// Command line arguments:
/// * config file path (default: config.ini)
#[tokio::main]
async fn main() -> Result<()> {
    // setup logging
    pretty_env_logger::init();
    info!(
        "{} version {}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    );

    // read config file
    let config_path = env::args().nth(1).unwrap_or("config.ini".to_string());
    let config = Config::from_file(config_path)?;

    // connect to RPS (random peer sampling) module
    let rps = RpsModule::new(&config.rps)
        .await
        .context("Failed to connect to RPS module")?;

    let onion_addr = SocketAddr::new(config.onion.p2p_hostname, config.onion.p2p_port);
    // read hostkey (RSA private key)
    let hostkey =
        RsaPrivateKey::from_pem_file(&config.onion.hostkey).context("Could not read hostkey")?;

    // initialize onion, start listening on p2p port
    // events is a stream of events from the p2p protocol which should notify API clients
    let (onion, events) = Onion::new(onion_addr, hostkey, rps.into_stream())?;

    // initialize onion module listening on API connections
    let onion_module = Arc::new(OnionModule::new());
    let api_listen_task = tokio::spawn({
        let api_handler = onion_module.clone();
        let api_addr = config.onion.api_address.clone();
        async move {
            api_handler.listen_api(api_addr, onion).await.unwrap();
        }
    });

    // TODO maybe one task for incoming and events (select), no mutex on connections required?
    let event_task = tokio::spawn({
        let event_handler = onion_module.clone();
        async move {
            event_handler.handle_events(events).await.unwrap();
        }
    });

    let (_, _) = join!(api_listen_task, event_task);
    Ok(())
}
