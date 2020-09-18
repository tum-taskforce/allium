use crate::api::config::Config;
use crate::api::rps::RpsModule;
use crate::api::socket::ApiSocket;
use anyhow::Context;
use api::protocol::*;
use bytes::Bytes;
use futures::stream::StreamExt;
use log::{info, trace, warn};
use onion::*;
use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};

mod api;
mod utils;

// for security reasons there should always be at least two hops per tunnel
const MIN_HOPS: usize = 2;

#[derive(Clone)]
struct ApiTunnel {
    writer: OnionTunnelWriter,
    events: mpsc::UnboundedSender<ApiEvent>,
}

impl ApiTunnel {
    fn new(tunnel: &OnionTunnel, events: mpsc::UnboundedSender<ApiEvent>) -> Self {
        ApiTunnel {
            writer: tunnel.writer(),
            events,
        }
    }
}

// Sent from the TunnelHandler to the ApiHandler
#[derive(Clone)]
enum TunnelEvent {
    Data { tunnel_id: TunnelId, data: Bytes },
    Destroyed { tunnel_id: TunnelId },
}

// Sent from the ApiHandler to the TunnelHandler
#[derive(Clone)]
enum ApiEvent {
    Subscribe {
        client_addr: SocketAddr,
        events: mpsc::UnboundedSender<TunnelEvent>,
    },
    Unsubscribe {
        client_addr: SocketAddr,
    },
}

struct ApiHandler {
    client_addr: SocketAddr,
    socket: ApiSocket<TcpStream>,
    ctx: OnionContext,
    incoming: broadcast::Receiver<ApiTunnel>,
    tunnels: HashMap<TunnelId, ApiTunnel>,
    events_tx: mpsc::UnboundedSender<TunnelEvent>,
    events_rx: mpsc::UnboundedReceiver<TunnelEvent>,
}

impl ApiHandler {
    fn new(stream: TcpStream, ctx: OnionContext, incoming: broadcast::Receiver<ApiTunnel>) -> Self {
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        ApiHandler {
            client_addr: stream.peer_addr().unwrap(),
            socket: ApiSocket::new(stream),
            ctx,
            incoming,
            tunnels: Default::default(),
            events_tx,
            events_rx,
        }
    }

    async fn handle(&mut self) -> Result<()> {
        trace!("Accepted API connection from: {}", self.client_addr);
        loop {
            tokio::select! {
                req = self.socket.read_next::<OnionRequest>() => {
                    self.handle_request(req?).await?;
                }
                Ok(tunnel) = self.incoming.recv() => {
                    self.handle_incoming(tunnel).await?;
                }
                Some(evt) = self.events_rx.recv() => {
                    self.handle_event(evt).await?;
                }
            }
        }
    }

    async fn handle_request(&mut self, req: OnionRequest) -> Result<()> {
        trace!("Handling {:?}", req);
        match req {
            OnionRequest::Build(dst_addr, dst_hostkey) => {
                let dest_public_key = RsaPublicKey::from_subject_info(dst_hostkey.as_ref());
                let dest = Peer::new(dst_addr, dest_public_key);

                let tunnel = self.ctx.build_tunnel(dest).await;

                if let Ok(tunnel) = tunnel {
                    let tunnel_id = tunnel.id();
                    self.socket
                        .write(OnionResponse::Ready(tunnel_id, dst_hostkey))
                        .await?;

                    let (events_tx, events_rx) = mpsc::unbounded_channel();
                    let api_tunnel = ApiTunnel::new(&tunnel, events_tx);
                    let prev = self.tunnels.insert(tunnel_id, api_tunnel);
                    assert!(prev.is_none());

                    let mut tunnel_handler = TunnelHandler::new(tunnel, events_rx);
                    tunnel_handler.subscribe(self.client_addr, self.events_tx.clone());
                    tokio::spawn(async move {
                        tunnel_handler.handle().await;
                    });
                } else {
                    self.socket
                        .write(OnionResponse::Error(ErrorReason::Build, 0))
                        .await?;
                }
            }
            OnionRequest::Destroy(tunnel_id) => {
                if let Some(tunnel) = self.tunnels.remove(&tunnel_id) {
                    let _ = tunnel.events.send(ApiEvent::Unsubscribe {
                        client_addr: self.client_addr,
                    });
                } else {
                    self.socket
                        .write(OnionResponse::Error(ErrorReason::Destroy, tunnel_id))
                        .await?;
                }
            }
            OnionRequest::Data(tunnel_id, tunnel_data) => {
                if let Some(tunnel) = self.tunnels.get_mut(&tunnel_id) {
                    let _ = tunnel.writer.write(tunnel_data);
                } else {
                    self.socket
                        .write(OnionResponse::Error(ErrorReason::Data, tunnel_id))
                        .await?;
                }
            }
            OnionRequest::Cover(cover_size) => {
                if self.ctx.send_cover(cover_size).is_err() {
                    self.socket
                        .write(OnionResponse::Error(ErrorReason::Cover, 0))
                        .await?;
                }
            }
        }
        Ok(())
    }

    async fn handle_incoming(&mut self, tunnel: ApiTunnel) -> Result<()> {
        let tunnel_id = tunnel.writer.id();
        if !self.tunnels.contains_key(&tunnel_id) {
            self.socket
                .write(OnionResponse::Incoming(tunnel_id))
                .await?;

            let _ = tunnel.events.send(ApiEvent::Subscribe {
                client_addr: self.client_addr,
                events: self.events_tx.clone(),
            });

            self.tunnels.insert(tunnel_id, tunnel);
        }
        Ok(())
    }

    async fn handle_event(&mut self, evt: TunnelEvent) -> Result<()> {
        match evt {
            TunnelEvent::Data { tunnel_id, data } => {
                self.socket
                    .write(OnionResponse::Data(tunnel_id, data))
                    .await?;
            }
            TunnelEvent::Destroyed { tunnel_id } => {
                self.tunnels.remove(&tunnel_id);
            }
        }
        Ok(())
    }
}

impl Drop for ApiHandler {
    fn drop(&mut self) {
        for tunnel in self.tunnels.values() {
            let _ = tunnel.events.send(ApiEvent::Unsubscribe {
                client_addr: self.client_addr,
            });
        }
    }
}

struct TunnelHandler {
    tunnel: OnionTunnel,
    clients: HashMap<SocketAddr, mpsc::UnboundedSender<TunnelEvent>>,
    events: mpsc::UnboundedReceiver<ApiEvent>,
}

impl TunnelHandler {
    fn new(tunnel: OnionTunnel, events: mpsc::UnboundedReceiver<ApiEvent>) -> Self {
        TunnelHandler {
            tunnel,
            clients: Default::default(),
            events,
        }
    }

    fn subscribe(&mut self, client_addr: SocketAddr, data: mpsc::UnboundedSender<TunnelEvent>) {
        self.clients.insert(client_addr, data);
    }

    async fn handle(&mut self) {
        loop {
            tokio::select! {
                data = self.tunnel.read() => {
                    let tunnel_id = self.tunnel.id();
                    let evt = match data {
                        Ok(data) => TunnelEvent::Data { tunnel_id, data },
                        Err(_) => TunnelEvent::Destroyed { tunnel_id },
                    };

                    for client in self.clients.values() {
                        let _ = client.send(evt.clone());
                        // maybe remove client in case send fails
                        // but should not happen as clients should unsubscribe
                    }
                }
                Some(evt) = self.events.recv() => {
                    match evt {
                        ApiEvent::Unsubscribe { client_addr } => {
                            self.clients.remove(&client_addr);

                            if self.clients.is_empty() {
                                break;
                            }
                        }
                        ApiEvent::Subscribe { client_addr, events } => {
                            self.subscribe(client_addr, events);
                        }
                    }
                }
            }
        }
    }
}

impl Drop for TunnelHandler {
    fn drop(&mut self) {
        let tunnel_id = self.tunnel.id();
        for client in self.clients.values() {
            let _ = client.send(TunnelEvent::Destroyed { tunnel_id });
        }
    }
}

pub struct OnionModule {
    ctx: OnionContext,
    onion_incoming: Incoming,
}

impl OnionModule {
    pub fn new(ctx: OnionContext, incoming: Incoming) -> Self {
        OnionModule {
            ctx,
            onion_incoming: incoming,
        }
    }

    pub async fn listen_api(&mut self, api_addr: SocketAddr) -> Result<()> {
        let mut listener = TcpListener::bind(api_addr).await?;
        info!(
            "Listening for API connections on {:?}",
            listener.local_addr()
        );
        let mut api_incoming = listener.incoming();

        let (incoming, _) = broadcast::channel(1);
        loop {
            tokio::select! {
                Some(client) = api_incoming.next() => {
                    let mut api_handler = ApiHandler::new(client?, self.ctx.clone(), incoming.subscribe());
                    tokio::spawn(async move {
                        api_handler.handle().await;
                    });
                }
                Some(tunnel) = self.onion_incoming.next() => {
                    let (events_tx, events_rx) = mpsc::unbounded_channel();
                    let api_tunnel = ApiTunnel::new(&tunnel, events_tx);
                    let _ = incoming.send(api_tunnel);

                    let mut tunnel_handler = TunnelHandler::new(tunnel, events_rx);
                    tokio::spawn(async move {
                        tunnel_handler.handle().await;
                    });
                }
                else => break,
            }
        }
        Ok(())
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
    let config_path = env::args()
        .nth(1)
        .unwrap_or_else(|| "config.ini".to_string());
    let config = Config::from_file(config_path)?;

    if config.onion.hops < MIN_HOPS {
        // this could be a hard error in the future
        warn!(
            "The number of hops should be at least 2! (current value: {})",
            config.onion.hops
        );
    }

    // connect to RPS (random peer sampling) module
    let rps = RpsModule::new(&config.rps)
        .await
        .context("Failed to connect to RPS module")?;

    let onion_addr = SocketAddr::new(config.onion.p2p_hostname, config.onion.p2p_port);
    // read hostkey (RSA private key)
    let hostkey =
        RsaPrivateKey::from_pem_file(&config.onion.hostkey).context("Could not read hostkey")?;

    let peer_provider = PeerProvider::from_stream(rps.into_stream());

    // initialize onion, start listening on p2p port
    // events is a stream of events from the p2p protocol which should notify API clients
    let (ctx, onion_incoming) = OnionBuilder::new(onion_addr, hostkey, peer_provider)
        .enable_cover_traffic(config.onion.cover_traffic.unwrap_or(true))
        .set_hops_per_tunnel(config.onion.hops)
        .start();

    let mut onion = OnionModule::new(ctx, onion_incoming);
    onion.listen_api(config.onion.api_address).await?;
    Ok(())
}
