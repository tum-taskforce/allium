#![allow(dead_code)]
#![allow(unused_variables)]
use crate::onion::circuit::{self, CircuitHandler, CircuitId};
use crate::onion::socket::OnionSocket;
use crate::onion::tunnel::{self, TunnelBuilder, TunnelHandler};
use anyhow::anyhow;
use bytes::Bytes;
use futures::stream::StreamExt;
use log::{info, trace, warn};
use ring::rand;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::stream::Stream;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time::{self, Duration};

pub use crate::onion::crypto::{RsaPrivateKey, RsaPublicKey};
pub use crate::onion::tunnel::random_id;
pub use crate::onion::tunnel::TunnelId;
use std::fmt;

mod onion;
mod utils;

pub type Result<T> = std::result::Result<T, anyhow::Error>;

const ROUND_DURATION: Duration = Duration::from_secs(30); // TODO read from config

#[derive(Clone)]
pub struct Peer {
    addr: SocketAddr,
    hostkey: RsaPublicKey,
}

impl Peer {
    pub fn new(addr: SocketAddr, hostkey: RsaPublicKey) -> Self {
        Peer { addr, hostkey }
    }
}

/// Handled by the RoundHandler
#[derive(Debug)]
enum Request {
    Build {
        tunnel_id: TunnelId,
        dest: Peer,
        n_hops: usize,
    },
    Data {
        tunnel_id: TunnelId,
        data: Bytes,
    },
    Destroy {
        tunnel_id: TunnelId,
    },
    Cover {
        size: u16,
    },
}

/// Events destined for the API
#[derive(Debug, PartialEq)]
pub enum Event {
    Ready {
        tunnel_id: TunnelId,
    },
    Incoming {
        tunnel_id: TunnelId,
    },
    Data {
        tunnel_id: TunnelId,
        data: Bytes,
    },
    Error {
        tunnel_id: TunnelId,
        reason: ErrorReason,
    },
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum ErrorReason {
    Build,
    Data,
    Destroy,
}

#[derive(Clone)]
pub struct Onion {
    requests: mpsc::UnboundedSender<Request>,
}

impl Onion {
    /// Construct a new onion instance.
    /// Returns the constructed instance and an event stream.
    pub fn new(
        listen_addr: SocketAddr,
        hostkey: RsaPrivateKey,
        peer_provider: PeerProvider,
    ) -> Result<(Self, impl Stream<Item = Event>)> {
        // create request channel for interaction from the API to the round handler
        let (req_tx, req_rx) = mpsc::unbounded_channel();
        // create event channel for propagating events back to the API
        let (evt_tx, evt_rx) = mpsc::channel(100);
        // shared map of all tunnels (incoming and outgoing)
        let tunnels = Arc::new(Mutex::new(HashMap::new()));

        // creates round handler task which receives requests on req_rx and sends events on evt_tx
        tokio::spawn({
            let events = evt_tx.clone();
            let tunnels = tunnels.clone();
            let mut round_handler = RoundHandler::new(req_rx, events, peer_provider, tunnels);
            async move { round_handler.handle().await }
        });

        // create task listening on p2p connections
        // also sends events on evt_tx
        tokio::spawn({
            let events = evt_tx;
            let tunnels = tunnels;
            let mut listener = OnionListener::new(hostkey, events, tunnels);
            async move { listener.listen_addr(listen_addr).await }
        });

        let onion = Onion { requests: req_tx };
        Ok((onion, evt_rx))
    }

    pub fn build_tunnel(&self, tunnel_id: TunnelId, dest: Peer, n_hops: usize) -> TunnelId {
        self.requests
            .send(Request::Build {
                tunnel_id, // TODO maybe refactor to return tunnel_id with Ready
                dest,
                n_hops,
            })
            .map_err(|_| anyhow!("Failed to send build request"))
            .unwrap();
        tunnel_id
    }

    pub fn destroy_tunnel(&self, tunnel_id: TunnelId) {
        self.requests
            .send(Request::Destroy { tunnel_id })
            .map_err(|_| anyhow!("Failed to send destroy request"))
            .unwrap();
    }

    pub fn send_data(&self, tunnel_id: TunnelId, data: &[u8]) {
        // big TODO don't allocate
        self.requests
            .send(Request::Data {
                tunnel_id,
                data: data.to_vec().into(),
            })
            .map_err(|_| anyhow!("Failed to send data request"))
            .unwrap();
    }

    pub fn send_cover(&self, size: u16) {
        self.requests
            .send(Request::Cover { size })
            .map_err(|_| anyhow!("Failed to send cover request"))
            .unwrap();
    }
}

#[derive(Clone)]
pub struct PeerProvider {
    inner: mpsc::Sender<oneshot::Sender<Peer>>,
}

impl PeerProvider {
    pub fn from_stream<S>(mut stream: S) -> Self
    where
        S: Stream<Item = Peer> + Unpin + Send + Sync + 'static,
    {
        let (peer_tx, mut peer_rx) = mpsc::channel::<oneshot::Sender<Peer>>(100);
        tokio::spawn(async move {
            while let Some(req) = peer_rx.recv().await {
                let _ = req.send(stream.next().await.unwrap());
            }
        });
        PeerProvider { inner: peer_tx }
    }

    pub(crate) async fn random_peer(&mut self) -> Result<Peer> {
        let (peer_tx, peer_rx) = oneshot::channel();
        let _ = self.inner.send(peer_tx).await;
        Ok(peer_rx.await?)
    }
}

struct RoundHandler {
    requests: mpsc::UnboundedReceiver<Request>,
    events: mpsc::Sender<Event>,
    rng: rand::SystemRandom,
    peer_provider: PeerProvider,
    tunnels: Arc<Mutex<HashMap<TunnelId, mpsc::UnboundedSender<tunnel::Request>>>>,
    cover_tunnel: Option<mpsc::UnboundedSender<tunnel::Request>>,
    // more info about outgoing tunnels
}

impl RoundHandler {
    pub(crate) fn new(
        requests: mpsc::UnboundedReceiver<Request>,
        events: mpsc::Sender<Event>,
        peer_provider: PeerProvider,
        tunnels: Arc<Mutex<HashMap<TunnelId, mpsc::UnboundedSender<tunnel::Request>>>>,
    ) -> Self {
        let rng = rand::SystemRandom::new();
        RoundHandler {
            requests,
            events,
            rng,
            peer_provider,
            tunnels,
            cover_tunnel: None,
        }
    }

    pub(crate) async fn handle(&mut self) {
        info!("Starting RoundHandler");
        let mut round_timer = time::interval(ROUND_DURATION);
        loop {
            tokio::select! {
                Some(req) = self.requests.recv() => {
                    self.handle_request(req).await;
                }
                _ = round_timer.tick() => {
                    self.next_round().await;
                }
            }
        }
    }

    async fn handle_request(&mut self, req: Request) {
        trace!("RoundHandler: handling request {:?}", req);
        match req {
            Request::Build {
                tunnel_id,
                dest,
                n_hops,
            } => {
                self.handle_build(tunnel_id, dest, n_hops).await;
            }
            Request::Data { tunnel_id, data } => {
                self.handle_data(tunnel_id, data).await;
            }
            Request::Destroy { tunnel_id } => {
                self.handle_destroy(tunnel_id).await;
            }
            Request::Cover { size } => {
                self.handle_cover(size).await;
            }
        }
    }

    /// Builds a new tunnel to `dest` over `n_hops` additional peers.
    /// Performs a handshake with each hop and then spawns a task for handling incoming messages.
    pub(crate) async fn handle_build(&mut self, tunnel_id: TunnelId, dest: Peer, n_hops: usize) {
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn({
            let mut builder = TunnelBuilder::new(
                tunnel_id,
                dest,
                n_hops,
                self.peer_provider.clone(),
                self.rng.clone(),
            );
            let mut events = self.events.clone();
            async move {
                let first_tunnel = match builder.build().await {
                    Ok(t) => t,
                    Err(e) => {
                        warn!("Failed to build tunnel: {}", e);
                        let _ = events.send(Event::Error {
                            tunnel_id,
                            reason: ErrorReason::Build,
                        });
                        return;
                    }
                };
                let mut handler = TunnelHandler::new(first_tunnel, builder, rx, events);
                handler.handle().await;
            }
        });
        self.tunnels.lock().await.insert(tunnel_id, tx);
    }

    pub(crate) async fn handle_data(&mut self, tunnel_id: TunnelId, data: Bytes) {
        let _ = self
            .tunnels
            .lock()
            .await
            .get(&tunnel_id)
            .unwrap()
            .send(tunnel::Request::Data { data });
    }

    pub(crate) async fn handle_destroy(&mut self, tunnel_id: TunnelId) {
        let _ = self
            .tunnels
            .lock()
            .await
            .get(&tunnel_id)
            .unwrap()
            .send(tunnel::Request::Destroy);
    }

    pub(crate) async fn handle_cover(&mut self, _size: u16) {
        if let Some(tunnel) = &mut self.cover_tunnel {
            let _ = tunnel.send(tunnel::Request::KeepAlive);
        }
    }

    /// Tunnels created in one period should be torn down and rebuilt for the next period.
    /// However, Onion should ensure that this is done transparently to the modules, using these
    /// tunnels. This could be achieved by creating a new tunnel before the end of a period and
    /// seamlessly switching over the data stream to the new tunnel once at the end of the current
    /// period. Since the destination peer of both old and new tunnel remains the same, the seamless
    /// switch over is possible.
    async fn next_round(&mut self) {
        info!("next round");
        for tunnel in self.tunnels.lock().await.values_mut() {
            let _ = tunnel.send(tunnel::Request::Switchover);
        }
    }
}

struct OnionListener {
    hostkey: Arc<RsaPrivateKey>,
    events: mpsc::Sender<Event>,
    tunnels: Arc<Mutex<HashMap<TunnelId, mpsc::UnboundedSender<tunnel::Request>>>>,
}

impl OnionListener {
    fn new(
        hostkey: RsaPrivateKey,
        events: mpsc::Sender<Event>,
        tunnels: Arc<Mutex<HashMap<TunnelId, mpsc::UnboundedSender<tunnel::Request>>>>,
    ) -> Self {
        OnionListener {
            hostkey: Arc::new(hostkey),
            events,
            tunnels,
        }
    }

    async fn listen_addr(&mut self, addr: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        self.listen(listener).await
    }

    async fn listen(&mut self, mut listener: TcpListener) -> Result<()> {
        info!(
            "Listening for P2P connections on {:?}",
            listener.local_addr()
        );
        let mut incoming = listener.incoming();
        let (events_tx, mut events_rx) = mpsc::channel(100);

        loop {
            tokio::select! {
                Some(stream) = incoming.next() => self.handle_connection(stream?, events_tx.clone()).await,
                Some(event) = events_rx.recv() => self.handle_event(event).await,
                else => break,
            }
        }
        Ok(())
    }

    async fn handle_connection(&self, stream: TcpStream, events_tx: mpsc::Sender<circuit::Event>) {
        info!("Accepted connection from {:?}", stream.peer_addr().unwrap());
        let socket = OnionSocket::new(stream);
        let hostkey = self.hostkey.clone();

        tokio::spawn(async move {
            let mut handler = match CircuitHandler::init(socket, &hostkey, events_tx).await {
                Ok(handler) => handler,
                Err(e) => {
                    warn!("{}", e);
                    return;
                }
            };

            if let Err(e) = handler.handle().await {
                warn!("{}", e);
            }
        });
    }

    async fn handle_event(&mut self, event: circuit::Event) {
        trace!("OnionListener: handling event {:?}", event);
        match event {
            circuit::Event::Incoming {
                tunnel_id,
                requests,
            } => {
                match self.tunnels.lock().await.insert(tunnel_id, requests) {
                    None => {
                        let _ = self.events.send(Event::Incoming { tunnel_id }).await;
                    }
                    Some(s) => {
                        let _ = s.send(tunnel::Request::Destroy);
                        // implicit drop of any old channel
                    }
                };
            }
            circuit::Event::Data { tunnel_id, data } => {
                /* TODO We do not accept any incoming Data packets on the old socket, which me might
                    opt to for less packet drop on switchover.
                */
                if self.tunnels.lock().await.contains_key(&tunnel_id) {
                    let _ = self.events.send(Event::Data { tunnel_id, data }).await;
                }
            }
            circuit::Event::End { tunnel_id } => {
                /* TODO We never communicate this step to the API, nor do we need to. However, we
                   need to clear up the map to prevent cluttering. Also, we do not limit old
                   circuits to remain as zombie circuits on Alice's client since Alice expects an
                   END response which we should send here.
                */
            }
        }
    }
}

impl fmt::Debug for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Peer").field(&self.addr).finish()
    }
}
