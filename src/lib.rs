use crate::onion::circuit::{self, CircuitHandler, CircuitId};
use crate::onion::protocol;
use crate::onion::socket::OnionSocket;
use crate::onion::tunnel::{self, Target, TunnelBuilder, TunnelHandler};
use anyhow::anyhow;
use bytes::Bytes;
use futures::stream::StreamExt;
use log::{debug, info, trace, warn};
use ring::rand;
use std::collections::{hash_map, HashMap};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::{cmp, fmt};
use tokio::net::{TcpListener, TcpStream};
use tokio::stream::Stream;
use tokio::sync::Mutex;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::time::{self, Duration};

pub use crate::onion::crypto::{RsaPrivateKey, RsaPublicKey};
pub use crate::onion::tunnel::random_id;
pub use crate::onion::tunnel::TunnelId;

mod onion;
mod utils;

pub type Result<T> = std::result::Result<T, anyhow::Error>;

const DEFAULT_ROUND_DURATION: Duration = Duration::from_secs(30);
const DEFAULT_HOPS: usize = 2;

const DATA_BUFFER_SIZE: usize = 100;
const INCOMING_BUFFER_SIZE: usize = 100;

static TUNNEL_COUNT: AtomicUsize = AtomicUsize::new(0);

/// A remote peer characterized by its address, the port on which it is listening for onion
/// connections and its public key. The public key is needed to verify the authenticity of
/// signed messages received from this peer.
#[derive(Clone)]
pub struct Peer {
    addr: SocketAddr,
    hostkey: RsaPublicKey,
}

impl Peer {
    pub fn new(addr: SocketAddr, hostkey: RsaPublicKey) -> Self {
        Peer { addr, hostkey }
    }

    pub fn address(&self) -> SocketAddr {
        self.addr
    }
}

impl fmt::Debug for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Peer").field(&self.addr).finish()
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

pub struct OnionTunnel {
    tunnel_id: TunnelId,
    data_tx: mpsc::UnboundedSender<Bytes>,
    data_rx: mpsc::Receiver<Bytes>,
    counted: bool,
}

impl OnionTunnel {
    pub(crate) fn new(
        tunnel_id: TunnelId,
        counted: bool,
    ) -> (Self, mpsc::Sender<Bytes>, mpsc::UnboundedReceiver<Bytes>) {
        if counted {
            TUNNEL_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        let (data_tx, data_rx2) = mpsc::unbounded_channel();
        let (data_tx2, data_rx) = mpsc::channel(DATA_BUFFER_SIZE);
        let tunnel = Self {
            tunnel_id,
            data_tx,
            data_rx,
            counted,
        };
        (tunnel, data_tx2, data_rx2)
    }

    pub async fn read(&mut self) -> Result<Bytes> {
        self.data_rx
            .recv()
            .await
            .ok_or(anyhow!("Connection closed."))
    }

    pub fn write(&self, mut buf: Bytes) -> Result<()> {
        while !buf.is_empty() {
            let part = buf.split_to(cmp::min(protocol::MAX_DATA_SIZE, buf.len()));
            self.data_tx
                .send(part)
                .map_err(|_| anyhow!("Connection closed."))?;
        }
        Ok(())
    }

    pub fn id(&self) -> TunnelId {
        self.tunnel_id
    }

    pub fn writer(&self) -> OnionTunnelWriter {
        OnionTunnelWriter {
            tunnel_id: self.tunnel_id,
            data_tx: self.data_tx.clone(),
        }
    }

    async fn forward_data(
        mut self,
        mut tunnel_rx: mpsc::Receiver<OnionTunnel>,
        mut data_tx: mpsc::Sender<Bytes>,
        mut data_rx: mpsc::UnboundedReceiver<Bytes>,
    ) -> Option<()> {
        loop {
            tokio::select! {
                t = tunnel_rx.recv() => self = t?,
                d = self.read() => data_tx.send(d.ok()?).await.ok()?,
                d = data_rx.recv() => self.write(d?).ok()?,
            }
        }
    }
}

impl fmt::Debug for OnionTunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OnionTunnel")
            .field("id", &self.tunnel_id)
            .finish()
    }
}

impl Drop for OnionTunnel {
    fn drop(&mut self) {
        if self.counted {
            let c = TUNNEL_COUNT.fetch_sub(1, Ordering::Relaxed);
            debug!("Dropping tunnel with ID {}, count: {}", self.id(), c);
        } else {
            debug!("Dropping tunnel with ID {}", self.id());
        }
    }
}

#[derive(Clone)]
pub struct OnionTunnelWriter {
    tunnel_id: TunnelId,
    data_tx: mpsc::UnboundedSender<Bytes>,
}

impl OnionTunnelWriter {
    pub fn write(&self, mut buf: Bytes) -> Result<()> {
        while !buf.is_empty() {
            let part = buf.split_to(cmp::min(protocol::MAX_DATA_SIZE, buf.len()));
            self.data_tx
                .send(part)
                .map_err(|_| anyhow!("Connection closed."))?;
        }
        Ok(())
    }

    pub fn id(&self) -> TunnelId {
        self.tunnel_id
    }
}

impl fmt::Debug for OnionTunnelWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OnionTunnelWriter")
            .field("id", &self.tunnel_id)
            .finish()
    }
}

#[derive(Clone)]
pub struct OnionContext {
    peer_provider: PeerProvider,
    n_hops: usize,
    events: broadcast::Sender<tunnel::Event>,
    cover_tunnel: OnionTunnelWriter,
    rng: rand::SystemRandom,
}

impl OnionContext {
    fn new(
        events: broadcast::Sender<tunnel::Event>,
        peer_provider: PeerProvider,
        n_hops: usize,
        enable_cover: bool,
    ) -> Self {
        let (cover_tx, cover_rx) = mpsc::unbounded_channel();
        let ctx = OnionContext {
            rng: rand::SystemRandom::new(),
            peer_provider,
            n_hops,
            events,
            cover_tunnel: OnionTunnelWriter {
                tunnel_id: 0,
                data_tx: cover_tx,
            },
        };

        if enable_cover {
            let mut cover_handler = CoverHandler {
                cover_rx,
                ctx: ctx.clone(),
                cover_tunnel: None,
            };

            tokio::spawn(async move {
                cover_handler.handle().await;
            });
        }

        ctx
    }

    /// Builds a new tunnel to `dest` over `n_hops` additional peers.
    /// Performs a handshake with each hop and then spawns a task for handling incoming messages
    pub async fn build_tunnel(&self, dest: Peer) -> Result<OnionTunnel> {
        self.build_tunnel_internal(Target::Peer(dest)).await
    }

    async fn build_tunnel_internal(&self, dest: Target) -> Result<OnionTunnel> {
        info!("Building tunnel to {:?}", dest);
        let tunnel_id = tunnel::random_id(&self.rng);
        let mut builder = TunnelBuilder::new(
            tunnel_id,
            dest,
            self.n_hops,
            self.peer_provider.clone(),
            self.rng.clone(),
        );

        let (ready_tx, ready_rx) = oneshot::channel();
        let mut handler = TunnelHandler::new(
            builder.build().await?,
            builder,
            self.events.subscribe(),
            ready_tx,
        );

        tokio::spawn(async move {
            handler.handle().await;
        });
        ready_rx.await?
    }

    pub fn send_cover(&self, size: u16) -> Result<()> {
        let packet_count = (size as usize + protocol::MAX_DATA_SIZE - 1) / protocol::MAX_DATA_SIZE;
        for _ in 0..packet_count {
            self.cover_tunnel
                .write(Bytes::new())
                .map_err(|_| anyhow!("Cover traffic is disabled"))?;
        }
        Ok(())
    }
}

struct CoverHandler {
    cover_rx: mpsc::UnboundedReceiver<Bytes>,
    ctx: OnionContext,
    cover_tunnel: Option<OnionTunnel>,
}

impl CoverHandler {
    async fn handle(&mut self) {
        let mut events = self.ctx.events.subscribe();
        loop {
            tokio::select! {
                Ok(evt) = events.recv() => {
                    if evt == tunnel::Event::Switchover {
                        self.update_tunnel().await;
                    }
                }
                Some(data) = self.cover_rx.recv() => {
                    // FIXME errors in case cover_tunnel is None or write fails are not propagated
                    // to send_cover.
                    // Potential fix: store Arc<Mutex<Option<OnionTunnel>>> in OnionContext which
                    // is updated by update_tunnel.
                    if let Some(tunnel) = &self.cover_tunnel {
                        tunnel.write(data);
                    }
                }
                else => break,
            }
        }
    }

    async fn update_tunnel(&mut self) {
        self.cover_tunnel = match (
            self.cover_tunnel.take(),
            TUNNEL_COUNT.load(Ordering::Relaxed),
        ) {
            (None, 0) => self
                .ctx
                .build_tunnel_internal(tunnel::Target::Random)
                .await
                .ok(),
            (None, _) => None,
            (Some(_), 0) => unreachable!(),
            (Some(t), 1) => Some(t),
            (Some(_), _) => None,
        }
    }
}

pub struct Incoming {
    incoming: mpsc::Receiver<OnionTunnel>,
}

impl Incoming {
    pub async fn next(&mut self) -> Option<OnionTunnel> {
        self.incoming.recv().await
    }
}

#[derive(Clone)]
struct OnionListener {
    hostkey: Arc<RsaPrivateKey>,
    incoming: mpsc::Sender<OnionTunnel>,
    tunnels: Arc<Mutex<HashMap<TunnelId, mpsc::Sender<OnionTunnel>>>>,
}

impl OnionListener {
    fn new(hostkey: RsaPrivateKey, incoming: mpsc::Sender<OnionTunnel>) -> Self {
        OnionListener {
            hostkey: Arc::new(hostkey),
            incoming,
            tunnels: Default::default(),
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
        while let Some(stream) = incoming.next().await {
            let stream = stream?;
            info!("Accepted connection from {:?}", stream.peer_addr().unwrap());
            let mut handler = self.clone();
            tokio::spawn(async move {
                handler.handle_connection(stream).await;
            });
        }
        Ok(())
    }

    async fn handle_connection(&mut self, stream: TcpStream) {
        let socket = OnionSocket::new(stream);
        let (incoming_tx, mut incoming_rx) = mpsc::channel(1); // maybe convert to oneshot
        let mut handler = match CircuitHandler::init(socket, &*self.hostkey, incoming_tx).await {
            Ok(handler) => handler,
            Err(e) => {
                warn!("{}", e);
                return;
            }
        };

        tokio::spawn(async move {
            if let Err(e) = handler.handle().await {
                warn!("{}", e);
            }
        });

        if let Some(tunnel) = incoming_rx.recv().await {
            self.handle_incoming(tunnel).await;
        }
    }

    async fn handle_incoming(&mut self, tunnel: OnionTunnel) {
        let tunnels = self.tunnels.clone();
        let mut tunnels = tunnels.lock().await;

        match tunnels.entry(tunnel.id()) {
            hash_map::Entry::Occupied(mut e) => {
                if let Err(t) = e.get_mut().send(tunnel).await {
                    if let Ok(tunnel_tx) = self.handle_new_tunnel(t.0).await {
                        e.insert(tunnel_tx);
                    }
                }
            }
            hash_map::Entry::Vacant(e) => {
                if let Ok(tunnel_tx) = self.handle_new_tunnel(tunnel).await {
                    e.insert(tunnel_tx);
                }
            }
        }
    }

    async fn handle_new_tunnel(
        &mut self,
        tunnel: OnionTunnel,
    ) -> Result<mpsc::Sender<OnionTunnel>> {
        let (tunnel_tx, tunnel_rx) = mpsc::channel(1);
        let (e_tunnel, e_data_tx, e_data_rx) = OnionTunnel::new(tunnel.id(), true);
        self.incoming.send(e_tunnel).await?;

        tokio::spawn({
            let tunnels = self.tunnels.clone();
            async move {
                let tunnel_id = tunnel.id();
                debug!("Handling incoming tunnel {}", tunnel_id);
                let _ = tunnel.forward_data(tunnel_rx, e_data_tx, e_data_rx).await;
                tunnels.lock().await.remove(&tunnel_id);
                debug!("Finished handling incoming tunnel {}", tunnel_id);
            }
        });

        Ok(tunnel_tx)
    }
}

/// Tunnels created in one period should be torn down and rebuilt for the next period.
/// However, Onion should ensure that this is done transparently to the modules, using these
/// tunnels. This could be achieved by creating a new tunnel before the end of a period and
/// seamlessly switching over the data stream to the new tunnel once at the end of the current
/// period. Since the destination peer of both old and new tunnel remains the same, the seamless
/// switch over is possible.
struct RoundHandler {
    events: broadcast::Sender<tunnel::Event>,
    round_duration: Duration,
}

impl RoundHandler {
    async fn handle(&mut self) {
        info!("Starting RoundHandler");
        let mut round_timer = time::interval(self.round_duration);
        let keep_alive_interval = circuit::IDLE_TIMEOUT / 3 * 2;
        let mut keep_alive_timer = time::interval(keep_alive_interval);
        loop {
            tokio::select! {
                _ = round_timer.tick() => {
                    info!("next round");
                    let _ = self.events.send(tunnel::Event::Switchover);
                }
                _ = keep_alive_timer.tick() => {
                    let _ = self.events.send(tunnel::Event::KeepAlive);
                }
            }
        }
    }
}

pub struct OnionBuilder {
    listen_addr: SocketAddr,
    hostkey: RsaPrivateKey,
    peer_provider: PeerProvider,
    enable_cover: bool,
    n_hops: usize,
    round_duration: Duration,
}

impl OnionBuilder {
    /// Construct a new onion instance.
    /// Returns a builder which allows further configuration.
    pub fn new(
        listen_addr: SocketAddr,
        hostkey: RsaPrivateKey,
        peer_provider: PeerProvider,
    ) -> OnionBuilder {
        OnionBuilder {
            listen_addr,
            hostkey,
            peer_provider,
            enable_cover: true,
            n_hops: DEFAULT_HOPS,
            round_duration: DEFAULT_ROUND_DURATION,
        }
    }

    pub fn enable_cover_traffic(mut self, enable: bool) -> Self {
        self.enable_cover = enable;
        self
    }

    pub fn set_hops_per_tunnel(mut self, n_hops: usize) -> Self {
        self.n_hops = n_hops;
        self
    }

    pub fn set_round_duration(mut self, secs: u64) -> Self {
        self.round_duration = Duration::from_secs(secs);
        self
    }

    /// Returns the constructed instance.
    pub fn start(self) -> (OnionContext, Incoming) {
        let OnionBuilder {
            listen_addr,
            hostkey,
            peer_provider,
            enable_cover,
            n_hops,
            round_duration,
        } = self;

        // capacity = 2 so both initial switch-over and keep-alive are received
        let (events, _) = broadcast::channel(2);
        let (incoming_tx, incoming_rx) = mpsc::channel(INCOMING_BUFFER_SIZE);

        // create task listening on p2p connections
        tokio::spawn({
            let mut listener = OnionListener::new(hostkey, incoming_tx);
            async move { listener.listen_addr(listen_addr).await }
        });

        let ctx = OnionContext::new(events.clone(), peer_provider, n_hops, enable_cover);

        // creates round handler task
        tokio::spawn({
            let mut round_handler = RoundHandler {
                events,
                round_duration,
            };
            async move { round_handler.handle().await }
        });

        let incoming = Incoming {
            incoming: incoming_rx,
        };
        (ctx, incoming)
    }
}
