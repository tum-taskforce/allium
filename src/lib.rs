use crate::onion::circuit::{self, CircuitHandler, CircuitId};
use crate::onion::protocol;
use crate::onion::socket::OnionSocket;
use crate::onion::tunnel::{self, TunnelBuilder, TunnelHandler};
use anyhow::anyhow;
use bytes::Bytes;
use futures::stream::StreamExt;
use log::{info, warn};
use ring::rand;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::{cmp, fmt};
use tokio::net::{TcpListener, TcpStream};
use tokio::stream::Stream;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::time::{self, Duration};

pub use crate::onion::crypto::{RsaPrivateKey, RsaPublicKey};
pub use crate::onion::tunnel::random_id;
pub use crate::onion::tunnel::TunnelDestination;
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
}

impl OnionTunnel {
    pub(crate) fn new(
        tunnel_id: TunnelId,
    ) -> (Self, mpsc::Sender<Bytes>, mpsc::UnboundedReceiver<Bytes>) {
        TUNNEL_COUNT.fetch_add(1, Ordering::Relaxed);
        let (data_tx, data_rx2) = mpsc::unbounded_channel();
        let (data_tx2, data_rx) = mpsc::channel(DATA_BUFFER_SIZE);
        let tunnel = Self {
            tunnel_id,
            data_tx,
            data_rx,
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
}

impl Drop for OnionTunnel {
    fn drop(&mut self) {
        TUNNEL_COUNT.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Clone)]
pub struct OnionContext {
    peer_provider: PeerProvider,
    n_hops: usize,
    enable_cover: bool,
    events: broadcast::Sender<tunnel::Event>,
    rng: rand::SystemRandom,
}

impl OnionContext {
    /// Builds a new tunnel to `dest` over `n_hops` additional peers.
    /// Performs a handshake with each hop and then spawns a task for handling incoming messages
    pub async fn build_tunnel(&self, dest: TunnelDestination) -> Result<OnionTunnel> {
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

    pub async fn send_cover(&mut self, size: u16) -> Result<()> {
        let size = size as usize;
        let packet_count = (size + protocol::MAX_DATA_SIZE - 1) / protocol::MAX_DATA_SIZE;
        for _ in 0..packet_count {
            self.events
                .send(tunnel::Event::KeepAlive)
                .map_err(|_| anyhow!("No tunnel to send cover traffic on."))?;
        }
        Ok(())
    }

    async fn ensure_cover_tunnel_exists(&mut self) {
        let mut cover_tunnel = None;
        let mut events = self.events.subscribe();
        while let Ok(evt) = events.recv().await {
            if !self.enable_cover || evt != tunnel::Event::Switchover {
                continue;
            }

            cover_tunnel = match (cover_tunnel.take(), TUNNEL_COUNT.load(Ordering::Relaxed)) {
                (None, 0) => self.build_tunnel(TunnelDestination::Random).await.ok(),
                (None, _) => None,
                (Some(_), 0) => unreachable!(),
                (Some(t), 1) => Some(t),
                (Some(_), _) => None,
            }
        }
    }
}

pub struct Incoming {
    incoming: mpsc::Receiver<OnionTunnel>,
}

impl Incoming {
    pub async fn next(&mut self) -> OnionTunnel {
        self.incoming.recv().await.expect("incoming channel closed")
    }
}

struct OnionListener {
    hostkey: Arc<RsaPrivateKey>,
    incoming: mpsc::Sender<OnionTunnel>,
}

impl OnionListener {
    fn new(hostkey: RsaPrivateKey, incoming: mpsc::Sender<OnionTunnel>) -> Self {
        OnionListener {
            hostkey: Arc::new(hostkey),
            incoming,
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
            self.handle_connection(stream?).await;
        }
        Ok(())
    }

    async fn handle_connection(&self, stream: TcpStream) {
        info!("Accepted connection from {:?}", stream.peer_addr().unwrap());
        let socket = OnionSocket::new(stream);
        let host_key = self.hostkey.clone();
        let incoming = self.incoming.clone();

        tokio::spawn(async move {
            let mut handler = match CircuitHandler::init(socket, &host_key, incoming).await {
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

        let (events, _) = broadcast::channel(1);
        let (incoming_tx, incoming_rx) = mpsc::channel(INCOMING_BUFFER_SIZE);

        // creates round handler task
        tokio::spawn({
            let events = events.clone();
            let mut round_handler = RoundHandler {
                events,
                round_duration,
            };
            async move { round_handler.handle().await }
        });

        // create task listening on p2p connections
        tokio::spawn({
            let mut listener = OnionListener::new(hostkey, incoming_tx);
            async move { listener.listen_addr(listen_addr).await }
        });

        let ctx = OnionContext {
            rng: rand::SystemRandom::new(),
            peer_provider,
            n_hops,
            enable_cover,
            events,
        };

        tokio::spawn({
            let mut ctx = ctx.clone();
            async move {
                ctx.ensure_cover_tunnel_exists().await;
            }
        });

        let incoming = Incoming {
            incoming: incoming_rx,
        };
        (ctx, incoming)
    }
}

impl fmt::Debug for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Peer").field(&self.addr).finish()
    }
}
