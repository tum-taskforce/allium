use crate::{Peer, PeerProvider, Result};
use anyhow::anyhow;
use bytes::Bytes;
use circuit::CircuitHandler;
use crypto::RsaPrivateKey;
use log::{debug, info, trace, warn};
use socket::OnionSocket;
use std::collections::{hash_map, HashMap};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::{cmp, fmt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::time::{self, Duration};
use tunnel::{Target, TunnelBuilder, TunnelHandler, TunnelId};

pub(crate) mod circuit;
pub(crate) mod crypto;
pub(crate) mod protocol;
pub(crate) mod socket;
pub(crate) mod tunnel;

#[cfg(test)]
mod tests;

const DEFAULT_ROUND_DURATION: Duration = Duration::from_secs(30);
const DEFAULT_HOPS: usize = 2;

const DATA_BUFFER_SIZE: usize = 100;
const INCOMING_BUFFER_SIZE: usize = 100;

static TUNNEL_COUNT: AtomicUsize = AtomicUsize::new(0);

/// A tunnel endpoint. This type persists over tunnel reconstructions.
///
/// Use [`OnionContext::build_tunnel`] to build a new tunnel.
///
/// We differentiate persistent and ephemeral tunnels.
/// A persistent tunnel is characterized only by its ID and its endpoints, while an ephemeral
/// tunnel is specific to the intermediate hops.
/// As a user, you will only deal with persistent tunnels, which forward data to and from
/// periodically rebuilt ephemeral tunnels.
pub struct Tunnel {
    tunnel_id: TunnelId,
    data_tx: mpsc::UnboundedSender<Bytes>,
    data_rx: mpsc::Receiver<Bytes>,
    counted: bool,
}

impl Tunnel {
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

    /// Receive data from the remote peer.
    ///
    /// Returns an error if the connection was closed.
    pub async fn read(&mut self) -> Result<Bytes> {
        self.data_rx
            .recv()
            .await
            .ok_or(anyhow!("Connection closed."))
    }

    /// Send data to the remote peer.
    ///
    /// The data may be split across multiple messages if it is too large to fit into a single one.
    ///
    /// Returns an error if the connection was closed.
    pub fn write(&self, mut buf: Bytes) -> Result<()> {
        while !buf.is_empty() {
            let part = buf.split_to(cmp::min(protocol::MAX_DATA_SIZE, buf.len()));
            self.data_tx
                .send(part)
                .map_err(|_| anyhow!("Connection closed."))?;
        }
        Ok(())
    }

    /// Returns the unique id of this tunnel.
    pub fn id(&self) -> TunnelId {
        self.tunnel_id
    }

    /// Create an additional write handle to this tunnel.
    pub fn writer(&self) -> TunnelWriter {
        TunnelWriter {
            tunnel_id: self.tunnel_id,
            data_tx: self.data_tx.clone(),
        }
    }

    async fn forward_data(
        mut self,
        mut tunnel_rx: mpsc::Receiver<Tunnel>,
        data_tx: mpsc::Sender<Bytes>,
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

impl fmt::Debug for Tunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OnionTunnel")
            .field("id", &self.tunnel_id)
            .finish()
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        if self.counted {
            let c = TUNNEL_COUNT.fetch_sub(1, Ordering::Relaxed);
            debug!("Dropping tunnel with ID {}, count: {}", self.id(), c);
        } else {
            debug!("Dropping tunnel with ID {}", self.id());
        }
    }
}

/// A write handle to a [`Tunnel`].
///
/// Each tunnel may have arbitrarily many [`TunnelWriter`]s.
/// This is useful because this type implements [`Clone`], [`Send`] and [`Sync`] and can thus
/// safely be shared across threads.
#[derive(Clone)]
pub struct TunnelWriter {
    tunnel_id: TunnelId,
    data_tx: mpsc::UnboundedSender<Bytes>,
}

impl TunnelWriter {
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

impl fmt::Debug for TunnelWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OnionTunnelWriter")
            .field("id", &self.tunnel_id)
            .finish()
    }
}

/// A handle to the underlying onion router allowing the construction of new tunnels.
///
/// Use [`OnionBuilder`] to configure and start a new onion router instance.
/// This type implements [`Clone`], [`Send`] and [`Sync`], so it can be shared across threads.
#[derive(Clone)]
pub struct OnionContext {
    peer_provider: PeerProvider,
    n_hops: usize,
    events: broadcast::Sender<tunnel::Event>,
    cover_tunnel: TunnelWriter,
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
            peer_provider,
            n_hops,
            events,
            cover_tunnel: TunnelWriter {
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

    /// Builds a new tunnel to `dest`.
    pub async fn build_tunnel(&self, dest: Peer) -> Result<Tunnel> {
        self.build_tunnel_internal(Target::Peer(dest)).await
    }

    async fn build_tunnel_internal(&self, dest: Target) -> Result<Tunnel> {
        info!("Building tunnel to {:?}", dest);
        let tunnel_id = tunnel::random_id();
        let mut builder =
            TunnelBuilder::new(tunnel_id, dest, self.n_hops, self.peer_provider.clone());

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

    /// Send cover data with a fake payload of the given size.
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
    cover_tunnel: Option<Tunnel>,
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

/// A stream of incoming tunnel connections.
pub struct OnionIncoming {
    incoming: mpsc::Receiver<Tunnel>,
}

impl OnionIncoming {
    /// Returns a [`Tunnel`] handle once a new incoming connection is made.
    pub async fn next(&mut self) -> Option<Tunnel> {
        self.incoming.recv().await
    }
}

#[derive(Clone)]
struct OnionListener {
    hostkey: Arc<RsaPrivateKey>,
    incoming: mpsc::Sender<Tunnel>,
    tunnels: Arc<Mutex<HashMap<TunnelId, mpsc::Sender<Tunnel>>>>,
}

impl OnionListener {
    fn new(hostkey: RsaPrivateKey, incoming: mpsc::Sender<Tunnel>) -> Self {
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

    async fn listen(&mut self, listener: TcpListener) -> Result<()> {
        info!(
            "Listening for P2P connections on {:?}",
            listener.local_addr()
        );

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            info!("Accepted connection from {:?}", peer_addr);
            let mut handler = self.clone();
            tokio::spawn(async move {
                handler.handle_connection(stream).await;
            });
        }
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

    async fn handle_incoming(&mut self, tunnel: Tunnel) {
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

    async fn handle_new_tunnel(&mut self, tunnel: Tunnel) -> Result<mpsc::Sender<Tunnel>> {
        let (tunnel_tx, tunnel_rx) = mpsc::channel(1);
        let (e_tunnel, e_data_tx, e_data_rx) = Tunnel::new(tunnel.id(), true);
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

/// Used for configuring and starting new onion router instances.
pub struct OnionBuilder {
    listen_addr: SocketAddr,
    hostkey: RsaPrivateKey,
    peer_provider: PeerProvider,
    enable_cover: bool,
    n_hops: usize,
    round_duration: Duration,
}

impl OnionBuilder {
    /// Initialized the construction of a new onion router instance.
    ///
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

    /// Sets whether cover traffic should be enabled.
    ///
    /// If cover traffic is disabled all calls to [`OnionContext::send_cover`] will fail.
    /// The default value is true.
    pub fn enable_cover_traffic(mut self, enable: bool) -> Self {
        self.enable_cover = enable;
        self
    }

    /// Sets the number of additional hops per tunnel, not counting the two endpoints.
    ///
    /// The default value is 2.
    pub fn set_hops_per_tunnel(mut self, n_hops: usize) -> Self {
        self.n_hops = n_hops;
        self
    }

    /// Sets the amount of time after which tunnels will be rebuilt.
    ///
    /// The default value is 30 seconds.
    pub fn set_round_duration(mut self, dur: Duration) -> Self {
        self.round_duration = dur;
        self
    }

    /// Starts the onion router.
    ///
    /// Returns a [`OnionContext`] handle used for building new tunnels and a stream of incoming
    /// connections [`OnionIncoming`].
    pub fn start(self) -> (OnionContext, OnionIncoming) {
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

        let incoming = OnionIncoming {
            incoming: incoming_rx,
        };
        (ctx, incoming)
    }
}
