#![allow(dead_code)]
#![allow(unused_variables)]
use crate::onion::circuit::{CircuitHandler, CircuitId};
use crate::onion::socket::OnionSocket;
use crate::onion::tunnel::{Tunnel, TunnelHandler, TunnelId};
use anyhow::anyhow;
use bytes::Bytes;
use futures::stream::StreamExt;
use log::{info, warn};
use ring::rand;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::stream::Stream;
use tokio::sync::{mpsc, oneshot, Mutex};

pub use crate::onion::crypto::{RsaPrivateKey, RsaPublicKey};
use std::collections::HashMap;

mod onion;
mod utils;

pub type Result<T> = std::result::Result<T, anyhow::Error>;

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

enum Request {
    Build {
        dest: Peer,
        n_hops: usize,
        res: oneshot::Sender<Result<TunnelId>>,
    },
    Data {
        tunnel_id: TunnelId,
        data: Bytes,
    },
}

#[derive(Debug)]
pub enum Event {
    Incoming {
        tunnel_id: TunnelId,
        requests: mpsc::UnboundedSender<Request>,
    },
    Data {
        tunnel_id: TunnelId,
        data: Bytes,
    },
}

#[derive(Clone)]
pub struct Onion {
    requests: mpsc::UnboundedSender<Request>,
}

impl Onion {
    /// Construct a new onion instance.
    /// Returns the constructed instance and an event stream.
    pub fn new<P>(
        listen_addr: SocketAddr,
        hostkey: RsaPrivateKey,
        peer_provider: P,
    ) -> Result<(Self, impl Stream<Item = Event>)>
    where
        P: Stream<Item = Peer> + Unpin + Send + Sync + 'static,
    {
        let (req_tx, req_rx) = mpsc::unbounded_channel();
        let (evt_tx, evt_rx) = mpsc::channel(100);
        let tunnels = Arc::new(Mutex::new(HashMap::new()));

        tokio::spawn({
            let events = evt_tx.clone();
            let tunnels = tunnels.clone();
            let mut round_handler = RoundHandler::new(req_rx, events, peer_provider, tunnels);
            async move { round_handler.next_round().await }
        });

        tokio::spawn({
            let events = evt_tx.clone();
            let tunnels = tunnels.clone();
            let listener = OnionListener::new(hostkey, events, tunnels);
            async move { listener.listen(listen_addr).await }
        });

        let onion = Onion { requests: req_tx };
        Ok((onion, evt_rx))
    }

    pub async fn build_tunnel(&self, dest: Peer, n_hops: usize) -> Result<TunnelId> {
        let (tx, rx) = oneshot::channel();
        let req = Request::Build {
            dest,
            n_hops,
            res: tx,
        };
        self.requests
            .send(req)
            .map_err(|_| anyhow!("Failed to send build request"))
            .unwrap();
        rx.await?
    }

    pub async fn destroy_tunnel(&self, tunnel_id: TunnelId) -> Result<()> {
        Ok(())
    }

    pub async fn send_data(&self, tunnel_id: TunnelId, data: &[u8]) -> Result<()> {
        // big TODO don't allocate
        self.requests
            .send(Request::Data {
                tunnel_id,
                data: data.to_vec().into(),
            })
            .map_err(|_| anyhow!("Failed to send data request"))
            .unwrap();
        Ok(())
    }
}

struct RoundHandler<P> {
    requests: mpsc::UnboundedReceiver<Request>,
    events: mpsc::Sender<Event>,
    rng: rand::SystemRandom,
    peer_provider: P,
    tunnels: Arc<Mutex<HashMap<TunnelId, mpsc::UnboundedSender<Request>>>>,
}

impl<P> RoundHandler<P>
where
    P: Stream<Item = Peer> + Unpin + Send + Sync + 'static,
{
    pub(crate) fn new(
        requests: mpsc::UnboundedReceiver<Request>,
        events: mpsc::Sender<Event>,
        peer_provider: P,
        tunnels: Arc<Mutex<HashMap<TunnelId, mpsc::UnboundedSender<Request>>>>,
    ) -> Self {
        let rng = rand::SystemRandom::new();
        RoundHandler {
            requests,
            events,
            rng,
            peer_provider,
            tunnels,
        }
    }

    /// Tunnels created in one period should be torn down and rebuilt for the next period.
    /// However, Onion should ensure that this is done transparently to the modules, using these
    /// tunnels. This could be achieved by creating a new tunnel before the end of a period and
    /// seamlessly switching over the data stream to the new tunnel once at the end of the current
    /// period. Since the destination peer of both old and new tunnel remains the same, the seamless
    /// switch over is possible.
    pub async fn next_round(&mut self) {
        // TODO proper scheduling
        while let Some(req) = self.requests.recv().await {
            match req {
                Request::Build { dest, n_hops, res } => {
                    res.send(self.handle_build(dest, n_hops).await).unwrap();
                }
                Request::Data { tunnel_id, data } => {
                    let req = Request::Data { tunnel_id, data };
                    // TODO handle errors
                    let _ = self.tunnels.lock().await.get(&tunnel_id).unwrap().send(req);
                }
            }
        }
    }

    /// Builds a new tunnel to `dest` over `n_hops` additional peers.
    /// Performs a handshake with each hop and then spawns a task for handling incoming messages.
    async fn handle_build(&mut self, dest: Peer, n_hops: usize) -> Result<TunnelId> {
        let tunnel_id = Tunnel::random_id(&self.rng);
        let peer = self.random_peer().await?;
        let mut tunnel = Tunnel::init(tunnel_id, &peer, &self.rng).await?;
        for _ in 1..n_hops {
            let peer = self.random_peer().await?;
            tunnel.extend(&peer, &self.rng).await?;
        }
        tunnel.extend(&dest, &self.rng).await?;

        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn({
            let mut handler = TunnelHandler::new(tunnel, rx, self.events.clone());
            async move {
                handler.handle().await.unwrap();
            }
        });
        self.tunnels.lock().await.insert(tunnel_id, tx);
        Ok(tunnel_id)
    }

    async fn random_peer(&mut self) -> Result<Peer> {
        self.peer_provider
            .next()
            .await
            .ok_or(anyhow!("Failed to get random peer"))
    }
}

struct OnionListener {
    hostkey: Arc<RsaPrivateKey>,
    events: mpsc::Sender<Event>,
    tunnels: Arc<Mutex<HashMap<TunnelId, mpsc::UnboundedSender<Request>>>>,
}

impl OnionListener {
    fn new(
        hostkey: RsaPrivateKey,
        events: mpsc::Sender<Event>,
        tunnels: Arc<Mutex<HashMap<TunnelId, mpsc::UnboundedSender<Request>>>>,
    ) -> Self {
        OnionListener {
            hostkey: Arc::new(hostkey),
            events,
            tunnels,
        }
    }

    async fn listen(&self, addr: SocketAddr) -> Result<()> {
        let mut listener = TcpListener::bind(addr).await?;
        info!(
            "Listening for P2P connections on {:?}",
            listener.local_addr()
        );
        let mut incoming = listener.incoming();
        while let Some(stream) = incoming.next().await {
            let socket = OnionSocket::new(stream?);
            let hostkey = self.hostkey.clone();
            let (events_tx, mut events_rx) = mpsc::channel(100);
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

            // FIXME don't block here
            if let Some(Event::Incoming {
                tunnel_id,
                requests,
            }) = events_rx.recv().await
            {
                self.tunnels.lock().await.insert(tunnel_id, requests);
            }
        }

        Ok(())
    }
}
