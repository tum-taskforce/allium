#![allow(dead_code)]
#![allow(unused_variables)]
use crate::circuit::CircuitHandler;
use crate::circuit::{CircuitHandler, CircuitId};
use crate::socket::OnionSocket;
use crate::tunnel::{Tunnel, TunnelId};
use anyhow::anyhow;
use bytes::Bytes;
use futures::stream::StreamExt;
use log::{info, warn};
use ring::{rand, signature};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::stream::Stream;
use tokio::sync::{mpsc, oneshot};

mod circuit;
mod onion_protocol;
mod socket;
mod tunnel;
mod utils;

#[cfg(test)]
mod tests;

pub type Result<T> = std::result::Result<T, anyhow::Error>;

pub struct Peer {
    addr: SocketAddr,
    hostkey: signature::UnparsedPublicKey<Bytes>,
}

impl Peer {
    pub fn new(addr: SocketAddr, hostkey: Vec<u8>) -> Self {
        let hostkey = signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            hostkey.into(),
        );
        Peer { addr, hostkey }
    }
}

enum Request {
    Build {
        dest: Peer,
        n_hops: usize,
        res: oneshot::Sender<Result<TunnelId>>,
    },
}

pub struct Onion {
    requests: mpsc::UnboundedSender<Request>,
    hostkey: signature::RsaKeyPair,
}

impl Onion {
    /// Construct a new onion instance.
    /// Returns Err if the supplied hostkey is invalid.
    pub fn new<P>(hostkey: &[u8], peer_provider: P) -> Result<Self>
    where
        P: Stream<Item = Peer> + Unpin + Send + Sync + 'static,
    {
        let hostkey = signature::RsaKeyPair::from_pkcs8(hostkey)?;
        let (tx, rx) = mpsc::unbounded_channel();
        let round_handler = RoundHandler {
            requests: rx,
            rng: rand::SystemRandom::new(),
            peer_provider,
        };

        Ok(Onion {
            requests: tx,
            hostkey,
        })
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
        Ok(())
    }

    pub async fn listen(self: Arc<Self>, addr: SocketAddr) -> Result<()> {
        let mut listener = TcpListener::bind(addr).await?;
        info!(
            "Listening for P2P connections on {:?}",
            listener.local_addr()
        );
        let mut incoming = listener.incoming();
        while let Some(stream) = incoming.next().await {
            let socket = OnionSocket::new(stream?);
            let onion = self.clone();
            tokio::spawn(async move {
                let mut handler = match CircuitHandler::init(socket, &onion.hostkey).await {
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
        Ok(())
    }
}

struct RoundHandler<P> {
    requests: mpsc::UnboundedReceiver<Request>,
    rng: rand::SystemRandom,
    peer_provider: P,
}

impl<P> RoundHandler<P>
where
    P: Stream<Item = Peer> + Unpin + Send + Sync + 'static,
{
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
            }
        }
    }

    async fn handle_build(&mut self, dest: Peer, n_hops: usize) -> Result<TunnelId> {
        let tunnel_id = Tunnel::random_id(&self.rng);
        let peer = self.random_peer().await?;
        let mut tunnel = Tunnel::init(tunnel_id, &peer, &self.rng).await?;
        for _ in 1..n_hops {
            let peer = self.random_peer().await?;
            tunnel.extend(&peer, &self.rng).await?;
        }
        tunnel.extend(&dest, &self.rng).await?;
        // TODO listen for incoming data
        Ok(tunnel_id)
    }

    async fn random_peer(&mut self) -> Result<Peer> {
        self.peer_provider
            .next()
            .await
            .ok_or(anyhow!("Failed to get random peer"))
    }
}
