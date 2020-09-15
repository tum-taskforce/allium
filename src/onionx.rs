use super::Result;
use crate::onion::tunnel;
use crate::onion::tunnel::{TunnelBuilder, TunnelDestination, TunnelHandler};
use crate::{Peer, PeerProvider, TunnelId};
use anyhow::anyhow;
use bytes::Bytes;
use ring::rand;
use tokio::sync::{broadcast, mpsc, oneshot};

const DATA_BUFFER_SIZE: usize = 100;

pub struct OnionTunnel {
    tunnel_id: TunnelId,
    data_tx: mpsc::UnboundedSender<Bytes>,
    data_rx: mpsc::Receiver<Bytes>,
}

impl OnionTunnel {
    pub(crate) fn new(
        tunnel_id: TunnelId,
    ) -> (Self, mpsc::Sender<Bytes>, mpsc::UnboundedReceiver<Bytes>) {
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

    pub fn write(&self, buf: Bytes) -> Result<()> {
        // TODO split buf
        self.data_tx
            .send(buf)
            .map_err(|_| anyhow!("Connection closed."))
    }
}

pub struct OnionContext {
    incoming: mpsc::Receiver<OnionTunnel>,
    rng: rand::SystemRandom,
    peer_provider: PeerProvider,
    n_hops: usize,
    events: broadcast::Sender<tunnel::Event>,
}

impl OnionContext {
    pub fn new() -> Self {
        unimplemented!()
    }

    pub async fn build_tunnel(&mut self, peer: Peer) -> Result<OnionTunnel> {
        let tunnel_id = tunnel::random_id(&self.rng);
        let mut builder = TunnelBuilder::new(
            tunnel_id,
            TunnelDestination::Fixed(peer),
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

    pub async fn next_incoming(&mut self) -> OnionTunnel {
        self.incoming.recv().await.expect("incoming channel closed")
    }
}
