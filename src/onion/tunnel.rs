use crate::onion::circuit::Circuit;
use crate::onion::crypto::{self, EphemeralPrivateKey, SessionKey};
use crate::onion::protocol::{
    CircuitOpaque, CircuitOpaqueBytes, TryFromBytesExt, TunnelRequest, VerifyKey,
};
use crate::onion::socket::{OnionSocket, OnionSocketError, SocketResult};
use crate::OnionTunnel;
use crate::Peer;
use crate::{PeerProvider, Result};
use anyhow::{anyhow, Context};
use bytes::Bytes;
use log::{trace, warn};
use std::fmt;
use std::mem;
use std::ops::Deref;
use std::sync::Arc;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};

const MAX_PEER_FAILURES: usize = 10;

pub type TunnelId = u32;

#[derive(Error, Debug)]
pub(crate) enum TunnelError {
    /// The requested operation could not be run to completion, but the tunnel has a consistent
    /// state that can be expanded on
    #[error("Tunnel operation could not be completed")]
    Incomplete,
    /// The requested operation could not be completed and the tunnel is left in a broken state
    /// that needs to be cleaned up. This may be triggered by an undecryptable `OPAQUE` message,
    /// or a `TEARDOWN` message from the first hop.
    #[error("Tunnel operation caused the tunnel to break")]
    Broken(Option<OnionSocketError>),
}

impl From<OnionSocketError> for TunnelError {
    fn from(e: OnionSocketError) -> Self {
        match e {
            OnionSocketError::Peer => TunnelError::Incomplete,
            e => TunnelError::Broken(Some(e)),
        }
    }
}

pub(crate) type TunnelResult<T> = std::result::Result<T, TunnelError>;

#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) enum Event {
    Switchover,
    Destroy,
    KeepAlive,
}

/// Represents the tunnel controller view of a tunnel.
/// Manages the first circuit and stores all session keys in encryption order.
pub(crate) struct Tunnel {
    pub(crate) id: TunnelId,
    out_circuit: Circuit,
    session_keys: Vec<SessionKey>,
}

impl Tunnel {
    /// Performs a circuit handshake with the first hop (peer).
    pub(crate) async fn init(id: TunnelId, peer: &Peer) -> Result<Self> {
        trace!("Creating tunnel {} to peer {}", id, &peer.addr);
        let (private_key, key) = crypto::generate_ephemeral_keypair();

        let circuit_id = Circuit::random_id();
        let stream = TcpStream::connect(peer.addr)
            .await
            .context("Could not connect to peer")?;
        let mut socket = OnionSocket::new(stream);
        let peer_key = socket
            .initiate_handshake(circuit_id, key)
            .await
            .context("Handshake failed while initializing new tunnel")?;

        let secret = Tunnel::derive_secret(&peer, private_key, peer_key)
            .context("SessionKey derivation failed")?;
        Ok(Self {
            id,
            out_circuit: Circuit::new(circuit_id, socket),
            session_keys: vec![secret],
        })
    }

    fn derive_secret(
        peer: &&Peer,
        private_key: EphemeralPrivateKey,
        peer_key: VerifyKey,
    ) -> Result<SessionKey> {
        let peer_key = peer_key
            .verify(&peer.hostkey)
            .context("Could not verify peer public key")?;
        let secret = SessionKey::from_key_exchange(private_key, &peer_key)?;
        Ok(secret)
    }

    /// Returns the length of a tunnel. The result of this function may be used with caution if the
    /// tunnel is in a broken state.
    pub(crate) fn len(&self) -> usize {
        self.session_keys.len()
    }

    /// Performs a key exchange with the given peer and extends the tunnel with a new hop
    pub(crate) async fn extend(&mut self, peer: &Peer) -> TunnelResult<()> {
        trace!("Extending tunnel {} to peer {}", self.id, &peer.addr);
        let (private_key, key) = crypto::generate_ephemeral_keypair();

        let peer_key = self
            .out_circuit
            .socket()
            .await
            .initiate_tunnel_handshake(self.out_circuit.id, peer.addr, key, &self.session_keys)
            .await?;

        // Any failure because of any incorrect secret answer should not cause our tunnel to become corrupted
        if let Ok(secret) = Tunnel::derive_secret(&peer, private_key, peer_key) {
            self.session_keys.insert(0, secret);
            Ok(())
        } else {
            // key derivation failed, the final hop needs to be truncated
            // if the truncate fails too, the tunnel is broken
            self.truncate(0)
                .await
                .map_err(|_| TunnelError::Broken(None))?;
            Err(TunnelError::Incomplete)
        }
    }

    /// Truncates the tunnel by `n` hops with one `TUNNEL TRUNCATE` message. If message returns with
    /// an error code, `Incomplete` will be returned.
    ///
    /// Returns `Incomplete` if the resulting hop count would be less than one.
    pub(crate) async fn truncate(&mut self, n: usize) -> TunnelResult<()> {
        if n >= self.session_keys.len() {
            return Err(TunnelError::Incomplete);
        }

        self.out_circuit
            .socket()
            .await
            .truncate_tunnel(self.out_circuit.id, &self.session_keys[n..])
            .await?;

        for _ in 0..n {
            self.session_keys.remove(0);
        }
        Ok(())
    }

    /// Begins a data connection with the last hop in the tunnel
    ///
    /// If there is already a tunnel connected to the same peer with the same `TunnelId`, the
    /// targeted peer should no longer use the old tunnel for communication and is expected to send a
    /// `TUNNEL END` message through the old tunnel. This works like an implicit `TUNNEL END` to the
    /// remote tunnel.
    ///
    /// After sending a `TUNNEL BEGIN` message to the other endpoint of a tunnel, the tunnel should
    /// be monitored for `TUNNEL DATA` messages, as long as no explicit `TUNNEL END` message is
    /// received, or any explicit or implicit `TUNNEL END` message is sent. After sending an
    /// implicit `TUNNEL END` message by calling this function (as mentioned above), the old tunnel
    /// should be monitored for any incoming `TUNNEL DATA` packets and a final `TUNNEL END` packet
    /// before tearing down the old tunnel. Be aware that the other endpoint peer should not be
    /// allowed to use the old tunnel indefinitely despite receiving a `TUNNEL END` packet. Any old
    /// tunnel that has been replaced should only have finite lifetime.
    pub(crate) async fn begin(&self) -> TunnelResult<()> {
        self.out_circuit
            .socket()
            .await
            .begin(self.out_circuit.id, self.id, &self.session_keys)
            .await?;
        Ok(())
    }

    /// Ends a data connection with the last hop in the tunnel
    pub(crate) async fn end(&self) -> TunnelResult<()> {
        self.out_circuit
            .socket()
            .await
            .end(self.out_circuit.id, self.id, &self.session_keys)
            .await?;
        Ok(())
    }

    /// Sends a `TUNNEL KEEPALIVE` packet on this tunnel to the last hop, affecting every single
    /// hop
    ///
    /// This can be used to prevent a tunnel from timing out or to send cover traffic to the final
    /// hop. This may also be used to check the integrity, since any failure would cause the hops
    /// to initiate a teardown on the tunnel.
    pub(crate) async fn keep_alive(&self) -> TunnelResult<()> {
        self.out_circuit
            .socket()
            .await
            .send_keep_alive(self.out_circuit.id, &self.session_keys)
            .await?;
        Ok(())
    }

    pub(crate) async fn _truncate_to_length(&mut self, n_hops: usize) -> TunnelResult<()> {
        let mut num_fails = 0;

        while self.session_keys.len() > n_hops + 1 {
            match self.truncate(1).await {
                Err(TunnelError::Broken(e)) => {
                    // do not try to fix this error to prevent endless looping
                    return Err(TunnelError::Broken(e));
                }
                Err(TunnelError::Incomplete) => {
                    num_fails += 1;
                    if num_fails >= MAX_PEER_FAILURES {
                        return Err(TunnelError::Incomplete);
                    }
                }
                Ok(_) => {}
            }
        }

        Ok(())
    }

    async fn unbuild(&self) {
        // TODO graceful deconstruction
        self.teardown().await;
    }

    async fn teardown(&self) {
        self.out_circuit.teardown_with_timeout().await;
    }
}

pub fn random_id() -> TunnelId {
    // FIXME an attacker may fill up all ids
    let mut id_buf = [0u8; 4];
    crypto::fill_random(&mut id_buf);
    u32::from_le_bytes(id_buf)
}

#[derive(Clone, Debug)]
pub enum Target {
    Peer(Peer),
    Random,
}

#[derive(Clone)]
pub(crate) struct TunnelBuilder {
    tunnel_id: TunnelId,
    dest: Target,
    n_hops: usize,
    peer_provider: PeerProvider,
}

impl TunnelBuilder {
    pub(crate) fn new(
        tunnel_id: TunnelId,
        dest: Target,
        n_hops: usize,
        peer_provider: PeerProvider,
    ) -> Self {
        TunnelBuilder {
            tunnel_id,
            dest,
            n_hops,
            peer_provider,
        }
    }

    /// Tries to extend this tunnel to intermediate hop count `n_hops` and final hop `final_peer`.
    ///
    /// The peers provided by `peer_provider` will be used as a source for the intermediate hops,
    /// the final hop at index `n` will be `final_peer`.
    ///
    /// This function does not check whether the peers provided by `peer_provider` are particularity
    /// secure. In order to preserve anonymity, there should never be two consecutive hops to the
    /// same peer. Also, `peer_provider` should produce peers in a way that potentially malicious
    /// peers with shared knowledge of circuits should be returned with a low probability (or with
    /// equal probability to any other peer) to prevent the tunnel from becoming compromised.
    ///
    /// Even if there is a high failure-rate among peers, the `peer_provider` should be able to
    /// generate a secure stream of peers.
    pub(crate) async fn build(&mut self) -> Result<Tunnel> {
        let mut tunnel = None;
        for _ in 0..MAX_PEER_FAILURES {
            tunnel = match (tunnel.take(), &self.dest) {
                (None, Target::Peer(peer)) if self.n_hops == 0 => {
                    Tunnel::init(self.tunnel_id, peer)
                        .await
                        .map_err(|e| warn!("Error while building tunnel: {:?}", e))
                        .ok()
                }
                (None, _) => {
                    let peer = self
                        .peer_provider
                        .random_peer()
                        .await
                        .context(anyhow!("Failed to get random peer"))?;
                    Tunnel::init(self.tunnel_id, &peer)
                        .await
                        .map_err(|e| warn!("Error while building tunnel: {:?}", e))
                        .ok()
                }
                (Some(mut tunnel), Target::Peer(peer)) if tunnel.len() == self.n_hops => {
                    match tunnel.extend(peer).await {
                        Err(TunnelError::Broken(e)) => {
                            warn!("Error while building tunnel: {:?}", e);
                            tunnel.teardown().await;
                            None
                        }
                        Err(TunnelError::Incomplete) => Some(tunnel),
                        Ok(_) => Some(tunnel),
                    }
                }
                (Some(mut tunnel), _) if tunnel.len() <= self.n_hops => {
                    let peer = self
                        .peer_provider
                        .random_peer()
                        .await
                        .context(anyhow!("Failed to get random peer"))?;

                    match tunnel.extend(&peer).await {
                        Err(TunnelError::Broken(e)) => {
                            warn!("Error while building tunnel: {:?}", e);
                            tunnel.teardown().await;
                            None
                        }
                        Err(TunnelError::Incomplete) => Some(tunnel),
                        Ok(_) => Some(tunnel),
                    }
                }
                (Some(tunnel), _) => return Ok(tunnel),
            }
        }
        Err(anyhow!("failed to build tunnel"))
    }
}

/// Manages a tunnel after its creation.
pub(crate) struct TunnelHandler {
    tunnel: Tunnel,
    next_tunnel: Arc<Mutex<Option<Tunnel>>>,
    state: State,
    events: broadcast::Receiver<Event>,
    builder: TunnelBuilder,
}

pub(crate) enum State {
    Building {
        ready: oneshot::Sender<Result<OnionTunnel>>,
    },
    Ready {
        data_tx: mpsc::Sender<Bytes>,
        data_rx: mpsc::UnboundedReceiver<Bytes>,
    },
    Destroying,
    Destroyed,
}

impl TunnelHandler {
    pub(crate) fn new(
        first_tunnel: Tunnel,
        tunnel_builder: TunnelBuilder,
        events: broadcast::Receiver<Event>,
        ready: oneshot::Sender<Result<OnionTunnel>>,
    ) -> Self {
        TunnelHandler {
            tunnel: first_tunnel,
            next_tunnel: Arc::new(Mutex::new(None)),
            state: State::Building { ready },
            events,
            builder: tunnel_builder,
        }
    }

    pub(crate) async fn handle(&mut self) {
        trace!(
            "Starting TunnelHandler for tunnel {:?}",
            self.builder.tunnel_id
        );
        if let Err(e) = self.try_handle().await {
            warn!("Error in TunnelHandler: {}", e);
            self.state = State::Destroyed;
            self.tunnel.teardown().await;
        }
    }

    async fn try_handle(&mut self) -> Result<()> {
        loop {
            match &mut self.state {
                State::Building { .. } | State::Destroying => {
                    tokio::select! {
                        Ok(evt) = self.events.recv() => {
                            self.handle_event(evt).await?;
                        }
                    }
                }
                State::Ready { data_rx, .. } => {
                    tokio::select! {
                        data = data_rx.recv() => {
                            self.handle_data(data).await?;
                        }
                        msg = self.tunnel.out_circuit.accept_opaque() => {
                            self.handle_tunnel_message(msg).await?;
                        }
                        Ok(evt) = self.events.recv() => {
                            self.handle_event(evt).await?;
                        }
                    }
                }
                State::Destroyed => return Ok(()),
            }
        }
    }

    async fn handle_tunnel_message(
        &mut self,
        msg: SocketResult<CircuitOpaque<CircuitOpaqueBytes>>,
    ) -> Result<()> {
        // no event in case of error
        let mut msg = msg?;
        // no event in case of error
        msg.decrypt(self.tunnel.session_keys.iter().rev())?;
        let tunnel_msg = TunnelRequest::read_with_digest_from(&mut msg.payload.bytes);
        match tunnel_msg {
            Ok(TunnelRequest::Data(tunnel_id, data)) if tunnel_id == self.tunnel.id => {
                if let State::Ready { data_tx, .. } = &mut self.state {
                    let _ = data_tx.send(data).await; // TODO handle closed
                }
                Ok(())
            }
            Ok(TunnelRequest::End(_tunnel_id)) => {
                // maybe reconstruct tunnel
                Err(anyhow!("Tunnel broke due to unexpected End"))
            }
            _ => {
                // invalid request or broken digest
                Err(anyhow!(
                    "Tunnel broke due to invalid request or broken digest"
                ))
            }
        }
    }

    async fn handle_data(&mut self, data: Option<Bytes>) -> Result<()> {
        // state is assumed to be Ready
        debug_assert!(matches!(&self.state, State::Ready { .. }));

        match data {
            Some(data) => {
                let circuit_id = self.tunnel.out_circuit.id;
                let tunnel_id = self.tunnel.id;
                self.tunnel
                    .out_circuit
                    .socket()
                    .await
                    .send_data(circuit_id, tunnel_id, data, &self.tunnel.session_keys)
                    .await?;
            }
            None => self.state = State::Destroying,
        }
        Ok(())
    }

    async fn handle_event(&mut self, evt: Event) -> Result<()> {
        trace!(
            "TunnelHandler: handling event {:?} (state = {:?})",
            evt,
            self.state
        );
        let mut state = State::Destroyed; // arbitrary
        std::mem::swap(&mut self.state, &mut state);
        self.state = match (evt, state) {
            (Event::Switchover, State::Building { ready }) => {
                self.tunnel.begin().await?;
                let (tunnel, data_tx, data_rx) = OnionTunnel::new(self.tunnel.id, true);
                let _ = ready.send(Ok(tunnel)); // TODO handle closed
                self.spawn_next_tunnel_task();
                State::Ready { data_tx, data_rx }
            }
            (Event::Switchover, State::Ready { data_tx, data_rx }) => {
                let mut new_tunnel = self
                    .next_tunnel
                    .lock()
                    .await
                    .take()
                    .ok_or_else(|| anyhow!("Switchover failed: no next tunnel"))?;

                mem::swap(&mut self.tunnel, &mut new_tunnel);
                let old_tunnel = new_tunnel;
                self.tunnel.begin().await?;
                old_tunnel.end().await?;

                self.spawn_next_tunnel_task();
                tokio::spawn(async move {
                    old_tunnel.unbuild().await;
                });
                State::Ready { data_tx, data_rx }
            }
            (Event::Switchover, State::Destroying) => {
                self.tunnel.end().await?;
                self.tunnel.unbuild().await;
                if let Some(next_tunnel) = self.next_tunnel.lock().await.deref() {
                    next_tunnel.unbuild().await;
                }
                State::Destroyed
            }
            (Event::Destroy, State::Ready { .. }) => State::Destroying,
            (Event::KeepAlive, State::Destroyed) => State::Destroyed, // ignore this event
            (Event::KeepAlive, state) => {
                self.tunnel.keep_alive().await?;
                if let Some(next_tunnel) = self.next_tunnel.lock().await.deref() {
                    next_tunnel.keep_alive().await?;
                }
                state
            } // ignore this event
            _ => return Err(anyhow!("Illegal TunnelHandler state")),
        };
        Ok(())
    }

    fn spawn_next_tunnel_task(&self) {
        tokio::spawn({
            let next_tunnel = self.next_tunnel.clone();
            let mut builder = self.builder.clone();
            async move {
                match builder.build().await {
                    Ok(new_tunnel) => {
                        // TODO only replace if not destroyed
                        next_tunnel.lock().await.replace(new_tunnel);
                    }
                    Err(e) => warn!("Rebuilding of a tunnel failed: {}", e),
                };
            }
        });
    }
}

impl fmt::Debug for Tunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tunnel")
            .field("id", &self.id)
            .field("out_circuit", &self.out_circuit)
            .field("len", &self.len())
            .finish()
    }
}

impl fmt::Debug for TunnelBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelBuilder")
            .field("tunnel_id", &self.tunnel_id)
            .field("dest", &self.dest)
            .field("n_hops", &self.n_hops)
            .finish()
    }
}

impl fmt::Debug for TunnelHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelHandler")
            .field("tunnel", &self.tunnel)
            .field("state", &self.state)
            .field("builder", &self.builder)
            .finish()
    }
}

impl fmt::Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            State::Building { .. } => f.debug_struct("Building").finish(),
            State::Ready { .. } => f.debug_struct("Ready").finish(),
            State::Destroying => f.debug_struct("Destroying").finish(),
            State::Destroyed => f.debug_struct("Destroyed").finish(),
        }
    }
}
