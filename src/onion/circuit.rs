use crate::onion::crypto::{self, EphemeralPublicKey, SessionKey};
use crate::onion::protocol::{
    CircuitOpaque, CircuitOpaqueBytes, SignKey, TryFromBytesExt, TunnelExtendedError,
    TunnelProtocolError, TunnelRequest, TunnelTruncatedError, VerifyKey,
};
use crate::onion::socket::{OnionSocket, OnionSocketError, SocketResult};
use crate::onion::tunnel::TunnelId;
use crate::OnionTunnel;
use crate::{Result, RsaPrivateKey};
use anyhow::anyhow;
use anyhow::Context;
use bytes::Bytes;
use log::trace;
use log::warn;
use ring::rand;
use ring::rand::SecureRandom;
use std::fmt;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex, MutexGuard};
use tokio::time;
use tokio::time::Duration;

/// timeout applied if there is no traffic on a circuit
pub(crate) const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// timeout applied for a teardown operation
const TEARDOWN_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) type CircuitId = u16;

/// A Circuit is a direct connection between two peers.
/// The struct stores its unique ID and a socket.
pub(crate) struct Circuit {
    pub(crate) id: CircuitId,
    pub(crate) socket: Mutex<OnionSocket<TcpStream>>,
}

impl Circuit {
    pub(crate) fn new(id: CircuitId, socket: OnionSocket<TcpStream>) -> Self {
        Circuit {
            id,
            socket: Mutex::new(socket),
        }
    }

    pub(crate) async fn socket(&self) -> MutexGuard<'_, OnionSocket<TcpStream>> {
        self.socket.lock().await
    }

    pub(crate) async fn accept_opaque(&self) -> SocketResult<CircuitOpaque<CircuitOpaqueBytes>> {
        self.socket().await.accept_opaque().await
    }

    pub(crate) async fn teardown_with_timeout(&self, rng: &rand::SystemRandom) {
        match time::timeout(TEARDOWN_TIMEOUT, {
            // NOTE: Ignore any errors
            self.socket().await.teardown(self.id, rng)
        })
        .await
        {
            Err(e) => warn!("{}", e),
            Ok(Err(e)) => warn!("{}", e),
            _ => {}
        };
    }

    /// Generates a random circuit ID which is assumed to be unique.
    pub(crate) fn random_id(rng: &rand::SystemRandom) -> CircuitId {
        // FIXME an attacker may fill up all ids
        let mut id_buf = [0u8; 2];
        rng.fill(&mut id_buf).unwrap();
        u16::from_le_bytes(id_buf)
    }
}

/// A CircuitHandler is created for each incoming circuit connection (in_circuit), after negotiating a session key.
/// It implements the circuit layer logic.
/// The events channel is used to communicate with the layer above.
/// It can be in one of three states:
///   * Default: Final hop of a tunnel. Waiting to be either extended or designated as tunnel endpoint.
///   * Router: Intermediate hop of a tunnel.
///   * Endpoint: Destination and final hop of a tunnel.
pub(crate) struct CircuitHandler {
    in_circuit: Circuit,
    session_key: [SessionKey; 1],
    incoming: mpsc::Sender<OnionTunnel>,
    rng: rand::SystemRandom,
    state: State,
}

pub(crate) enum State {
    Default,
    Router {
        out_circuit: Circuit,
    },
    /// Stores the receiving end of a channel which is used by higher layers to control the tunnel.
    Endpoint {
        tunnel_id: TunnelId,
        data_rx: mpsc::UnboundedReceiver<Bytes>,
        data_tx: mpsc::Sender<Bytes>,
    },
}

impl CircuitHandler {
    /// Performs the reacting part of a circuit handshake.
    /// If successful a session key with the tunnel controller (tunnel-building peer) is agreed on.
    pub(crate) async fn init(
        mut socket: OnionSocket<TcpStream>,
        host_key: &RsaPrivateKey,
        incoming: mpsc::Sender<OnionTunnel>,
    ) -> Result<Self> {
        trace!("Accepting handshake from {:?}", socket.peer_addr());
        let (circuit_id, peer_key) = socket
            .accept_handshake()
            .await
            .context("Handshake with new connection failed")?;

        let rng = rand::SystemRandom::new();
        let (private_key, key) = crypto::generate_ephemeral_keypair(&rng);
        let key = SignKey::sign(&key, host_key, &rng);

        socket
            .finalize_handshake(circuit_id, key, &rng)
            .await
            .context("Could not finalize handshake")?;

        if let Ok(secret) = SessionKey::from_key_exchange(private_key, &peer_key) {
            let in_circuit = Circuit::new(circuit_id, socket);
            Ok(Self {
                in_circuit,
                session_key: [secret],
                incoming,
                rng,
                state: State::Default,
            })
        } else {
            trace!("Incoming handshake failed post-handshake: unable to derive key");
            let _ = time::timeout(TEARDOWN_TIMEOUT, socket.teardown(circuit_id, &rng)).await;
            Err(anyhow!(
                "Incoming handshake failed post-handshake: unable to derive key"
            ))
        }
    }

    /// Handles messages and requests depending on the current state in a loop.
    pub(crate) async fn handle(&mut self) -> Result<()> {
        trace!("CircuitHandler started for circuit {:?}", self.in_circuit);
        // main accept loop
        match self.try_handle().await {
            Ok(_) => Ok(()),
            Err(e) => {
                // finally tear down the circuits
                self.teardown_all().await;
                Err(e)
            }
        }
    }

    async fn try_handle(&mut self) -> Result<()> {
        loop {
            let mut delay = time::sleep(IDLE_TIMEOUT);

            match &mut self.state {
                State::Default => {
                    tokio::select! {
                        msg = self.in_circuit.accept_opaque() => self.handle_in_circuit(msg).await?,
                        _ = &mut delay => {
                            self.handle_timeout().await;
                            break;
                        },
                    }
                }
                State::Router { out_circuit } => {
                    tokio::select! {
                        msg = self.in_circuit.accept_opaque() => self.handle_in_circuit(msg).await?,
                        msg = out_circuit.accept_opaque() => self.handle_out_circuit(msg).await?,
                        _ = &mut delay => {
                            self.handle_timeout().await;
                            break;
                        },
                    }
                }
                State::Endpoint {
                    tunnel_id, data_rx, ..
                } => {
                    let tunnel_id = *tunnel_id;
                    tokio::select! {
                        msg = self.in_circuit.accept_opaque() => self.handle_in_circuit(msg).await?,
                        data = data_rx.recv() => self.handle_data(tunnel_id, data).await?,
                        _ = &mut delay => {
                            self.handle_timeout().await;
                            break;
                        },
                    }
                }
            }
        }
        Ok(())
    }

    /// Performs protocol logic on the incoming circuit.
    /// Checks if a message contains errors and checks whether a valid opaque circuit message is addressed to us.
    /// This function takes care of handling errors and tearing down the sockets if necessary
    async fn handle_in_circuit(
        &mut self,
        msg: SocketResult<CircuitOpaque<CircuitOpaqueBytes>>,
    ) -> Result<()> {
        // event from controlling socket
        // match whether a message has been received or if an error occurred
        match msg {
            Ok(mut msg) => {
                // decrypt message
                msg.decrypt(self.session_key.iter().rev())?;
                // test if this message is directed to us or is broken
                let tunnel_msg = TunnelRequest::read_with_digest_from(&mut msg.payload.bytes);
                match tunnel_msg {
                    Ok(tunnel_msg) => {
                        // addressed to us
                        self.handle_tunnel_message(tunnel_msg).await
                    }
                    Err(TunnelProtocolError::Digest) => {
                        // message not directed to us, forward to relay_socket
                        if let State::Router { out_circuit } = &self.state {
                            out_circuit
                                .socket()
                                .await
                                .forward_opaque(out_circuit.id, msg.payload, &self.rng)
                                .await?;
                            Ok(())
                        } else {
                            // no relay_socket => proto breach teardown
                            Err(anyhow!(
                                "Cannot forward CircuitOpaque since there is no out circuit, \
                            is the encryption correct?"
                            ))
                        }
                    }
                    Err(TunnelProtocolError::Unknown { actual }) => {
                        /* digest correct, but message can't be parsed due to other protocol errors
                           like unsupported tunnel message types.
                           A problem that might surface here is when the decryption randomly
                           decrypted a packet not directed to us to a valid digest.
                        */
                        Err(anyhow!("Unsupported packet: {:?}", actual))
                    }
                    Err(TunnelProtocolError::Peer(())) => unreachable!(),
                }
            }
            Err(OnionSocketError::BrokenMessage) => Err(anyhow!(
                "In Circuit breached protocol by sending unexpected message"
            )),
            Err(OnionSocketError::StreamTerminated(e)) => {
                Err(anyhow!("In Stream terminated: {:?}", e))
            }
            Err(OnionSocketError::TeardownMessage) => Err(anyhow!("In Stream torn down")),
            Err(e) => {
                // Panicking stub
                warn!("An unexpected error occurred during handling of the in_socket");
                panic!(e)
            }
        }
    }

    /// Handles a valid TunnelRequest addressed to us.
    async fn handle_tunnel_message(&mut self, tunnel_msg: TunnelRequest) -> Result<()> {
        let mut state = State::Default;
        std::mem::swap(&mut self.state, &mut state);
        self.state = match (tunnel_msg, state) {
            (TunnelRequest::Extend(dest, key), State::Default) => {
                /*
                   any error in here should never cause the entire loop to fail and we
                   should always respond with EXTENDED (same reason as before)
                   It may be preferable to capsulise this into another function
                */
                match self.handle_tunnel_message_extend(dest, key).await {
                    Ok((out_circuit, peer_key)) => {
                        self.in_circuit
                            .socket()
                            .await
                            .finalize_tunnel_handshake(
                                self.in_circuit.id,
                                peer_key,
                                &self.session_key,
                                &self.rng,
                            )
                            .await?;
                        State::Router { out_circuit }
                    }
                    Err(e) => {
                        self.in_circuit
                            .socket()
                            .await
                            .reject_tunnel_handshake(
                                self.in_circuit.id,
                                &self.session_key,
                                e,
                                &self.rng,
                            )
                            .await?;
                        return Ok(());
                    }
                }
            }
            (TunnelRequest::Extend(_, _), state) => {
                /* reply to socket with EXTENDED
                   this is required to prevent any deadlocks and errors in the tunnel
                   since Alice in the tunnel waits for a EXTENDED packet
                */
                self.in_circuit
                    .socket()
                    .await
                    .reject_tunnel_handshake(
                        self.in_circuit.id,
                        &self.session_key,
                        TunnelExtendedError::BranchingDetected,
                        &self.rng,
                    )
                    .await?;

                state
            }
            (TunnelRequest::Truncate, State::Router { .. }) => {
                // Teardown out circuit
                self.teardown_out_circuit().await;

                self.in_circuit
                    .socket()
                    .await
                    .finalize_tunnel_truncate(self.in_circuit.id, &self.session_key, &self.rng)
                    .await?;

                State::Default
            }
            (TunnelRequest::Truncate, state) => {
                self.in_circuit
                    .socket()
                    .await
                    .reject_tunnel_truncate(
                        self.in_circuit.id,
                        &self.session_key,
                        TunnelTruncatedError::NoNextHop,
                        &self.rng,
                    )
                    .await?;

                state
            }
            (TunnelRequest::Begin(tunnel_id), State::Default) => {
                // counted = false because these tunnels will be mapped to counted tunnels by the OnionListener
                let (tunnel, tx, rx) = OnionTunnel::new(tunnel_id, false);
                if self.incoming.try_send(tunnel).is_ok() {
                    State::Endpoint {
                        tunnel_id,
                        data_rx: rx,
                        data_tx: tx,
                    }
                } else {
                    State::Default
                }
            }
            (TunnelRequest::Begin(_), _) => {
                return Err(anyhow!("Begin request while not in Default state"));
            }
            (TunnelRequest::End(req_tunnel_id), State::Endpoint { tunnel_id, .. }) => {
                if req_tunnel_id != tunnel_id {
                    return Err(anyhow!("Unknown tunnel id in Data message"));
                }

                State::Default
            }
            (TunnelRequest::End(_), _) => {
                return Err(anyhow!("End request white not in Endpoint state"));
            }
            (
                TunnelRequest::Data(req_tunnel_id, data),
                State::Endpoint {
                    tunnel_id,
                    data_tx,
                    data_rx,
                },
            ) => {
                if req_tunnel_id != tunnel_id {
                    return Err(anyhow!("Unknown tunnel id in Data message"));
                }

                let _ = data_tx.send(data).await; // TODO handle closed

                State::Endpoint {
                    tunnel_id,
                    data_tx,
                    data_rx,
                }
            }
            (TunnelRequest::Data(_, _), _) => {
                return Err(anyhow!("Data request while not in Endpoint state"));
            }
            /*
             KeepAlive messages are always valid and only cause a reset of the loop
            */
            (TunnelRequest::KeepAlive, state) => state,
        };
        Ok(())
    }

    async fn handle_tunnel_message_extend(
        &mut self,
        dest: SocketAddr,
        key: EphemeralPublicKey,
    ) -> std::result::Result<(Circuit, VerifyKey), TunnelExtendedError> {
        let stream = TcpStream::connect(dest)
            .await
            .map_err(|_| TunnelExtendedError::PeerUnreachable)?;

        let mut relay_socket = OnionSocket::new(stream);
        let peer_key = relay_socket
            .initiate_handshake(self.in_circuit.id, key, &self.rng)
            .await
            .map_err(|_| TunnelExtendedError::PeerUnreachable)?;

        let out_circuit = Circuit::new(Circuit::random_id(&self.rng), relay_socket);

        Ok((out_circuit, peer_key))
    }

    /// Handles a message received on the outgoing circuit in the router state.
    /// Forwards the message on the incoming circuit if valid.
    async fn handle_out_circuit(
        &mut self,
        msg: SocketResult<CircuitOpaque<CircuitOpaqueBytes>>,
    ) -> Result<()> {
        // event from relay socket
        // match whether a message has been received or if an error occured
        match msg {
            Ok(mut msg) => {
                // encrypt message and try to send it to socket
                msg.encrypt(self.session_key.iter())?;
                self.in_circuit
                    .socket()
                    .await
                    .forward_opaque(self.in_circuit.id, msg.payload, &self.rng)
                    .await?;
                Ok(())
            }
            Err(OnionSocketError::BrokenMessage) => {
                // NOTE: error handling will just be propagated, robustness could be improved here
                Err(anyhow!(
                    "Out Circuit breached protocol by sending unexpected message"
                ))
            }
            Err(OnionSocketError::StreamTerminated(_)) => {
                // NOTE: error handling will just be propagated, robustness could be improved here
                Err(anyhow!("Out Stream terminated"))
            }
            Err(OnionSocketError::TeardownMessage) => {
                // NOTE: error handling will just be propagated, robustness could be improved here
                Err(anyhow!("Out Stream torn down"))
            }
            Err(e) => {
                // Panicking stub
                warn!("An unexpected error occurred during handling of the in_socket");
                panic!(e)
            }
        }
    }

    /// Handles a request to send data from a higher layer in the endpoint state.
    /// If data is None, the tunnel is no longer needed and can be destroyed.
    /// This function takes care of handling errors and tearing down the sockets if necessary
    async fn handle_data(&mut self, tunnel_id: TunnelId, data: Option<Bytes>) -> Result<()> {
        match data {
            Some(data) => {
                let circuit_id = self.in_circuit.id;
                self.in_circuit
                    .socket()
                    .await
                    .send_data(circuit_id, tunnel_id, data, &self.session_key, &self.rng)
                    .await?;
            }
            None => {
                let circuit_id = self.in_circuit.id;
                self.in_circuit
                    .socket()
                    .await
                    .end(circuit_id, tunnel_id, &self.session_key, &self.rng)
                    .await?;
                self.state = State::Default;
            }
        }
        Ok(())
    }

    async fn handle_timeout(&mut self) {
        /* Depending on the implementation of next_message, the timeout may also be
          triggered if only a partial message has been collected so far from any of the
          sockets when the timeout triggers.
          Potentially, this case could be changed to improve robustness, since any
          unhandled TCP packet loss may cause this to happen.
          TCP can trigger a request for any dropped TCP packets, so a switch to UDP
          could cause problems here, if the incoming onion packets are highly fractured
          into multiple UDP packets. The tunnel would fail if any UDP packet gets lost.
        */
        warn!("Timeout triggered, terminating CircuitHandler");
        self.teardown_all().await;
    }

    async fn teardown_all(&mut self) {
        self.teardown_in_circuit().await;
        self.teardown_out_circuit().await;
    }

    async fn teardown_in_circuit(&mut self) {
        self.in_circuit.teardown_with_timeout(&self.rng).await;
    }

    async fn teardown_out_circuit(&mut self) {
        if let State::Router { out_circuit } = &self.state {
            out_circuit.teardown_with_timeout(&self.rng).await;
        }
    }
}

impl fmt::Debug for Circuit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Circuit").field(&self.id).finish()
    }
}

impl fmt::Debug for CircuitHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CircuitHandler")
            .field("in_circuit", &self.in_circuit)
            .field("state", &self.state)
            .finish()
    }
}

impl fmt::Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            State::Default => f.debug_struct("Default").finish(),
            State::Router { out_circuit } => f
                .debug_struct("Router")
                .field("out_circuit", out_circuit)
                .finish(),
            State::Endpoint { tunnel_id, .. } => f
                .debug_struct("Endpoint")
                .field("tunnel_id", tunnel_id)
                .finish(),
        }
    }
}
