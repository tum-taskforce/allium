use crate::crypto::{generate_ephemeral_key_pair, SessionKey};
use crate::onion_protocol::{
    CircuitOpaque, CircuitOpaqueBytes, SignKey, TryFromBytesExt, TunnelProtocolError,
    TunnelRequest, TUNNEL_EXTENDED_ERROR_BRANCHING_DETECTED, TUNNEL_EXTENDED_ERROR_NONE,
    TUNNEL_EXTENDED_ERROR_PEER_UNREACHABLE, TUNNEL_TRUNCATED_ERROR_NONE,
    TUNNEL_TRUNCATED_ERROR_NO_NEXT_HOP,
};
use crate::socket::{OnionSocket, OnionSocketError, SocketResult};
use crate::{Result, RsaPrivateKey};
use anyhow::anyhow;
use anyhow::Context;
use log::trace;
use ring::rand;
use ring::rand::SecureRandom;
use log::warn;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, MutexGuard};
use tokio::time;
use tokio::time::Duration;

pub(crate) type CircuitId = u16;

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

    pub(crate) fn random_id(rng: &rand::SystemRandom) -> CircuitId {
        // FIXME an attacker may fill up all ids
        let mut id_buf = [0u8; 2];
        rng.fill(&mut id_buf).unwrap();
        u16::from_le_bytes(id_buf)
    }
}

pub(crate) struct CircuitHandler {
    in_circuit: Circuit,
    aes_keys: [SessionKey; 1],
    out_circuit: Option<Circuit>,
    rng: rand::SystemRandom,
}

impl CircuitHandler {
    pub(crate) async fn init(
        mut socket: OnionSocket<TcpStream>,
        host_key: &RsaPrivateKey,
    ) -> Result<Self> {
        trace!("Accepting handshake from {:?}", socket.peer_addr());
        let (circuit_id, peer_key) = socket
            .accept_handshake()
            .await
            .context("Handshake with new connection failed")?;

        let rng = rand::SystemRandom::new();
        // TODO handle errors
        let (private_key, key) = generate_ephemeral_key_pair(&rng);
        let key = SignKey::sign(&key, host_key, &rng);

        socket.finalize_handshake(circuit_id, key, &rng).await?;

        let secret = SessionKey::from_key_exchange(private_key, &peer_key).unwrap();
        let in_circuit = Circuit::new(circuit_id, socket);
        Ok(Self {
            in_circuit,
            aes_keys: [secret],
            out_circuit: None,
            rng,
        })
    }

    pub(crate) async fn handle(&mut self) -> Result<()> {
        // main accept loop
        loop {
            // TODO needs proper timeout definition
            let mut delay = time::delay_for(Duration::from_secs(10));

            tokio::select! {
                msg = self.accept_in_circuit() => self.handle_in_circuit(msg).await?,
                msg = self.accept_out_circuit() => self.handle_out_circuit(msg).await?,
                _ = &mut delay => {
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
                    break;
                },
            }
        }

        Ok(())
    }

    async fn handle_in_circuit(
        &mut self,
        msg: SocketResult<CircuitOpaque<CircuitOpaqueBytes>>,
    ) -> Result<()> {
        // event from controlling socket
        // match whether a message has been received or if an error occurred
        match msg {
            Ok(mut msg) => {
                // TODO final teardown after errors here
                // decrypt message
                msg.decrypt(self.aes_keys.iter().rev())?;
                // test if this message is directed to us or is broken
                let tunnel_msg = TunnelRequest::read_with_digest_from(&mut msg.payload.bytes);
                match tunnel_msg {
                    Ok(tunnel_msg) => {
                        // addressed to us
                        self.handle_tunnel_message(tunnel_msg).await
                    }
                    Err(TunnelProtocolError::Digest) => {
                        // message not directed to us, forward to relay_socket
                        if let Some(out_circuit) = &self.out_circuit {
                            out_circuit
                                .socket()
                                .await
                                .forward_opaque(out_circuit.id, msg.payload, &self.rng)
                                .await?;
                            Ok(())
                        } else {
                            // no relay_socket => proto breach teardown
                            Err(anyhow!("Cannot forward CircuitOpaque since there is no out circuit, \
                            is the encryption correct?"))
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
                }
            }
            Err(OnionSocketError::BrokenMessage) => {
                self.teardown_in_circuit().await;
                self.teardown_out_circuit().await;
                Err(anyhow!(
                    "In Circuit breached protocol by sending unexpected message"
                ))
            }
            Err(OnionSocketError::StreamTerminated(e)) => {
                self.teardown_out_circuit().await;
                Err(anyhow!("In Stream terminated"))
            }
            Err(OnionSocketError::TeardownMessage) => {
                self.teardown_out_circuit().await;
                Ok(())
            }
            Err(e) => {
                // Panicing stub
                warn!("An unexpected error occured during handling of the in_socket");
                panic!(e)
            }
        }
    }

    async fn handle_tunnel_message(&mut self, tunnel_msg: TunnelRequest) -> Result<()> {
        match tunnel_msg {
            TunnelRequest::Extend(tunnel_id, dest, key) => {
                if self.out_circuit.is_some() {
                    /* reply to socket with EXTENDED
                       this is required to prevent any deadlocks and errors in the tunnel
                       since Alice in the tunnel waits for a EXTENDED packet
                    */
                    self.in_circuit
                        .socket()
                        .await
                        .reject_tunnel_handshake(
                            self.in_circuit.id,
                            tunnel_id,
                            &self.aes_keys,
                            TUNNEL_EXTENDED_ERROR_BRANCHING_DETECTED,
                            &self.rng,
                        )
                        .await?;
                    Ok(())
                } else {
                    /* TODO handle connect failure
                       any error in here should never cause the entire loop to fail and we
                       should always respond with EXTENDED (same reason as before)
                       It may be preferable to capsulise this into another function
                    */
                    let mut relay_socket = OnionSocket::new(TcpStream::connect(dest).await?);
                    let peer_key = relay_socket
                        .initiate_handshake(self.in_circuit.id, key, &self.rng)
                        .await?;

                    self.out_circuit =
                        Some(Circuit::new(Circuit::random_id(&self.rng), relay_socket));

                    self.in_circuit
                        .socket()
                        .await
                        .finalize_tunnel_handshake(
                            self.in_circuit.id,
                            tunnel_id,
                            peer_key,
                            &self.aes_keys,
                            &self.rng,
                        )
                        .await?;
                    Ok(())
                }
            }
            TunnelRequest::Truncate(tunnel_id) => {
                if self.out_circuit.is_none() {
                    self.in_circuit
                        .socket()
                        .await
                        .reject_tunnel_truncate(
                            self.in_circuit.id,
                            tunnel_id,
                            &self.aes_keys,
                            TUNNEL_TRUNCATED_ERROR_NO_NEXT_HOP,
                            &self.rng,
                        )
                        .await?;
                    Ok(())
                } else {
                    // Teardown out circuit
                    self.teardown_out_circuit().await;
                    self.out_circuit = None;

                    self.in_circuit
                        .socket()
                        .await
                        .finalize_tunnel_truncate(
                            self.in_circuit.id,
                            tunnel_id,
                            &self.aes_keys,
                            &self.rng,
                        )
                        .await?;
                    Ok(())
                }
            }
            TunnelRequest::Begin(tunnel_id) => todo!(),
            TunnelRequest::End(tunnel_id) => todo!(),
            TunnelRequest::Data(tunnel_id, data) => unimplemented!(),
        }
    }

    async fn handle_out_circuit(
        &mut self,
        msg: SocketResult<CircuitOpaque<CircuitOpaqueBytes>>,
    ) -> Result<()> {
        // event from relay socket
        // match whether a message has been received or if an error occured
        match msg {
            Ok(mut msg) => {
                // encrypt message and try to send it to socket
                // TODO final teardown after errors here
                msg.encrypt(self.aes_keys.iter())?;
                self.in_circuit
                    .socket()
                    .await
                    .forward_opaque(self.in_circuit.id, msg.payload, &self.rng)
                    .await?;
                Ok(())
            }
            Err(OnionSocketError::BrokenMessage) => {
                // NOTE: error handling will just be propagated, robustness could be improved here
                self.teardown_all().await;
                Err(anyhow!(
                    "Out Circuit breached protocol by sending unexpected message"
                ))
            }
            Err(OnionSocketError::StreamTerminated(e)) => {
                // NOTE: error handling will just be propagated, robustness could be improved here
                self.teardown_in_circuit().await;
                Err(anyhow!("Out Stream terminated"))
            }
            Err(OnionSocketError::TeardownMessage) => {
                // NOTE: error handling will just be propagated, robustness could be improved here
                self.teardown_in_circuit().await;
                Ok(())
            }
            Err(e) => {
                // Panicing stub
                warn!("An unexpected error occured during handling of the in_socket");
                panic!(e)
            }
        }
    }

    async fn accept_in_circuit(&self) -> SocketResult<CircuitOpaque<CircuitOpaqueBytes>> {
        self.in_circuit.socket().await.accept_opaque().await
    }

    async fn accept_out_circuit(&self) -> SocketResult<CircuitOpaque<CircuitOpaqueBytes>> {
        match &self.out_circuit {
            Some(c) => c.socket().await.accept_opaque().await,
            None => futures::future::pending().await,
        }
    }

    async fn teardown_all(&mut self) {
        tokio::join!(self.teardown_in_circuit(), self.teardown_out_circuit());
    }

    async fn teardown_in_circuit(&mut self) {
        self.in_circuit
            .socket()
            .await
            .teardown(self.in_circuit.id, &self.rng)
            .await; // NOTE: Ignore any errors
    }

    async fn teardown_out_circuit(&mut self) {
        if let Some(out_circuit) = &self.out_circuit {
            out_circuit
                .socket()
                .await
                .teardown(out_circuit.id, &self.rng)
                .await; // NOTE: Ignore any errors
        }
    }
}
