use crate::onion_protocol::{
    CircuitOpaque, CircuitOpaqueBytes, FromBytesExt, SignKey, TunnelRequest,
};
use crate::socket::OnionSocket;
use crate::utils::derive_secret;
use crate::utils::generate_ephemeral_key_pair;
use crate::Result;
use anyhow::anyhow;
use anyhow::Context;
use bytes::BytesMut;
use ring::{aead, rand, signature};
use std::cell::{RefCell, RefMut};
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
}

pub(crate) struct CircuitHandler {
    in_circuit: Circuit,
    aes_keys: [aead::LessSafeKey; 1],
    out_circuit: Option<Circuit>,
    rng: rand::SystemRandom,
}

impl CircuitHandler {
    pub(crate) async fn init(
        mut socket: OnionSocket<TcpStream>,
        host_key: &signature::RsaKeyPair,
    ) -> Result<Self> {
        let (circuit_id, peer_key) = socket
            .accept_handshake()
            .await
            .context("Handshake with new connection failed")?;

        let rng = rand::SystemRandom::new();
        // TODO handle errors
        let (private_key, key) = generate_ephemeral_key_pair(&rng).unwrap();
        let key = SignKey::sign(&key, host_key, &rng);

        socket.finalize_handshake(circuit_id, key, &rng).await?;

        let secret = derive_secret(private_key, &peer_key).unwrap();
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
                    println!("timeout");
                    // TODO teardown
                    break;
                },
            }
        }

        Ok(())
    }

    async fn handle_in_circuit(
        &mut self,
        msg: Result<CircuitOpaque<CircuitOpaqueBytes>>,
    ) -> Result<()> {
        // event from controlling socket
        // match whether a message has been received or if an error occurred
        match msg {
            Ok(mut msg) => {
                // decrypt message
                msg.decrypt(self.aes_keys.iter().rev())?;
                // test if this message is directed to us or is broken
                let tunnel_msg = TunnelRequest::read_with_digest_from(&mut msg.payload.bytes);
                match tunnel_msg {
                    Ok(tunnel_msg) => {
                        // addressed to us
                        self.handle_tunnel_message(tunnel_msg).await
                    }
                    Err(e) => {
                        /* TODO proper error match for unsupported messages, i.e. digest
                           correct, but message can't be parsed due to other protocol errors
                           like unsupported tunnel message types
                        */
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
                            Err(e)
                        }
                    }
                }
            }
            Err(e) => {
                /* possible scenarios:
                  socket closed => teardown other socket
                  no opaque message, but different message => react accordingly to what message
                  unreadable message => teardown
                  -> Beware: don't duplicate code since behavior should be highly equal to errors
                     from socket
                */
                todo!();
                Err(e)
            }
        }
    }

    async fn handle_tunnel_message(&mut self, tunnel_msg: TunnelRequest) -> Result<()> {
        match tunnel_msg {
            TunnelRequest::Extend(tunnel_id, dest, key) => {
                if self.out_circuit.is_some() {
                    /* TODO reply to socket with EXTENDED
                       this is required to prevent any deadlocks and errors in the tunnel
                       since Alice in the tunnel waits for a EXTENDED packet
                    */
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

                    // TODO generate relay circuit id
                    self.out_circuit = Some(Circuit {
                        id: 0,
                        socket: Mutex::new(relay_socket),
                    });

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
            TunnelRequest::Data(tunnel_id, data) => unimplemented!(),
        }
    }

    async fn handle_out_circuit(
        &mut self,
        msg: Result<CircuitOpaque<CircuitOpaqueBytes>>,
    ) -> Result<()> {
        // event from relay socket
        // match whether a message has been received or if an error occured
        match msg {
            Ok(mut msg) => {
                // encrypt message and try to send it to socket
                msg.encrypt(self.aes_keys.iter())?;
                self.in_circuit
                    .socket()
                    .await
                    .forward_opaque(self.in_circuit.id, msg.payload, &self.rng)
                    .await?;
                Ok(())
            }
            Err(e) => {
                /* possible scenarios:
                  socket closed => teardown other socket
                  no opaque message, but different message => react accordingly to what message
                  unreadable message => teardown
                  -> Beware: don't duplicate code since behavior should be highly equal to errors
                     from socket
                */
                todo!();
                Err(e)
            }
        }
    }

    async fn accept_in_circuit(&self) -> Result<CircuitOpaque<CircuitOpaqueBytes>> {
        self.in_circuit.socket().await.accept_opaque().await
    }

    async fn accept_out_circuit(&self) -> Result<CircuitOpaque<CircuitOpaqueBytes>> {
        match &self.out_circuit {
            Some(c) => c.socket().await.accept_opaque().await,
            None => futures::future::pending().await,
        }
    }
}
