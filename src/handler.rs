use crate::onion_protocol::{CircuitOpaque, FromBytesExt, Key, SignKey, TunnelRequest};
use crate::socket::OnionSocket;
use crate::Result;
use anyhow::anyhow;
use anyhow::Context;
use bytes::BytesMut;
use ring::{aead, agreement, rand, signature};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::time;
use tokio::time::Duration;

type CircuitId = u16;

struct Circuit {
    id: CircuitId,
    socket: OnionSocket<TcpStream>,
}

impl Circuit {
    pub(crate) fn new(id: CircuitId, socket: OnionSocket<TcpStream>) -> Self {
        Circuit { id, socket }
    }
}

struct Handler {
    in_circuit: Circuit,
    aes_keys: [aead::LessSafeKey; 1],
    out_circuit: Option<Circuit>,
    rng: rand::SystemRandom,
}

impl Handler {
    async fn init(
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

    async fn handle(&mut self) -> Result<()> {
        // main accept loop
        loop {
            // TODO needs proper timeout definition
            let mut delay = time::delay_for(Duration::from_secs(10));

            tokio::select! {
                msg = self.in_circuit.socket.accept_opaque() => self.handle_in_circuit(msg).await?,
                Some(msg) = async {
                    Some(self.out_circuit.as_mut()?.socket.accept_opaque().await)
                } => self.handle_out_circuit(msg).await?,
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

    async fn handle_in_circuit(&mut self, msg: Result<CircuitOpaque<BytesMut>>) -> Result<()> {
        // event from controlling socket
        // match whether a message has been received or if an error occurred
        match msg {
            Ok(mut msg) => {
                // decrypt message
                msg.decrypt(&self.rng, self.aes_keys.iter())?;
                // test if this message is directed to us or is broken
                let tunnel_msg = TunnelRequest::read_with_digest_from(&mut msg.payload);
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
                        if let Some(out_circuit) = &mut self.out_circuit {
                            // TODO avoid unwrap here
                            out_circuit
                                .socket
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
                        socket: relay_socket,
                    });

                    self.in_circuit
                        .socket
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

    async fn handle_out_circuit(&mut self, msg: Result<CircuitOpaque<BytesMut>>) -> Result<()> {
        // event from relay socket
        // match whether a message has been received or if an error occured
        match msg {
            Ok(mut msg) => {
                // encrypt message and try to send it to socket
                todo!();
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
}

fn generate_ephemeral_key_pair(
    rng: &rand::SystemRandom,
) -> Result<(agreement::EphemeralPrivateKey, Key)> {
    let private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, rng).unwrap();
    let public_key = private_key.compute_public_key().unwrap();
    // TODO maybe avoid allocating here
    let key = Key::new(&agreement::X25519, public_key.as_ref().to_vec().into());
    Ok((private_key, key))
}

fn derive_secret(
    private_key: agreement::EphemeralPrivateKey,
    peer_key: &Key,
) -> Result<aead::LessSafeKey> {
    // TODO use proper key derivation function
    agreement::agree_ephemeral(
        private_key,
        peer_key,
        anyhow!("Key exchange failed"),
        |key_material| {
            let unbound = aead::UnboundKey::new(&aead::AES_128_GCM, &key_material[..16])
                .context("Could not construct unbound key from keying material")?;
            Ok(aead::LessSafeKey::new(unbound))
        },
    )
}
