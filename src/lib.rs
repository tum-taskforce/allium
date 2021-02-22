//! Allium is a implementation of [onion routing](https://en.wikipedia.org/wiki/Onion_routing)
//! written in Rust. It enables anonymous communication over encrypted tunnels.
//!
//! ## Features
//!
//! - Asynchronous design
//! - Periodic, seamless tunnel reconstruction
//! - Fixed-size packets
//! - Cover traffic
//!
//! ## Getting started
//!
//! Each peer in the onion network requires a RSA keypair to sign its messages.
//! A suitable RSA keypair can be generated with OpenSSL:
//! ```text
//! $ genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out hostkey.pkcs8.pem
//! $ openssl rsa -in hostkey.pkcs8.pem -out hostkey.pem
//! ```
//! Use [`RsaPrivateKey::from_pem_file`] to load the created key.
//!
//! Furthermore, the public keys of other peers in the network must be supplied to verify their identities.
//! A peer can export its public key like this:
//! ```text
//! $ openssl rsa -in hostkey.pem -outform DER -pubout -out hostkey_pub.der
//! ```
//! A remote peer is represented by the [`Peer`] struct which stores the peers address, port and [`RsaPublicKey`].
//!
//! To continuously (re-) build tunnels, the onion router needs a stream of peers which can be used as intermediary nodes in a tunnel.
//! This is requirement is met by the [`PeerProvider`] struct, which can be created from a asynchronous `Stream<Item = Peer>`.
//! The [`PeerProvider`] is fully responsible for the peer sampling.
//!
//! With a [`RsaPrivateKey`] and a [`PeerProvider`] ready, the actual onion router can be constructed.
//! The onion router is split into two parts: a stream of incoming connections and a context
//! allowing the building of new tunnels.
//! Use the [`OnionBuilder`] type to configure the onion router and then call [`OnionBuilder::start`]
//! to obtain a [`OnionIncoming`] stream and a [`OnionContext`].
//!
//! [`OnionContext`] implements [`Clone`], [`Send`] and [`Sync`] allowing to have multiple handles to the
//! same onion router instance.
//! The async method [`OnionContext::build_tunnel`] blocks until a [`Tunnel`] was successfully created and is ready for communication.
//! A [`Tunnel`] can be used similar to a normal socket by calling the [`Tunnel::read`] and [`Tunnel::write`] methods.
//!
//! ## Daemon
//!
//! In addition to being used as a Rust library, Allium can also be run as a stand-alone daemon,
//! which can be controlled over a socket.
//! Refer to the [README](https://github.com/tum-taskforce/allium/blob/master/README.md) for more
//! information on how to use Allium as a daemon.
//!

use std::fmt;
use std::net::SocketAddr;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::{Stream, StreamExt};

mod onion;
mod utils;

pub use crate::onion::crypto::{RsaPrivateKey, RsaPublicKey};
pub use crate::onion::tunnel::TunnelId;
pub use crate::onion::*;

pub type Result<T> = std::result::Result<T, anyhow::Error>;

/// A remote peer characterized by its address, the port on which it is listening for onion
/// connections and its public key.
///
/// The public key is needed to verify the authenticity of signed messages received from this peer.
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

impl fmt::Debug for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Peer").field(&self.addr).finish()
    }
}

/// A stream of [`Peer`]s used for constructing tunnels.
///
/// It is up to the user to choose an appropriate peer sampling and caching strategy.
#[derive(Clone)]
pub struct PeerProvider {
    inner: mpsc::Sender<oneshot::Sender<Peer>>,
}

impl PeerProvider {
    /// Turns a given stream of [`Peer`]s into a [`PeerProvider`].
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
