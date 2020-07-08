use crate::utils::{FromBytes, ToBytes, TryFromBytes};
use anyhow::{anyhow, Context};
use api_protocol::*;
use bytes::BytesMut;
use futures::stream::StreamExt;
use log::{info, trace};
use onion::*;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;
use tokio::stream;
use tokio::sync::Mutex;

#[allow(dead_code)]
mod api_protocol;
mod utils;

#[derive(Debug, Deserialize)]
struct Config {
    /// Path to file containing PEM-encoded RSA hostkey in PKCS#8 format.
    ///
    /// Generated with:
    /// ```text
    /// openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out testkey.pem
    /// ```
    hostkey: String,
    onion: OnionConfig,
    rps: RpsConfig,
}

#[derive(Debug, Deserialize)]
struct OnionConfig {
    api_address: String,
    /// This is the port for Onion’s P2P protocol i.e., the port number on which Onion accepts
    /// tunnel connections from Onion modules of other peers. This is different from the port where
    /// it listens for API connections. This value is used by the RPS module to advertise the socket
    /// the onion module is listening on, so that other peers onion modules can connect to it.
    p2p_port: u16,
    /// Similar to p2p port this parameter determines the interface on which Onion listens for
    /// incoming P2P connections.
    p2p_hostname: String,
}

#[derive(Debug, Deserialize)]
struct RpsConfig {
    api_address: String,
}

struct ApiSocket<S> {
    stream: S,
    buf: BytesMut,
}

impl<S: AsyncRead + AsyncWrite + Unpin> ApiSocket<S> {
    pub(crate) fn new(stream: S) -> Self {
        ApiSocket {
            stream,
            buf: BytesMut::new(),
        }
    }

    pub async fn read_next<M: TryFromBytes<anyhow::Error>>(&mut self) -> Result<Option<M>> {
        let mut size_buf = [0u8; 2];
        self.stream.read_exact(&mut size_buf).await?;
        let size = u16::from_be_bytes(size_buf) as usize;

        self.buf.clear();
        self.buf.reserve(size);
        self.buf.extend_from_slice(&size_buf);
        self.stream.read_exact(&mut self.buf[2..]).await?;
        Ok(Some(M::try_read_from(&mut self.buf)?))
    }

    pub async fn write<M: ToBytes>(&mut self, message: M) -> Result<()> {
        self.buf.clear();
        self.buf.reserve(message.size());
        message.write_to(&mut self.buf);
        self.stream.write_all(&self.buf).await?;
        Ok(())
    }
}

struct RpsModule {
    socket: ApiSocket<TcpStream>,
}

impl RpsModule {
    async fn connect(api_address: &str) -> Result<Self> {
        let stream = TcpStream::connect(api_address).await?;
        let socket = ApiSocket::new(stream);
        Ok(RpsModule { socket })
    }

    async fn query(&mut self) -> Result<Peer> {
        self.socket.write(RpsRequest::Query).await?;
        if let Some(msg) = self.socket.read_next().await? {
            match msg {
                RpsResponse::Peer(_port, portmap, peer_addr, peer_hostkey) => {
                    let (_, peer_port) = portmap
                        .iter()
                        .find(|(m, _)| *m == Module::Onion)
                        .ok_or(anyhow!("Peer does not expose onion port"))?;
                    let peer_addr = SocketAddr::new(peer_addr, *peer_port);
                    Ok(Peer::new(peer_addr, peer_hostkey.to_vec()))
                }
            }
        } else {
            Err(anyhow!("rps query failed"))
        }
    }
}

struct OnionModule {
    onion: Onion,
    config: Config,
    rps: Mutex<RpsModule>,
}

impl OnionModule {
    async fn init(config: Config) -> Result<Self> {
        let rps = RpsModule::connect(&config.rps.api_address)
            .await
            .context("Failed to connect to RPS module")?;
        let rps = Mutex::new(rps);
        // TODO construct peer provider from rps (use buffering)
        let peer_provider = stream::empty();

        let hostkey = utils::read_hostkey(&config.hostkey).context("Could not read hostkey")?;
        let onion = Onion::new(&hostkey, peer_provider)?;
        /*task::spawn(async {
            let addr = SocketAddr::new(config.onion.p2p_hostname.parse().unwrap(), config.onion.p2p_port);
            onion.listen(addr).await.unwrap();
        });*/
        Ok(OnionModule { onion, config, rps })
    }

    async fn listen_api(self: Arc<Self>) -> Result<()> {
        let api_address = &self.config.onion.api_address;
        let mut listener = TcpListener::bind(api_address).await?;
        info!(
            "Listening for API connections on {:?}",
            listener.local_addr()
        );
        let mut incoming = listener.incoming();
        while let Some(stream) = incoming.next().await {
            let stream = stream?;
            let handler = self.clone();
            tokio::spawn(async move {
                handler.handle_api(stream).await.unwrap();
            });
        }
        Ok(())
    }

    async fn handle_api(self: Arc<Self>, stream: TcpStream) -> Result<()> {
        trace!("Accepted API connection from: {:?}", stream.peer_addr());
        let mut socket = ApiSocket::new(stream);

        while let Some(msg) = socket.read_next::<OnionRequest>().await? {
            trace!("Handling {:?}", msg);
            let msg_id = msg.id();
            match msg {
                OnionRequest::Build(dst_addr, dst_hostkey) => {
                    let handler = self.clone();
                    let dest = Peer::new(dst_addr, dst_hostkey.to_vec());
                    let tunnel =
                    handler.onion.build_tunnel(dest, 3).await?;
                }
                OnionRequest::Destroy(tunnel_id) => {
                    self.onion.destroy_tunnel(tunnel_id).await?;
                }
                OnionRequest::Data(tunnel_id, tunnel_data) => {
                    self.onion.send_data(tunnel_id, &tunnel_data).await?;
                }
                OnionRequest::Cover(_cover_size) => {
                    unimplemented!();
                }
            }
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    info!(
        "{} version {}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    );

    #[rustfmt::skip]
    let config: Config = toml::from_str(r#"
        hostkey = "testkey.pem"

        [onion]
        api_address = "127.0.0.1:4201"
        p2p_port = 4202
        p2p_hostname = "127.0.0.1"

        [rps]
        api_address = "127.0.0.1:4203"
    "#)?;

    let onion_module = OnionModule::init(config)
        .await
        .context("Failed to initialize onion module")?;
    let onion_module = Arc::new(onion_module);
    onion_module.listen_api().await?;
    Ok(())
}
