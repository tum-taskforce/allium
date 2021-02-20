#[cfg(feature = "crypto_ring")]
#[path = "crypto_ring.rs"]
pub(crate) mod inner;
#[cfg(not(feature = "crypto_ring"))]
#[path = "crypto_openssl.rs"]
pub(crate) mod inner;

pub use inner::*;
