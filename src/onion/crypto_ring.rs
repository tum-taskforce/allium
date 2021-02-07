use crate::Result;
use anyhow::anyhow;
use anyhow::Context;
use bytes::Bytes;
use once_cell::sync::Lazy;
use ring::rand::SecureRandom;
use ring::signature::KeyPair;
use ring::{aead, agreement, digest, rand, signature};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::ops::Deref;
use std::path::Path;

static GLOBAL_RNG: Lazy<rand::SystemRandom> = Lazy::new(|| rand::SystemRandom::new());
pub(crate) const NONCE_LEN: usize = aead::NONCE_LEN;

pub(crate) struct EphemeralPrivateKey(agreement::EphemeralPrivateKey);
pub(crate) struct EphemeralPublicKey(agreement::UnparsedPublicKey<Bytes>);
#[derive(Clone)]
pub struct RsaPublicKey(signature::UnparsedPublicKey<Bytes>);
pub struct RsaPrivateKey(signature::RsaKeyPair);
pub(crate) struct SessionKey(aead::LessSafeKey);
// TODO consider storing generic B: AsRef<[u8]> instead of Bytes (-> avoid allocations)

pub(crate) fn fill_random(buf: &mut [u8]) {
    GLOBAL_RNG.fill(buf).unwrap()
}

pub(crate) fn digest(buf: &[u8]) -> impl AsRef<[u8]> {
    digest::digest(&digest::SHA256, buf)
}

impl EphemeralPrivateKey {
    pub(crate) fn generate() -> Self {
        Self(
            agreement::EphemeralPrivateKey::generate(&agreement::X25519, GLOBAL_RNG.deref())
                .unwrap(),
        )
    }

    pub(crate) fn public_key(&self) -> EphemeralPublicKey {
        let public_key = self.0.compute_public_key().unwrap();
        let public_key_bytes = public_key.as_ref().to_vec().into();
        EphemeralPublicKey(agreement::UnparsedPublicKey::new(
            &agreement::X25519,
            public_key_bytes,
        ))
    }
}

impl EphemeralPublicKey {
    pub(crate) fn new(bytes: Bytes) -> EphemeralPublicKey {
        EphemeralPublicKey(agreement::UnparsedPublicKey::new(&agreement::X25519, bytes))
    }

    pub(crate) fn bytes(&self) -> &Bytes {
        self.0.bytes()
    }
}

pub(crate) fn generate_ephemeral_keypair() -> (EphemeralPrivateKey, EphemeralPublicKey) {
    let private_key = EphemeralPrivateKey::generate();
    let public_key = private_key.public_key();
    (private_key, public_key)
}

impl RsaPrivateKey {
    /// Reads a RSA private key from the specified file.
    /// The key is expected to be in the DER format and PEM encoded.
    pub fn from_pem_file<P: AsRef<Path>>(path: P) -> Result<RsaPrivateKey> {
        let file = BufReader::new(File::open(path)?);
        let key = file
            .lines()
            .map(|line| line.unwrap())
            .skip(1)
            .take_while(|line| !line.starts_with('-'))
            .collect::<String>();
        let bytes = base64::decode(&key)?;
        Ok(RsaPrivateKey(signature::RsaKeyPair::from_der(&bytes)?))
    }

    pub fn public_key(&self) -> RsaPublicKey {
        let public_key_bytes = self.0.public_key().as_ref().to_vec().into();
        let public_key = signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            public_key_bytes,
        );
        RsaPublicKey(public_key)
    }

    pub(crate) fn sign(&self, data: &[u8], signature: &mut [u8]) -> Result<()> {
        self.0.sign(
            &signature::RSA_PKCS1_SHA256,
            GLOBAL_RNG.deref(),
            data,
            signature,
        )?;
        Ok(())
    }
}

impl RsaPublicKey {
    pub fn new(bytes: &[u8]) -> Self {
        let public_key = signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            bytes.to_vec().into(),
        );
        RsaPublicKey(public_key)
    }

    /// Converts a RSA public key from the SubjectPublicKeyInfo format
    pub fn from_subject_info(bytes: &[u8]) -> Self {
        Self::new(&bytes[24..])
    }

    pub(crate) fn verify(&self, data: &[u8], signature: &[u8]) -> Result<()> {
        self.0.verify(data, signature)?;
        Ok(())
    }
}

impl SessionKey {
    pub(crate) fn from_key_exchange(
        private_key: EphemeralPrivateKey,
        peer_key: &EphemeralPublicKey,
    ) -> Result<SessionKey> {
        // TODO use proper key derivation function
        agreement::agree_ephemeral(
            private_key.0,
            &peer_key.0,
            anyhow!("Key exchange failed"),
            Self::from_bytes,
        )
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let unbound = aead::UnboundKey::new(&aead::AES_128_GCM, &bytes[..16])
            .context("Could not construct session key from keying material")?;
        Ok(SessionKey(aead::LessSafeKey::new(unbound)))
    }

    pub(crate) fn encrypt(&self, nonce: [u8; NONCE_LEN], data: &mut [u8]) -> Result<()> {
        let nonce = aead::Nonce::assume_unique_for_key(nonce);
        let _tag = self
            .0
            .seal_in_place_separate_tag(nonce, aead::Aad::empty(), data)?;
        Ok(())
    }

    pub(crate) fn decrypt(&self, nonce: [u8; NONCE_LEN], data: &mut [u8]) -> Result<()> {
        let nonce = aead::Nonce::assume_unique_for_key(nonce);
        self.0
            .open_in_place_no_tag(nonce, aead::Aad::empty(), data)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::RsaPrivateKey;

    #[test]
    fn test_read_hostkey() {
        RsaPrivateKey::from_pem_file("testkey.pem").unwrap();
    }
}
