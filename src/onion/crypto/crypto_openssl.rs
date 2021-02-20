use crate::Result;
use anyhow::anyhow;
use bytes::Bytes;
use openssl::{derive, hash, pkey, rand, sha, sign, symm};
use std::convert::TryInto;
use std::fs::File;
use std::io::Read;
use std::path::Path;

const AES_128_CTR_KEY_LEN: usize = 16;
const AES_128_CTR_IV_LEN: usize = 16;
pub(crate) const NONCE_LEN: usize = AES_128_CTR_IV_LEN;

/// Length of EphemeralPublicKey in bytes
pub(crate) const KEY_LEN: usize = 44;

// 4096 / 8
pub(crate) const SIGNATURE_LEN: usize = 512;

pub(crate) struct EphemeralPrivateKey(pkey::PKey<pkey::Private>);
pub(crate) struct EphemeralPublicKey(Bytes);
#[derive(Clone)]
pub struct RsaPublicKey(Bytes);
pub struct RsaPrivateKey(pkey::PKey<pkey::Private>);
pub(crate) struct SessionKey([u8; AES_128_CTR_KEY_LEN]);
// TODO consider storing generic B: AsRef<[u8]> instead of Bytes (-> avoid allocations)

pub(crate) fn fill_random(buf: &mut [u8]) {
    rand::rand_bytes(buf).unwrap()
}

pub(crate) fn digest(buf: &[u8]) -> impl AsRef<[u8]> {
    let mut hasher = sha::Sha256::new();
    hasher.update(buf);
    hasher.finish()
}

impl EphemeralPrivateKey {
    pub(crate) fn generate() -> Self {
        Self(pkey::PKey::generate_x25519().unwrap())
    }

    pub(crate) fn public_key(&self) -> EphemeralPublicKey {
        // TODO: maybe use EVP_PKEY_get_raw_public_key
        EphemeralPublicKey::new(self.0.public_key_to_der().unwrap().into())
    }
}

impl EphemeralPublicKey {
    pub(crate) fn new(bytes: Bytes) -> EphemeralPublicKey {
        Self(bytes)
    }

    pub(crate) fn bytes(&self) -> &Bytes {
        &self.0
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
        let mut file = File::open(path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        let pkey = pkey::PKey::private_key_from_pem(&buf)?;
        Ok(RsaPrivateKey(pkey))
    }

    pub fn public_key(&self) -> RsaPublicKey {
        RsaPublicKey(self.0.public_key_to_der().unwrap().into())
    }

    pub(crate) fn sign(&self, data: &[u8], signature: &mut [u8]) -> Result<()> {
        let mut signer = sign::Signer::new(hash::MessageDigest::sha256(), &self.0)?;
        signer.sign_oneshot(signature, data)?;
        Ok(())
    }
}

impl RsaPublicKey {
    pub fn new(bytes: &[u8]) -> Self {
        Self(bytes.to_vec().into())
    }

    /// Converts a RSA public key from the SubjectPublicKeyInfo format
    pub fn from_subject_info(bytes: &[u8]) -> Self {
        Self(bytes.to_vec().into())
    }

    pub(crate) fn verify(&self, data: &[u8], signature: &[u8]) -> Result<()> {
        let pkey = pkey::PKey::public_key_from_der(self.0.as_ref())?;
        let mut verifier = sign::Verifier::new(hash::MessageDigest::sha256(), &pkey)?;

        if verifier.verify_oneshot(signature, data)? {
            Ok(())
        } else {
            Err(anyhow!("Could not verify signature"))
        }
    }
}

impl SessionKey {
    pub(crate) fn from_key_exchange(
        private_key: EphemeralPrivateKey,
        peer_key: &EphemeralPublicKey,
    ) -> Result<SessionKey> {
        let mut deriver = derive::Deriver::new(&private_key.0)?;
        let pkey = pkey::PKey::public_key_from_der(peer_key.0.as_ref())?;
        deriver.set_peer(&pkey)?;

        let mut key = [0u8; AES_128_CTR_KEY_LEN];
        if deriver.derive(&mut key)? >= AES_128_CTR_KEY_LEN {
            Ok(SessionKey(key))
        } else {
            Err(anyhow!("Insufficient keying material"))
        }
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(SessionKey(bytes.try_into()?))
    }

    pub(crate) fn encrypt(&self, nonce: [u8; NONCE_LEN], data: &mut [u8]) -> Result<()> {
        let encrypted = symm::encrypt(symm::Cipher::aes_128_ctr(), &self.0, Some(&nonce), &data)?;
        data.copy_from_slice(&encrypted);
        Ok(())
    }

    pub(crate) fn decrypt(&self, nonce: [u8; NONCE_LEN], data: &mut [u8]) -> Result<()> {
        let decrypted = symm::decrypt(symm::Cipher::aes_128_ctr(), &self.0, Some(&nonce), &data)?;
        data.copy_from_slice(&decrypted);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::RsaPrivateKey;
    use super::{AES_128_CTR_IV_LEN, AES_128_CTR_KEY_LEN};

    #[test]
    fn test_read_hostkey() {
        RsaPrivateKey::from_pem_file("testkey.pem").unwrap();
    }

    #[test]
    fn test_aes_cipher() {
        let cipher = openssl::symm::Cipher::aes_128_ctr();
        assert_eq!(cipher.key_len(), AES_128_CTR_KEY_LEN);
        assert_eq!(cipher.iv_len(), Some(AES_128_CTR_IV_LEN));
    }

    #[test]
    fn test_rsa_size() {
        let key = openssl::rsa::Rsa::generate(4096).unwrap();
        assert_eq!(key.size() as usize, super::SIGNATURE_LEN);
    }
}
