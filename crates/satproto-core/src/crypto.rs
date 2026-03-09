use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use crypto_box::{PublicKey, SecretKey};
use rand::RngCore;

/// Generate a new X25519 keypair. Returns (secret_key_bytes, public_key_bytes).
pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    let secret = SecretKey::generate(&mut OsRng);
    let public = secret.public_key();
    (secret.to_bytes(), public.to_bytes())
}

/// Generate a random 256-bit content key.
pub fn generate_content_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

/// Encrypt a content key for a recipient using their X25519 public key (sealed box).
pub fn seal_content_key(content_key: &[u8; 32], recipient_public: &[u8; 32]) -> Vec<u8> {
    let pk = PublicKey::from(*recipient_public);
    pk.seal(&mut OsRng, content_key).expect("seal failed")
}

/// Decrypt a content key using our secret key (sealed box open).
pub fn open_content_key(
    sealed: &[u8],
    our_secret: &[u8; 32],
) -> Result<[u8; 32], CryptoError> {
    let sk = SecretKey::from(*our_secret);
    let plaintext = sk.unseal(sealed).map_err(|_| CryptoError::DecryptionFailed)?;
    let key: [u8; 32] = plaintext
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength)?;
    Ok(key)
}

/// Encrypt data with a content key using XChaCha20-Poly1305.
/// Returns nonce (24 bytes) || ciphertext.
pub fn encrypt_data(data: &[u8], content_key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(content_key.into());
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|_| CryptoError::EncryptionFailed)?;
    let mut output = Vec::with_capacity(24 + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt data encrypted with encrypt_data. Input: nonce (24 bytes) || ciphertext.
pub fn decrypt_data(encrypted: &[u8], content_key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    if encrypted.len() < 24 {
        return Err(CryptoError::InvalidData);
    }
    let (nonce_bytes, ciphertext) = encrypted.split_at(24);
    let cipher = XChaCha20Poly1305::new(content_key.into());
    let nonce = XNonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Encode bytes to base64 string.
pub fn to_base64(data: &[u8]) -> String {
    BASE64.encode(data)
}

/// Decode base64 string to bytes.
pub fn from_base64(s: &str) -> Result<Vec<u8>, CryptoError> {
    BASE64.decode(s).map_err(|_| CryptoError::InvalidBase64)
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("invalid key length")]
    InvalidKeyLength,
    #[error("invalid data")]
    InvalidData,
    #[error("invalid base64")]
    InvalidBase64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let (sk, pk) = generate_keypair();
        assert_ne!(sk, [0u8; 32]);
        assert_ne!(pk, [0u8; 32]);
        assert_ne!(sk, pk);
    }

    #[test]
    fn test_content_key_seal_open() {
        let (sk, _pk) = generate_keypair();
        let content_key = generate_content_key();
        let sealed = seal_content_key(&content_key, &_pk);
        let opened = open_content_key(&sealed, &sk).unwrap();
        assert_eq!(content_key, opened);
    }

    #[test]
    fn test_encrypt_decrypt_data() {
        let key = generate_content_key();
        let data = b"hello satproto";
        let encrypted = encrypt_data(data, &key).unwrap();
        let decrypted = decrypt_data(&encrypted, &key).unwrap();
        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = generate_content_key();
        let key2 = generate_content_key();
        let data = b"secret message";
        let encrypted = encrypt_data(data, &key1).unwrap();
        assert!(decrypt_data(&encrypted, &key2).is_err());
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = b"test data";
        let encoded = to_base64(data);
        let decoded = from_base64(&encoded).unwrap();
        assert_eq!(data.as_slice(), decoded.as_slice());
    }
}
