//! Encrypted large files (REQ-FILE-001, ADR 0009).
//!
//! A file is encrypted with a fresh random key and split into chunks of
//! [`CHUNK_SIZE`] bytes. Each chunk is sealed with XChaCha20-Poly1305 (nonce from
//! the chunk index; the key is used for this file only). A chunk's ID is the
//! SHA-256 of its ciphertext, so any peer can store and serve chunks and anyone
//! can verify them without the key. The key and chunk IDs travel in a `kith.file`
//! object through the normal (MLS-encrypted, signed) change flow.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use sha2::{Digest, Sha256};

/// Plaintext bytes per chunk (the last one may be shorter).
pub const CHUNK_SIZE: usize = 256 * 1024;

/// SHA-256 of a chunk's ciphertext.
pub type ChunkId = [u8; 32];

/// File errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FileError {
    /// A chunk does not decrypt (wrong key, index, or tampered data).
    #[error("chunk {0} does not decrypt")]
    Decrypt(usize),
}

/// A file ready to store and share: its key and its encrypted chunks in order.
pub struct EncryptedFile {
    /// The file key (32 random bytes). Secret: it goes only into the encrypted change flow.
    pub key: [u8; 32],
    /// Plaintext size in bytes.
    pub size: u64,
    /// `(id, ciphertext)` per chunk, in order.
    pub chunks: Vec<(ChunkId, Vec<u8>)>,
}

impl std::fmt::Debug for EncryptedFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedFile")
            .field("size", &self.size)
            .field("chunks", &self.chunks.len())
            .finish_non_exhaustive()
    }
}

/// The ID of a chunk's ciphertext.
pub fn chunk_id(ciphertext: &[u8]) -> ChunkId {
    Sha256::digest(ciphertext).into()
}

fn nonce(index: usize) -> XNonce {
    let mut n = [0u8; 24];
    n[16..].copy_from_slice(&(index as u64).to_be_bytes());
    XNonce::from(n)
}

fn aad(index: usize) -> Vec<u8> {
    let mut a = b"kith/file-chunk/v1\0".to_vec();
    a.extend_from_slice(&(index as u64).to_be_bytes());
    a
}

/// Encrypt `data` with a fresh key.
#[allow(
    clippy::expect_used,
    reason = "XChaCha20-Poly1305 encryption of an in-memory buffer cannot fail"
)]
pub fn encrypt_file(data: &[u8]) -> EncryptedFile {
    let key: [u8; 32] = kith_core::random_bytes();
    let cipher = XChaCha20Poly1305::new(&key.into());
    let chunks = data
        .chunks(CHUNK_SIZE)
        .enumerate()
        .map(|(i, plain)| {
            let ct = cipher
                .encrypt(
                    &nonce(i),
                    Payload {
                        msg: plain,
                        aad: &aad(i),
                    },
                )
                .expect("XChaCha20-Poly1305 encryption cannot fail for in-memory data");
            (chunk_id(&ct), ct)
        })
        .collect();
    EncryptedFile {
        key,
        size: data.len() as u64,
        chunks,
    }
}

/// Decrypt chunk number `index` of a file.
pub fn decrypt_chunk(
    key: &[u8; 32],
    index: usize,
    ciphertext: &[u8],
) -> Result<Vec<u8>, FileError> {
    XChaCha20Poly1305::new(key.into())
        .decrypt(
            &nonce(index),
            Payload {
                msg: ciphertext,
                aad: &aad(index),
            },
        )
        .map_err(|_| FileError::Decrypt(index))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// req: REQ-FILE-001
    #[test]
    fn files_roundtrip_in_verifiable_chunks() {
        let data: Vec<u8> = (0..(CHUNK_SIZE * 2 + 123))
            .map(|i| (i % 251) as u8)
            .collect();
        let f = encrypt_file(&data);
        assert_eq!(f.size, data.len() as u64);
        assert_eq!(f.chunks.len(), 3);
        let mut back = vec![];
        for (i, (id, ct)) in f.chunks.iter().enumerate() {
            assert_eq!(*id, chunk_id(ct), "anyone can verify a chunk");
            let plain = &data[i * CHUNK_SIZE..];
            assert_ne!(&ct[..64], &plain[..64], "encrypted");
            back.extend(decrypt_chunk(&f.key, i, ct).unwrap());
        }
        assert_eq!(back, data);
        assert!(encrypt_file(&[]).chunks.is_empty());
    }

    #[test]
    fn wrong_key_index_or_tampering_fails() {
        let f = encrypt_file(b"hello file");
        let ct = &f.chunks[0].1;
        assert!(decrypt_chunk(&[0; 32], 0, ct).is_err());
        assert!(
            decrypt_chunk(&f.key, 1, ct).is_err(),
            "chunks cannot be reordered"
        );
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(decrypt_chunk(&f.key, 0, &bad).is_err());
        assert_ne!(encrypt_file(b"hello file").key, f.key, "fresh key per file");
    }
}
