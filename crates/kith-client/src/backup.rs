//! Encrypted backups (phase 8b, ADR 0010).
//!
//! A backup holds a device's key, all its changes and file chunks, and its org
//! state (membership certificates, root keys, open invites), encrypted under a
//! passphrase (Argon2id, then XChaCha20-Poly1305). It deliberately leaves out the
//! MLS state: restoring old ratchets would make the device reuse encryption keys
//! it already used before the backup. A restored device is re-added to its groups
//! by any online member instead (it asks on its own, see `Client::handle_frame`),
//! then catches up. Restore only when the original device is gone: two devices
//! with one key would keep re-adding each other.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::*;

const MAGIC: &[u8] = b"kith-backup/v1\0";

/// Argon2id cost: 64 MiB, 3 passes (OWASP); cheap in tests.
fn params() -> Params {
    let (m, t) = if cfg!(test) {
        (8 * 1024, 1)
    } else {
        (64 * 1024, 3)
    };
    Params::new(m, t, 1, Some(32)).expect("valid Argon2 parameters")
}

fn derive(passphrase: &str, salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>, ClientError> {
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params())
        .hash_password_into(passphrase.as_bytes(), salt, &mut *key)
        .map_err(|e| ClientError::InvalidBackup(e.to_string()))?;
    Ok(key)
}

fn put(w: &mut Vec<u8>, b: &[u8]) {
    w.extend_from_slice(&(b.len() as u32).to_be_bytes());
    w.extend_from_slice(b);
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ClientError> {
        let (h, t) = self
            .0
            .split_at_checked(n)
            .ok_or_else(|| ClientError::InvalidBackup("truncated".into()))?;
        self.0 = t;
        Ok(h)
    }
    fn u32(&mut self) -> Result<usize, ClientError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("4 bytes")) as usize)
    }
    fn bytes(&mut self) -> Result<&'a [u8], ClientError> {
        let n = self.u32()?;
        self.take(n)
    }
}

impl<S: Store> Client<S, DeviceKey> {
    /// Everything this device needs to be restored elsewhere, encrypted under
    /// `passphrase` (ADR 0010). Contains the device key: anyone
    /// with the file and the passphrase can act as this device.
    pub fn export_backup(&self, passphrase: &str) -> Result<Vec<u8>, ClientError> {
        // Holds the device key and the org root keys: wiped when dropped.
        let mut plain = Zeroizing::new(Vec::new());
        plain.extend_from_slice(&*Zeroizing::new(self.key.secret_bytes()));
        put(&mut plain, &Zeroizing::new(self.orgs.to_bytes()));
        let ids = self.store.all_ids()?;
        plain.extend_from_slice(&(ids.len() as u32).to_be_bytes());
        for id in &ids {
            if let Some(c) = self.store.get(id)? {
                put(&mut plain, &kith_store::codec::encode_change(&c));
            }
        }
        // Chunks of every stored file.
        let mut chunks = vec![];
        for id in &ids {
            if let Some(c) = self.store.get(id)?
                && c.body.object_type.as_str() == FILE_TYPE
                && let Some(r) = FileRef::decode(&c.body.payload)
            {
                for chunk in r.chunks {
                    if let Some((scope, data)) = self.store.get_chunk(&chunk)? {
                        chunks.push((chunk, scope, data));
                    }
                }
            }
        }
        plain.extend_from_slice(&(chunks.len() as u32).to_be_bytes());
        for (id, scope, data) in &chunks {
            plain.extend_from_slice(id);
            put(&mut plain, scope.as_str().as_bytes());
            put(&mut plain, data);
        }
        let salt: [u8; 16] = kith_core::random_bytes();
        let nonce: [u8; 24] = kith_core::random_bytes();
        let key = derive(passphrase, &salt)?;
        let ct = XChaCha20Poly1305::new((&*key).into())
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plain.as_slice(),
                    aad: MAGIC,
                },
            )
            .map_err(|_| ClientError::InvalidBackup("encryption failed".into()))?;
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Restore a backup into `store` (which should be empty) and return the
    /// client. Its groups are rejoined through a re-add once a member is online.
    pub fn import_backup(backup: &[u8], passphrase: &str, store: S) -> Result<Self, ClientError> {
        let mut r = Reader(backup);
        if r.take(MAGIC.len())? != MAGIC {
            return Err(ClientError::InvalidBackup("not a kith backup".into()));
        }
        let salt: [u8; 16] = r.take(16)?.try_into().expect("16 bytes");
        let nonce: [u8; 24] = r.take(24)?.try_into().expect("24 bytes");
        let key = derive(passphrase, &salt)?;
        let plain = XChaCha20Poly1305::new((&*key).into())
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: r.0,
                    aad: MAGIC,
                },
            )
            .map_err(|_| ClientError::InvalidBackup("wrong passphrase or damaged backup".into()))?;
        let plain = Zeroizing::new(plain);
        let mut r = Reader(&plain);
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(r.take(32)?.try_into().expect("32 bytes"));
        let orgs = Zeroizing::new(r.bytes()?.to_vec());
        let mut store = store;
        let n = r.u32()?;
        for _ in 0..n {
            let c = kith_store::codec::decode_change(r.bytes()?)?;
            c.verify()?;
            store.put(c)?;
        }
        let n = r.u32()?;
        for _ in 0..n {
            let id: [u8; 32] = r.take(32)?.try_into().expect("32 bytes");
            let scope = std::str::from_utf8(r.bytes()?)
                .ok()
                .and_then(|s| Scope::parse(s).ok())
                .ok_or_else(|| ClientError::InvalidBackup("chunk scope".into()))?;
            let data = r.bytes()?;
            if kith_crypto::files::chunk_id(data) != id {
                return Err(ClientError::InvalidBackup("damaged chunk".into()));
            }
            store.put_chunk(&id, &scope, data)?;
        }
        if !r.0.is_empty() {
            return Err(ClientError::InvalidBackup("trailing bytes".into()));
        }
        let key = DeviceKey::from_secret_bytes(&seed);
        let storage_key = Zeroizing::new(sealed::storage_key(&key).map_err(stored_state)?);
        store.put_meta(ORGS_KEY, &sealed::seal(&storage_key, ORGS_KEY, &orgs))?;
        // No MLS state: the device gets fresh keys through a re-add.
        let groups = Groups::new().to_bytes();
        store.put_meta(
            MLS_STATE_KEY,
            &sealed::seal(&storage_key, MLS_STATE_KEY, &groups),
        )?;
        Client::new(key, store)
    }
}
