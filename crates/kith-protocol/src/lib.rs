//! Wire protocol between clients and the relay.
//!
//! The relay only ever sees [`Frame`]s. Application payloads (`body`) are
//! MLS ciphertext and opaque to the relay (design section "Relay server
//! protocol"). Encoding is JSON for now; a binary encoding can replace it
//! behind [`encode`] / [`decode`] without touching callers.

use serde::{Deserialize, Serialize};

/// Protocol version announced in [`Frame::Hello`].
pub const PROTOCOL_VERSION: u16 = 1;

/// Oldest protocol version a relay still accepts in [`Frame::Hello`] (ADR 0012: from the first
/// beta on, a relay serves the previous version too). Raise [`PROTOCOL_VERSION`] for a wire
/// change and keep this at the previous release's version.
pub const MIN_PROTOCOL_VERSION: u16 = 1;

/// Whether a relay serves a client that announced `version`.
pub fn supports_version(version: u16) -> bool {
    (MIN_PROTOCOL_VERSION..=PROTOCOL_VERSION).contains(&version)
}

/// Maximum size of a single frame body in bytes. Larger data goes through
/// the large-file path (chunked, peer-to-peer where possible).
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Hex-encoded device public key.
pub type DeviceIdHex = String;
/// Organization identifier (opaque to the relay).
pub type OrgId = String;

/// One message on the client-relay connection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "kebab-case")]
pub enum Frame {
    /// Client -> relay: first message after connecting.
    Hello {
        /// Protocol version spoken by the client.
        version: u16,
        /// Device public key.
        device: DeviceIdHex,
    },
    /// Relay -> client: prove you own the device key.
    Challenge {
        /// Random nonce to sign.
        nonce: String,
    },
    /// Client -> relay: signature over the nonce.
    Auth {
        /// Hex Ed25519 signature.
        signature: String,
    },
    /// Client -> relay: organizations this device belongs to.
    Announce {
        /// Memberships with proofs the relay can check without decrypting.
        orgs: Vec<Membership>,
    },
    /// Fan out to all online devices of an org except the sender.
    Broadcast {
        /// Target organization.
        org: OrgId,
        /// Opaque ciphertext.
        body: Vec<u8>,
    },
    /// Deliver to one device.
    Direct {
        /// Target organization.
        org: OrgId,
        /// Recipient device.
        to: DeviceIdHex,
        /// Opaque ciphertext.
        body: Vec<u8>,
    },
    /// Ask the relay to pick one online peer for catch-up.
    SyncRequest {
        /// Target organization.
        org: OrgId,
        /// Opaque ciphertext (e.g. current MLS epoch + reconciliation start).
        body: Vec<u8>,
    },
    /// Relay -> client: who is online in an org.
    Presence {
        /// Organization.
        org: OrgId,
        /// Online devices.
        online: Vec<DeviceIdHex>,
    },
    /// New device -> inviting admin device(s), routed by invite token.
    InviteClaim {
        /// Organization being joined.
        org: OrgId,
        /// Public token identifying the invite (not the secret).
        token: String,
        /// Opaque claim (KeyPackage + proof).
        body: Vec<u8>,
        /// Set for a member's own-device invite: the issuing device, which may be a
        /// non-admin. Without it the claim goes to the org's online admins.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to: Option<DeviceIdHex>,
    },
    /// Relay -> client: an inbound message from a peer.
    Deliver {
        /// Organization.
        org: OrgId,
        /// Sender device.
        from: DeviceIdHex,
        /// Opaque ciphertext.
        body: Vec<u8>,
    },
    /// Relay -> client: an invite claim ([`Frame::InviteClaim`]) from a device that
    /// may not be a member yet. Clients accept nothing but a claim from it.
    ClaimDeliver {
        /// Organization.
        org: OrgId,
        /// Claiming device.
        from: DeviceIdHex,
        /// The opaque claim.
        body: Vec<u8>,
    },
    /// Relay -> sender: which devices received a message.
    Receipt {
        /// Devices the message was handed to.
        delivered: Vec<DeviceIdHex>,
    },
    /// Relay -> client: request rejected.
    Error {
        /// Machine-readable code.
        code: String,
        /// Human-readable message.
        message: String,
    },
}

/// Proof that a device belongs to an organization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Membership {
    /// Organization.
    pub org: OrgId,
    /// Membership certificate chain (hex, ADR 0005); empty while joining.
    pub proof: String,
    /// The device is an always-on client: the relay prefers it as catch-up partner
    /// (REQ-SYNC-006). Only honoured for certified members.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub always_on: bool,
    /// Admin-signed revocation notices (`Revocation::to_hex`, REQ-INV-004). The relay
    /// verifies and remembers them in RAM and refuses the revoked devices. Admins and
    /// always-on clients repeat the ones they know on every announce.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked: Vec<String>,
}

/// Encoding errors.
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    /// Frame could not be (de)serialized.
    #[error("codec: {0}")]
    Serde(#[from] serde_json::Error),
    /// Body exceeds [`MAX_BODY_BYTES`].
    #[error("frame body too large: {0} bytes")]
    TooLarge(usize),
}

/// The bytes a device signs to answer a [`Frame::Challenge`]: a domain tag, the
/// device ID and the nonce (both as sent on the wire). The tag keeps the signature
/// from being valid for anything else, such as a change.
pub fn auth_message(device: &str, nonce: &str) -> Vec<u8> {
    let mut m = Vec::with_capacity(32 + device.len() + nonce.len());
    m.extend_from_slice(b"kith/relay-auth/v1\0");
    m.extend_from_slice(device.as_bytes());
    m.push(0);
    m.extend_from_slice(nonce.as_bytes());
    m
}

/// Serialize a frame for the wire.
pub fn encode(frame: &Frame) -> Result<Vec<u8>, CodecError> {
    if let Some(n) = body_len(frame).filter(|n| *n > MAX_BODY_BYTES) {
        return Err(CodecError::TooLarge(n));
    }
    Ok(serde_json::to_vec(frame)?)
}

/// Parse a frame from the wire.
pub fn decode(bytes: &[u8]) -> Result<Frame, CodecError> {
    let frame: Frame = serde_json::from_slice(bytes)?;
    if let Some(n) = body_len(&frame).filter(|n| *n > MAX_BODY_BYTES) {
        return Err(CodecError::TooLarge(n));
    }
    Ok(frame)
}

fn body_len(f: &Frame) -> Option<usize> {
    match f {
        Frame::Broadcast { body, .. }
        | Frame::Direct { body, .. }
        | Frame::SyncRequest { body, .. }
        | Frame::InviteClaim { body, .. }
        | Frame::Deliver { body, .. }
        | Frame::ClaimDeliver { body, .. } => Some(body.len()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let f = Frame::Broadcast {
            org: "o1".into(),
            body: vec![1, 2, 3],
        };
        assert_eq!(decode(&encode(&f).unwrap()).unwrap(), f);
    }

    #[test]
    fn auth_message_binds_device_and_nonce() {
        assert_ne!(auth_message("a", "n"), auth_message("b", "n"));
        assert_ne!(auth_message("a", "n"), auth_message("a", "m"));
        assert_ne!(auth_message("ab", "c"), auth_message("a", "bc"));
    }

    /// req: REQ-RELAY-006
    #[test]
    fn oversized_body_rejected() {
        let f = Frame::Broadcast {
            org: "o1".into(),
            body: vec![0; MAX_BODY_BYTES + 1],
        };
        assert!(matches!(encode(&f), Err(CodecError::TooLarge(_))));
    }
}
