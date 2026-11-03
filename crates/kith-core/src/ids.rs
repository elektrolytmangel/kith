use std::fmt;

/// Error parsing an identifier from its hex form.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum IdError {
    /// Input was not valid hex.
    #[error("invalid hex: {0}")]
    Hex(#[from] hex::FromHexError),
    /// Input decoded to the wrong number of bytes.
    #[error("expected {expected} bytes, got {actual}")]
    Length {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length.
        actual: usize,
    },
}

macro_rules! byte_id {
    ($(#[$doc:meta])* $name:ident, $len:expr) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name(pub [u8; $len]);

        impl $name {
            /// Byte length of this identifier.
            pub const LEN: usize = $len;

            /// Raw bytes.
            pub fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            /// Lowercase hex encoding.
            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }

            /// Parse from lowercase or uppercase hex.
            pub fn from_hex(s: &str) -> Result<Self, IdError> {
                let v = hex::decode(s)?;
                let arr: [u8; $len] = v.as_slice().try_into().map_err(|_| IdError::Length {
                    expected: $len,
                    actual: v.len(),
                })?;
                Ok(Self(arr))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), &self.to_hex()[..12])
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }
    };
}

byte_id!(
    /// Random identifier of an object, fixed at creation.
    ObjectId, 16
);
byte_id!(
    /// Hash of a change envelope's contents (SHA-256).
    ChangeId, 32
);
byte_id!(
    /// A device's Ed25519 public key; its identity everywhere in the system.
    DeviceId, 32
);

impl ObjectId {
    /// Generate a new random object ID from the OS RNG.
    pub fn random() -> Self {
        use rand_core::{OsRng, RngCore};
        let mut b = [0u8; 16];
        OsRng.fill_bytes(&mut b);
        Self(b)
    }
}

/// Application-defined type tag, e.g. `note`, `config`, `file-ref`.
///
/// The core never interprets payloads; the type tag lets apps and the
/// permission layer decide how to handle an object.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ObjectType(pub String);

impl ObjectType {
    /// Create a type tag.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// The tag as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let id = ObjectId::random();
        assert_eq!(ObjectId::from_hex(&id.to_hex()).unwrap(), id);
    }

    #[test]
    fn wrong_length_rejected() {
        assert_eq!(
            ChangeId::from_hex("abcd"),
            Err(IdError::Length {
                expected: 32,
                actual: 2
            })
        );
    }
}
