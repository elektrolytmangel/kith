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
        Self(crate::random_bytes())
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

/// Where a change belongs, and so who may receive and read it (phase 6b):
/// `local` (this device only, never synced), an org (`<org hex>`), or a subgroup
/// of an org (`<org hex>/<name>`, name: 1-64 of `a-z 0-9 - _ .`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Scope(String);

/// An invalid scope string.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid scope {0:?}: use local, <org hex> or <org hex>/<name>")]
pub struct ScopeError(pub String);

impl Scope {
    /// Data that stays on this device.
    pub fn local() -> Self {
        Self("local".into())
    }

    /// An org's main scope.
    pub fn org(org: &DeviceId) -> Self {
        Self(org.to_hex())
    }

    /// A subgroup of `org`.
    pub fn subgroup(org: &DeviceId, name: &str) -> Result<Self, ScopeError> {
        Self::parse(&format!("{}/{name}", org.to_hex()))
    }

    /// Parse and validate.
    pub fn parse(s: &str) -> Result<Self, ScopeError> {
        let bad = || ScopeError(s.to_string());
        if s == "local" {
            return Ok(Self::local());
        }
        let (org, sub) = match s.split_once('/') {
            Some((o, n)) => (o, Some(n)),
            None => (s, None),
        };
        if org.len() != 64
            || DeviceId::from_hex(org).is_err()
            || org.bytes().any(|b| b.is_ascii_uppercase())
        {
            return Err(bad());
        }
        if let Some(n) = sub {
            let ok = !n.is_empty()
                && n.len() <= 64
                && n.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_.".contains(&b));
            if !ok {
                return Err(bad());
            }
        }
        Ok(Self(s.to_string()))
    }

    /// The scope as text (also its canonical encoding).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True for `local`.
    pub fn is_local(&self) -> bool {
        self.0 == "local"
    }

    /// The org this scope belongs to (`None` for `local`).
    pub fn org_id(&self) -> Option<DeviceId> {
        if self.is_local() {
            return None;
        }
        DeviceId::from_hex(self.0.split('/').next().unwrap_or_default()).ok()
    }

    /// The subgroup name, if this is a subgroup scope.
    pub fn subgroup_name(&self) -> Option<&str> {
        self.0.split_once('/').map(|(_, n)| n)
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_parse_and_name_their_org() {
        let org = DeviceId([0xab; 32]);
        let s = Scope::org(&org);
        assert_eq!(Scope::parse(s.as_str()).unwrap(), s);
        assert_eq!(s.org_id(), Some(org));
        let sub = Scope::subgroup(&org, "finance").unwrap();
        assert_eq!(sub.subgroup_name(), Some("finance"));
        assert_eq!(sub.org_id(), Some(org));
        assert!(Scope::local().is_local() && Scope::local().org_id().is_none());
        for bad in [
            "",
            "abc",
            "x/y",
            &format!("{}/", org.to_hex()),
            &format!("{}/Bad", org.to_hex()),
            &org.to_hex().to_uppercase(),
        ] {
            assert!(Scope::parse(bad).is_err(), "{bad}");
        }
    }

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
