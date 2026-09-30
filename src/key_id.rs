//! Key identifiers: RFC 9679 COSE Key Thumbprints of the Ed25519 public key.

use core::fmt;

use sha2::{Digest, Sha256};

/// Length of a [`KeyId`] in bytes (a SHA-256 digest).
pub const KEY_ID_LEN: usize = 32;

/// Deterministic CBOR (RFC 8949, section 4.2.1) of the required members of an OKP COSE_Key,
/// up to the public key itself: `{1: 1 (kty OKP), -1: 6 (crv Ed25519), -2: h'<32 bytes>'}`.
/// RFC 9679, section 3 and 4, defines the thumbprint as SHA-256 over exactly this encoding.
const THUMBPRINT_PREFIX: [u8; 8] = [0xa3, 0x01, 0x01, 0x20, 0x06, 0x21, 0x58, 0x20];

/// Identifies a signing key.
///
/// The ID is the RFC 9679 COSE Key Thumbprint (SHA-256) of the Ed25519 public key, so it is
/// bound to the key: anyone can recompute it from the key ring, and a key ring whose IDs do
/// not match their keys is refused.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyId([u8; KEY_ID_LEN]);

impl KeyId {
    /// Computes the key ID of an Ed25519 public key.
    pub fn from_public_key(public_key: &[u8; 32]) -> KeyId {
        let mut hasher = Sha256::new();
        hasher.update(THUMBPRINT_PREFIX);
        hasher.update(public_key);
        let digest = hasher.finalize();
        let mut id = [0u8; KEY_ID_LEN];
        id.copy_from_slice(&digest);
        KeyId(id)
    }

    /// Wraps raw key ID bytes.
    pub const fn from_bytes(bytes: [u8; KEY_ID_LEN]) -> KeyId {
        KeyId(bytes)
    }

    /// The raw key ID bytes, as written into the `kid` header parameter.
    pub const fn as_bytes(&self) -> &[u8; KEY_ID_LEN] {
        &self.0
    }

    pub(crate) fn from_slice(bytes: &[u8]) -> Option<KeyId> {
        <[u8; KEY_ID_LEN]>::try_from(bytes).ok().map(KeyId)
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId({self})")
    }
}
