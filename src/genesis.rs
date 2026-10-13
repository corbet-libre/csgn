//! The genesis document: the self-signed root of one community's key chain.
//!
//! It names the community, its creation time, its maximum message lifetime and
//! the founding public key, and is signed by that key. Its hash is the
//! community's fingerprint. Anyone holding the fingerprint can recognize the
//! document, build the first key ring from it and then follow every key
//! transition (each signed by the previous ring) to the current ring.

use coset::CborSerializable;
use coset::cbor::value::Value;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use crate::cose::{as_u64, int, int_map, take};
use crate::ring::KeyEntry;
use crate::{KeyId, KeyRing, Kind, VerifyError};

/// Length of a fingerprint in bytes (SHA-256).
pub const FINGERPRINT_LEN: usize = 32;
const DOMAIN: &[u8] = b"csgn.genesis.v1\0";

/// A signature-verified genesis document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Genesis {
    community: String,
    created_at: u64,
    max_validity: u64,
    founding_key: [u8; 32],
    fingerprint: [u8; FINGERPRINT_LEN],
}

impl Genesis {
    /// The community (ring issuer) this document founds.
    pub fn community(&self) -> &str {
        &self.community
    }
    /// Creation time in Unix seconds; the founding key is active from then.
    pub fn created_at(&self) -> u64 {
        self.created_at
    }
    /// The founding Ed25519 public key.
    pub fn founding_key(&self) -> [u8; 32] {
        self.founding_key
    }
    /// SHA-256 of the exact document bytes, domain separated.
    pub fn fingerprint(&self) -> [u8; FINGERPRINT_LEN] {
        self.fingerprint
    }
    /// The ring at revision 0: exactly the founding key, active.
    pub fn ring(&self) -> KeyRing {
        // Verified at parse time, so the key is a valid, non-weak public key.
        let public = VerifyingKey::from_bytes(&self.founding_key).expect("verified founding key");
        let entry = KeyEntry::new_active(
            KeyId::from_public_key(&self.founding_key),
            public,
            self.created_at,
        );
        KeyRing::new(self.community.clone(), entry, self.max_validity)
    }
}

/// The fingerprint of a genesis document, without verifying it.
pub fn fingerprint(document: &[u8]) -> [u8; FINGERPRINT_LEN] {
    Sha256::new()
        .chain_update(DOMAIN)
        .chain_update(document)
        .finalize()
        .into()
}

pub(crate) fn payload(
    community: &str,
    created_at: u64,
    max_validity: u64,
    key: &[u8; 32],
) -> Vec<u8> {
    Value::Map(vec![
        (int(1), Value::Text(community.to_owned())),
        (int(2), Value::Integer(created_at.into())),
        (int(3), Value::Integer(max_validity.into())),
        (int(4), Value::Bytes(key.to_vec())),
    ])
    .to_vec()
    .expect("CBOR encoding into memory cannot fail")
}

/// Verifies a genesis document and returns what it founds.
///
/// Time is irrelevant: the document is self-signed and immutable, and trust
/// comes from comparing its [`Genesis::fingerprint`] with the expected one.
/// Refuses non-canonical payloads, weak keys, a key ID that is not the
/// founding key's thumbprint, an issuer other than the community and an issue
/// time other than the creation time.
pub fn verify_genesis(document: &[u8]) -> Result<Genesis, VerifyError> {
    let bad = VerifyError::Malformed("invalid genesis payload");
    let parsed = crate::cose::parse(document)?;
    if parsed.kind != Kind::Genesis {
        return Err(VerifyError::WrongKind {
            expected: Kind::Genesis,
            found: parsed.kind,
        });
    }
    let raw = parsed.payload();
    let mut fields =
        int_map(Value::from_slice(raw).map_err(|_| bad.clone())?).ok_or(bad.clone())?;
    let community = match take(&mut fields, 1) {
        Some(Value::Text(text))
            if !text.is_empty() && text.len() <= crate::MAX_ISSUER_LEN && !text.contains('\0') =>
        {
            text
        }
        _ => return Err(bad),
    };
    let created_at = take(&mut fields, 2).and_then(as_u64).ok_or(bad.clone())?;
    let max_validity = take(&mut fields, 3)
        .and_then(as_u64)
        .filter(|value| *value > 0)
        .ok_or(bad.clone())?;
    let Some(Value::Bytes(key)) = take(&mut fields, 4) else {
        return Err(bad);
    };
    let founding_key: [u8; 32] = key.as_slice().try_into().map_err(|_| bad.clone())?;
    // One byte string per document: a non-canonical payload would give the same
    // community two fingerprints.
    if !fields.is_empty() || payload(&community, created_at, max_validity, &founding_key) != raw {
        return Err(bad);
    }
    let public = VerifyingKey::from_bytes(&founding_key).map_err(|_| VerifyError::BadSignature)?;
    if public.is_weak() || parsed.key_id != KeyId::from_public_key(&founding_key) {
        return Err(VerifyError::UnknownKey);
    }
    parsed.verify_signature(&public)?;
    if parsed.issuer != community {
        return Err(VerifyError::WrongIssuer);
    }
    if parsed.issued_at != created_at || parsed.valid_until != created_at.saturating_add(1) {
        return Err(VerifyError::Malformed("genesis times differ"));
    }
    Ok(Genesis {
        community,
        created_at,
        max_validity,
        founding_key,
        fingerprint: fingerprint(document),
    })
}
