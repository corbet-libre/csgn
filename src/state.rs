//! Private operational metadata for crash recovery; never publish this state.

use std::collections::BTreeSet;

use coset::CborSerializable;
use coset::cbor::value::Value;

use crate::cose::{as_u64, int, int_map, take};
use crate::{KeyId, KeyRing, RingError};

/// Exact signing state, separate from the published verification ring.
///
/// Contains no secret, credential, member identifier or per-request record.
/// Must be stored before publishing a signature or rotation. Loading an older
/// backup can invalidate issued credentials; storage rollback protection belongs
/// to the deployment. Prefer [`crate::PersistentSigner`] for persistence ordering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningState {
    pub(crate) ring: KeyRing,
    pub(crate) max_validity: u64,
    pub(crate) active_signed_until: u64,
    pub(crate) clock: u64,
    pub(crate) used_ids: BTreeSet<KeyId>,
}

impl SigningState {
    /// The public ring at this state.
    pub fn key_ring(&self) -> &KeyRing {
        &self.ring
    }

    /// Encode private recovery metadata, including the exact active deadline.
    /// Never distribute this blob to verifiers; publish `key_ring()` instead.
    pub fn to_cbor(&self) -> Vec<u8> {
        Value::Map(vec![
            (int(1), int(2)),
            (int(2), Value::Bytes(self.ring.to_cbor())),
            (int(3), Value::Integer(self.max_validity.into())),
            (int(4), Value::Integer(self.clock.into())),
            (int(6), Value::Integer(self.active_signed_until.into())),
            (
                int(5),
                Value::Array(
                    self.used_ids
                        .iter()
                        .map(|id| Value::Bytes(id.as_bytes().to_vec()))
                        .collect(),
                ),
            ),
        ])
        .to_vec()
        .expect("validated recovery state always encodes")
    }

    /// Decode and validate exact signing metadata from trusted storage.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, RingError> {
        let bad = || RingError::Malformed("invalid signing state");
        if bytes.len() > 1024 * 1024 {
            return Err(bad());
        }
        let mut fields = Value::from_slice(bytes)
            .ok()
            .and_then(int_map)
            .ok_or_else(bad)?;
        if take(&mut fields, 1) != Some(int(2)) {
            return Err(RingError::UnsupportedVersion);
        }
        let ring = match take(&mut fields, 2) {
            Some(Value::Bytes(bytes)) => KeyRing::from_cbor(&bytes)?,
            _ => return Err(bad()),
        };
        let max_validity = take(&mut fields, 3)
            .and_then(as_u64)
            .filter(|v| *v > 0)
            .ok_or_else(bad)?;
        if max_validity != ring.max_validity() {
            return Err(bad());
        }
        let clock = take(&mut fields, 4).and_then(as_u64).ok_or_else(bad)?;
        let active_signed_until = take(&mut fields, 6).and_then(as_u64).ok_or_else(bad)?;
        let active = ring.active().ok_or_else(bad)?;
        if (active_signed_until != 0 && active_signed_until <= active.activated_at())
            || active_signed_until > clock.saturating_add(max_validity)
        {
            return Err(bad());
        }
        let Some(Value::Array(ids)) = take(&mut fields, 5) else {
            return Err(bad());
        };
        if !fields.is_empty() || ids.len() > crate::MAX_USED_KEYS || ring.active().is_none() {
            return Err(bad());
        }
        let mut used_ids = BTreeSet::new();
        for id in ids {
            let Value::Bytes(id) = id else {
                return Err(bad());
            };
            if !used_ids.insert(KeyId::from_slice(&id).ok_or_else(bad)?) {
                return Err(bad());
            }
        }
        for entry in ring.keys() {
            if !used_ids.contains(&entry.key_id())
                || entry.activated_at() > clock
                || entry.retired_at().is_some_and(|retired| retired > clock)
                || entry.signed_until()
                    > crate::ring::rounded_deadline(clock.saturating_add(max_validity))
            {
                return Err(bad());
            }
        }
        Ok(Self {
            ring,
            max_validity,
            active_signed_until,
            clock,
            used_ids,
        })
    }
}
