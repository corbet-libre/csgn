//! Typed public ring transitions carried in the existing COSE envelope.

use coset::CborSerializable;
use coset::cbor::value::Value;

use crate::cose::{as_u64, int, int_map, take};
use crate::{KeyRing, Kind, VerifyError};

/// A signature-verified ring transition, not an installation decision.
///
/// The caller must compare `previous()` with its installed ring and enforce its
/// permanent revision floor before atomically storing `next()` and the proof.
/// An initial ring always comes from deployment configuration, never this object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedTransition {
    pub(crate) revision: u64,
    pub(crate) previous: KeyRing,
    pub(crate) next: KeyRing,
}

impl VerifiedTransition {
    /// Positive sequence that advances only when the public ring changes.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Exact public ring endorsed as the predecessor.
    pub fn previous(&self) -> &KeyRing {
        &self.previous
    }

    /// Exact proposed successor ring.
    pub fn next(&self) -> &KeyRing {
        &self.next
    }

    pub(crate) fn payload(&self) -> Vec<u8> {
        Value::Map(vec![
            (int(1), int(1)),
            (int(2), Value::Text(self.previous.issuer().to_owned())),
            (int(3), Value::Integer(self.revision.into())),
            (int(4), Value::Bytes(self.previous.to_cbor())),
            (int(5), Value::Bytes(self.next.to_cbor())),
        ])
        .to_vec()
        .expect("validated public rings always encode")
    }

    fn decode(payload: &[u8]) -> Result<Self, VerifyError> {
        let bad = VerifyError::Malformed("invalid key-ring transition");
        let mut fields = Value::from_slice(payload)
            .ok()
            .and_then(int_map)
            .ok_or(bad.clone())?;
        if take(&mut fields, 1) != Some(int(1)) {
            return Err(bad);
        }
        let Some(Value::Text(issuer)) = take(&mut fields, 2) else {
            return Err(bad);
        };
        let revision = take(&mut fields, 3)
            .and_then(as_u64)
            .filter(|value| *value > 0)
            .ok_or(bad.clone())?;
        let Some(Value::Bytes(previous)) = take(&mut fields, 4) else {
            return Err(bad);
        };
        let Some(Value::Bytes(next)) = take(&mut fields, 5) else {
            return Err(bad);
        };
        let previous = KeyRing::from_cbor(&previous).map_err(|_| bad.clone())?;
        let next = KeyRing::from_cbor(&next).map_err(|_| bad.clone())?;
        if !fields.is_empty()
            || previous.issuer() != issuer
            || next.issuer() != issuer
            || previous.max_validity() != next.max_validity()
            || previous.active().is_none()
            || next.active().is_none()
        {
            return Err(bad);
        }
        let value = Self {
            revision,
            previous,
            next,
        };
        if value.payload() != payload {
            return Err(bad);
        }
        Ok(value)
    }
}

/// Verify one original COSE proof using a caller-trusted ring and time.
///
/// This uses the existing strict Ed25519/COSE verifier, including expiry. It
/// checks kind, issuer and the predecessor's active signing key. Charter owns
/// installed-ring equality, the permanent revision floor and chain installation.
/// Never obtain `trusted` from the response being verified.
pub fn verify_transition(
    trusted: &KeyRing,
    proof: &[u8],
    now: u64,
) -> Result<VerifiedTransition, VerifyError> {
    let verified = trusted.verify(proof, Kind::KeyRingTransition, now)?;
    let transition = VerifiedTransition::decode(verified.payload())?;
    if transition.previous.issuer() != trusted.issuer()
        || transition.previous.active().map(|key| key.key_id()) != Some(verified.key_id())
    {
        return Err(VerifyError::Malformed(
            "transition issuer or active key mismatch",
        ));
    }
    Ok(transition)
}

/// Verifies a transition proof at its own issue time against the ring it names as
/// predecessor's trusted copy. For walking a chain from the genesis ring long
/// after the intermediate proofs expired: the proof is still a signature by the
/// previous ring's active key, only its freshness is not asked.
pub fn verify_transition_at_issue(
    trusted: &KeyRing,
    proof: &[u8],
) -> Result<VerifiedTransition, VerifyError> {
    let issued = crate::cose::parse(proof)?.issued_at;
    verify_transition(trusted, proof, issued)
}

#[cfg(feature = "signer")]
pub(crate) fn recovery_transition(proof: &[u8]) -> Result<VerifiedTransition, VerifyError> {
    // Recovery checks historical proof consistency, not current publication
    // freshness. The consumer still verifies using its current trusted clock.
    let parsed = crate::cose::parse(proof)?;
    let issued = parsed.issued_at;
    let transition = VerifiedTransition::decode(&parsed.into_payload())?;
    verify_transition(&transition.previous, proof, issued)
}
