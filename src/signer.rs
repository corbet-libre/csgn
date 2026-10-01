//! Signing: the secret key wrapper and the per-level signer with rotation.

use core::fmt;
use std::collections::BTreeSet;

use coset::{CoseSign1Builder, TaggedCborSerializable};
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use rand_core::{CryptoRng, Rng};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::cose::{self, EXTERNAL_AAD};
use crate::ring::{KeyEntry, KeyRing};
use crate::{KeyId, Kind};
#[cfg(feature = "volatile-signer")]
use crate::{Verified, VerifyError};

/// Length of an Ed25519 secret key seed in bytes.
pub const SEED_LEN: usize = 32;

/// An Ed25519 signing key.
///
/// There is no way to read the secret back: no getter, no serialization, no `Clone`, and
/// `Debug` prints only the key ID. The key lives on the heap so moves do not copy it, and it
/// is wiped when dropped.
///
/// ```compile_fail
/// let key = csgn::SecretKey::from_seed(&mut [1; 32]);
/// let seed = key.to_bytes(); // Private bytes are never exported.
/// ```
///
/// ```compile_fail
/// let key = csgn::SecretKey::from_seed(&mut [1; 32]);
/// let duplicate = key.clone(); // Secret ownership cannot be duplicated.
/// ```
pub struct SecretKey {
    inner: Box<SigningKey>,
    key_id: KeyId,
}

impl SecretKey {
    /// Loads a key from its 32-byte seed and wipes the caller's buffer.
    pub fn from_seed(seed: &mut [u8; SEED_LEN]) -> SecretKey {
        let inner = Box::new(SigningKey::from_bytes(seed));
        seed.zeroize();
        let key_id = KeyId::from_public_key(inner.verifying_key().as_bytes());
        SecretKey { inner, key_id }
    }

    /// Generates an ephemeral, non-exportable key from a cryptographically secure RNG.
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> SecretKey {
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        Rng::fill_bytes(rng, &mut *seed);
        SecretKey::from_seed(&mut seed)
    }

    /// The key ID (RFC 9679 thumbprint of the public key).
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// The Ed25519 public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.inner.verifying_key().to_bytes()
    }

    fn verifying_key(&self) -> VerifyingKey {
        self.inner.verifying_key()
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.inner.sign(message).to_bytes().to_vec()
    }
}

impl ZeroizeOnDrop for SecretKey {}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

/// Signs credentials and snapshots for one level (global or community) and keeps its key ring.
///
/// Holds exactly one secret key, the active one. Rotation replaces it; the old public key
/// stays in the ring until everything it signed has expired. All times are Unix seconds and
/// come from the caller, so behaviour is deterministic and works without a system clock.
pub struct Signer {
    ring: KeyRing,
    active: SecretKey,
    max_validity: u64,
    active_signed_until: u64,
    clock: u64,
    used_ids: BTreeSet<KeyId>,
    ring_revision: u64,
    pending_transition: Option<Vec<u8>>,
}

impl Signer {
    /// Starts a new key ring for `issuer` with `key` active from `now`.
    ///
    /// `max_validity` bounds how far past its issued time anything may be valid.
    /// It is retained unchanged in exact recovery metadata.
    pub fn new(
        issuer: impl Into<String>,
        key: SecretKey,
        now: u64,
        max_validity: u64,
    ) -> Result<Signer, SignError> {
        let issuer = issuer.into();
        if issuer.is_empty() || issuer.len() > crate::MAX_ISSUER_LEN || issuer.contains('\0') {
            return Err(SignError::InvalidIssuer);
        }
        if max_validity == 0 {
            return Err(SignError::InvalidMaxValidity);
        }
        let entry = KeyEntry::new_active(key.key_id(), key.verifying_key(), now);
        Ok(Signer {
            ring: KeyRing::new(issuer, entry, max_validity),
            used_ids: BTreeSet::from([key.key_id()]),
            active: key,
            max_validity,
            active_signed_until: 0,
            clock: now,
            ring_revision: 0,
            pending_transition: None,
        })
    }

    /// Resume exactly persisted state with its active key from the secret store.
    ///
    /// Never reconstruct state from a published ring. Use [`crate::PersistentSigner`]
    /// to persist every successful change before returning signed bytes.
    pub fn resume(state: crate::SigningState, key: SecretKey, now: u64) -> Result<Self, SignError> {
        if state.ring.active().map(KeyEntry::key_id) != Some(key.key_id()) {
            return Err(SignError::KeyMismatch);
        }
        if now < state.clock {
            return Err(SignError::ClockBeforeActivation);
        }
        Ok(Self {
            ring: state.ring,
            active: key,
            max_validity: state.max_validity,
            active_signed_until: state.active_signed_until,
            clock: now,
            used_ids: state.used_ids,
            ring_revision: state.ring_revision,
            pending_transition: state.pending_transition,
        })
    }

    /// Private operational metadata for exact recovery; never publish it.
    pub fn state(&self) -> crate::SigningState {
        crate::SigningState {
            ring: self.ring.clone(),
            max_validity: self.max_validity,
            active_signed_until: self.active_signed_until,
            clock: self.clock,
            used_ids: self.used_ids.clone(),
            ring_revision: self.ring_revision,
            pending_transition: self.pending_transition.clone(),
        }
    }

    /// Signs `payload` as `kind`, issued `now` and valid until `valid_until` (exclusive).
    ///
    /// Returns a tagged COSE_Sign1 (RFC 9052) with an Ed25519 signature. Records
    /// `valid_until` privately as the active retention deadline if it is the latest so far.
    pub fn sign(
        &mut self,
        kind: Kind,
        payload: &[u8],
        now: u64,
        valid_until: u64,
    ) -> Result<Vec<u8>, SignError> {
        if payload.len() > crate::MAX_PAYLOAD_LEN {
            return Err(SignError::LimitExceeded);
        }
        let issuer = self.ring.issuer().to_owned();
        let max_validity = self.max_validity;
        let entry = self.ring.active_mut().ok_or(SignError::KeyMismatch)?;
        if entry.key_id != self.active.key_id() {
            return Err(SignError::KeyMismatch);
        }
        if now < self.clock {
            return Err(SignError::ClockBeforeActivation);
        }
        if valid_until <= now {
            return Err(SignError::InvalidValidity);
        }
        if valid_until - now > max_validity {
            return Err(SignError::ValidityTooLong);
        }

        let protected = cose::protected_header(&entry.key_id, kind, &issuer, now, valid_until);
        let active = &self.active;
        let message = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload.to_vec())
            .create_signature(EXTERNAL_AAD, |signed_data| active.sign(signed_data))
            .build()
            .to_tagged_vec()
            .map_err(|_| SignError::Encoding)?;

        self.active_signed_until = self.active_signed_until.max(valid_until);
        self.clock = now;
        Ok(message)
    }

    /// Makes `new_key` the active key from `now` and retires the current one.
    ///
    /// The retired public key stays until the latest expiry rounded up to a UTC day;
    /// its secret is wiped. Retired keys that have expired are dropped. A key that was in the ring
    /// before is refused.
    pub fn rotate(&mut self, new_key: SecretKey, now: u64) -> Result<(), SignError> {
        if self.ring_revision != 0 {
            return Err(SignError::TransitionRequired);
        }
        let ring = self.rotation_ring(&new_key, now, self.active_signed_until)?;
        self.install_rotation(new_key, ring, now);
        Ok(())
    }

    fn rotation_ring(
        &self,
        new_key: &SecretKey,
        now: u64,
        signed_until: u64,
    ) -> Result<KeyRing, SignError> {
        if self.used_ids.contains(&new_key.key_id()) {
            return Err(SignError::KeyReused);
        }
        if self.used_ids.len() >= crate::MAX_USED_KEYS
            || self
                .ring
                .keys()
                .iter()
                .filter(|key| !key.is_expired(now))
                .count()
                >= crate::MAX_RING_KEYS
        {
            return Err(SignError::LimitExceeded);
        }
        if now < self.clock {
            return Err(SignError::ClockBeforeActivation);
        }
        let mut ring = self.ring.clone();
        let entry = ring.active_mut().ok_or(SignError::KeyMismatch)?;
        entry.retired_at = Some(now);
        entry.signed_until = crate::ring::rounded_deadline(signed_until);
        ring.push(KeyEntry::new_active(
            new_key.key_id(),
            new_key.verifying_key(),
            now,
        ));
        ring.prune(now);
        Ok(ring)
    }

    fn install_rotation(&mut self, new_key: SecretKey, ring: KeyRing, now: u64) {
        self.ring = ring;
        self.active_signed_until = 0;
        self.used_ids.insert(new_key.key_id());
        self.clock = now;
        self.active = new_key;
    }

    /// Drops retired keys; continuity-mode issuers must use a proof instead.
    pub fn prune(&mut self, now: u64) -> Result<(), SignError> {
        if self.ring_revision != 0 {
            return Err(SignError::TransitionRequired);
        }
        if now < self.clock {
            return Err(SignError::ClockBeforeActivation);
        }
        self.ring.prune(now);
        self.clock = now;
        Ok(())
    }

    /// Endorse a rotation and retain its proof in memory. Persist state before publishing.
    /// The low-level Signer is exported only by the volatile-signer feature.
    pub fn rotate_with_proof(
        &mut self,
        new_key: SecretKey,
        now: u64,
        valid_until: u64,
    ) -> Result<Vec<u8>, SignError> {
        let revision = self.next_ring_revision()?;
        let next = self.rotation_ring(&new_key, now, self.active_signed_until.max(valid_until))?;
        let payload = crate::VerifiedTransition {
            revision,
            previous: self.ring.clone(),
            next: next.clone(),
        }
        .payload();
        let proof = self.sign(Kind::KeyRingTransition, &payload, now, valid_until)?;
        self.install_rotation(new_key, next, now);
        self.ring_revision = revision;
        self.pending_transition = Some(proof.clone());
        Ok(proof)
    }

    /// Endorse removal of expired keys; return None without a public ring change.
    /// The caller must persist state before exposing a proof or successor ring.
    pub fn prune_with_proof(
        &mut self,
        now: u64,
        valid_until: u64,
    ) -> Result<Option<Vec<u8>>, SignError> {
        let revision = self.next_ring_revision()?;
        if now < self.clock {
            return Err(SignError::ClockBeforeActivation);
        }
        let mut next = self.ring.clone();
        next.prune(now);
        if next == self.ring {
            self.clock = now;
            return Ok(None);
        }
        let payload = crate::VerifiedTransition {
            revision,
            previous: self.ring.clone(),
            next: next.clone(),
        }
        .payload();
        let proof = self.sign(Kind::KeyRingTransition, &payload, now, valid_until)?;
        self.ring = next;
        self.ring_revision = revision;
        self.pending_transition = Some(proof.clone());
        Ok(Some(proof))
    }

    fn next_ring_revision(&self) -> Result<u64, SignError> {
        if self.pending_transition.is_some() {
            return Err(SignError::TransitionPending);
        }
        self.ring_revision
            .checked_add(1)
            .ok_or(SignError::LimitExceeded)
    }

    /// Original unacknowledged proof in this state. Durable callers use PersistentSigner.
    pub fn pending_transition(&self) -> Option<&[u8]> {
        self.pending_transition.as_deref()
    }

    /// Public ring-only sequence, independent of ordinary signing activity.
    pub fn ring_revision(&self) -> u64 {
        self.ring_revision
    }

    /// Clear the matching proof after the consumer retains it. Persist the updated state.
    pub fn acknowledge_transition(&mut self, revision: u64) -> Result<(), SignError> {
        if revision != self.ring_revision || self.pending_transition.is_none() {
            return Err(SignError::InvalidTransition);
        }
        self.pending_transition = None;
        Ok(())
    }

    /// The public verification ring. Persist `state()` separately for recovery.
    pub fn key_ring(&self) -> &KeyRing {
        &self.ring
    }

    /// The ID of the key currently signing.
    #[cfg(feature = "volatile-signer")]
    pub fn active_key_id(&self) -> KeyId {
        self.active.key_id()
    }

    /// The longest validity [`Signer::sign`] accepts, in seconds.
    #[cfg(feature = "volatile-signer")]
    pub fn max_validity(&self) -> u64 {
        self.max_validity
    }

    /// Verifies against this signer's own key ring; see [`KeyRing::verify`].
    #[cfg(feature = "volatile-signer")]
    pub fn verify(&self, cose: &[u8], expected: Kind, now: u64) -> Result<Verified, VerifyError> {
        self.ring.verify(cose, expected, now)
    }
}

impl fmt::Debug for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signer")
            .field("issuer", &self.ring.issuer())
            .field("active_key_id", &self.active.key_id())
            .field("max_validity", &self.max_validity)
            .field("ring", &self.ring)
            .finish()
    }
}

/// Why signing, starting, resuming or rotating was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignError {
    /// The issuer is empty, too long or contains NUL.
    InvalidIssuer,
    /// The maximum validity is zero.
    InvalidMaxValidity,
    /// The key does not match the ring's active key (or the ring has none).
    KeyMismatch,
    /// The new key is already in the ring.
    KeyReused,
    /// The clock is earlier than the last successful operation.
    ClockBeforeActivation,
    /// `valid_until` is not after `now`.
    InvalidValidity,
    /// `valid_until` is further from `now` than the maximum validity.
    ValidityTooLong,
    /// A payload, ring or key history exceeds the documented resource limit.
    LimitExceeded,
    /// Another ring change must wait for durable retention of the pending proof.
    TransitionPending,
    /// This issuer has enabled continuity and must endorse every ring change.
    TransitionRequired,
    /// No pending proof matches the supplied ring revision.
    InvalidTransition,
    /// COSE encoding failed.
    Encoding,
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SignError::InvalidIssuer => "issuer is empty, too long or contains NUL",
            SignError::InvalidMaxValidity => "maximum validity is zero",
            SignError::KeyMismatch => "key is not the key ring's active key",
            SignError::KeyReused => "key is already in the key ring",
            SignError::ClockBeforeActivation => "clock is before the last successful operation",
            SignError::InvalidValidity => "validity does not end after now",
            SignError::ValidityTooLong => "validity exceeds the maximum",
            SignError::Encoding => "COSE encoding failed",
            SignError::TransitionPending => "key-ring transition awaits durable acknowledgement",
            SignError::TransitionRequired => "key-ring continuity proof required",
            SignError::InvalidTransition => "pending key-ring transition mismatch",
            SignError::LimitExceeded => "resource limit exceeded",
        })
    }
}

impl std::error::Error for SignError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_delegate_erasure_to_dalek() {
        fn requires_erasure<T: ZeroizeOnDrop>() {}
        requires_erasure::<SigningKey>();
        requires_erasure::<SecretKey>();
        let mut seed = [7u8; SEED_LEN];
        let key = SecretKey::from_seed(&mut seed);
        assert_eq!(seed, [0u8; SEED_LEN]);
        assert_ne!(key.public_key(), [0u8; 32]);
    }
}
