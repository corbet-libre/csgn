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
