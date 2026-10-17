//! Thin wrappers over reference libraries (feature "baselines"): same inputs, boolean verdicts.
pub fn dalek_verify(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64], strict: bool) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let Ok(vk) = VerifyingKey::from_bytes(pk) else { return false };
    let sig = Signature::from_bytes(sig);
    if strict { vk.verify_strict(msg, &sig).is_ok() } else { vk.verify(msg, &sig).is_ok() }
}
/// ed25519-zebra implements ZIP-215 (permissive decoding + cofactored equation).
pub fn zebra_verify(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(vk) = ed25519_zebra::VerificationKey::try_from(&pk[..]) else { return false };
    vk.verify(&ed25519_zebra::Signature::from(*sig), msg).is_ok()
}
pub fn libsecp_schnorr(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    use secp256k1::{schnorr::Signature, Message, XOnlyPublicKey};
    // the crate API takes 32-byte messages only; callers must filter other lengths
    let Ok(m): Result<[u8; 32], _> = msg.try_into() else { return false };
    let Ok(pk) = XOnlyPublicKey::from_slice(pk) else { return false };
    let Ok(sig) = Signature::from_slice(sig) else { return false };
    ctx().verify_schnorr(&sig, &Message::from_digest(m), &pk).is_ok()
}
pub fn libsecp_ecdsa(qx: &[u8; 32], qy: &[u8; 32], z: &[u8; 32], r: &[u8; 32], s: &[u8; 32], normalize_s: bool) -> bool {
    use secp256k1::{ecdsa::Signature, Message, PublicKey};
    let mut full = [0u8; 65]; full[0] = 4; full[1..33].copy_from_slice(qx); full[33..].copy_from_slice(qy);
    let Ok(pk) = PublicKey::from_slice(&full) else { return false };
    let mut c = [0u8; 64]; c[..32].copy_from_slice(r); c[32..].copy_from_slice(s);
    let Ok(mut sig) = Signature::from_compact(&c) else { return false };
    if normalize_s { sig.normalize_s(); }
    ctx().verify_ecdsa(&Message::from_digest(*z), &sig, &pk).is_ok()
}
pub fn k256_schnorr(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    use k256::schnorr::{Signature, VerifyingKey};
    let Ok(vk) = VerifyingKey::from_bytes(pk) else { return false };
    let Ok(sig) = Signature::try_from(&sig[..]) else { return false };
    vk.verify_raw(msg, &sig).is_ok()
}
pub fn k256_ecdsa(qx: &[u8; 32], qy: &[u8; 32], z: &[u8; 32], r: &[u8; 32], s: &[u8; 32]) -> bool {
    use k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
    let mut full = [0u8; 65]; full[0] = 4; full[1..33].copy_from_slice(qx); full[33..].copy_from_slice(qy);
    let Ok(vk) = VerifyingKey::from_sec1_bytes(&full) else { return false };
    let mut c = [0u8; 64]; c[..32].copy_from_slice(r); c[32..].copy_from_slice(s);
    let Ok(sig) = Signature::from_slice(&c) else { return false };
    vk.verify_prehash(z, &sig).is_ok()
}

fn ctx() -> &'static secp256k1::Secp256k1<secp256k1::VerifyOnly> {
    static C: std::sync::OnceLock<secp256k1::Secp256k1<secp256k1::VerifyOnly>> = std::sync::OnceLock::new();
    C.get_or_init(secp256k1::Secp256k1::verification_only)
}
