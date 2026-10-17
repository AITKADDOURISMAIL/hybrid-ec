//! Layer B: model-specific arithmetic. Research prototype, NOT audited.
#![forbid(unsafe_code)]
pub mod secp256k1;
pub mod ed25519;
pub mod x25519;
pub mod group;
pub mod fixed_base;
pub mod wnaf;
pub mod bn;
pub mod glv;
pub mod pippenger;
