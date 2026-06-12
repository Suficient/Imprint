//! Core field types for STARK-side cryptography.
//! All issuer data operates only over the KoalaBear field.

use p3_koala_bear::KoalaBear;

/// The prime field used everywhere on the issuer side: `p = 2^31 - 2^24 + 1`.
pub type F = KoalaBear;

/// Number of field elements in a hash digest.
/// 8 × 31 bits ≈ 248 bits of collision resistance.
/// do not reduce.
pub const DIGEST_ELEMS: usize = 8;

/// A collision-resistant hash digest: 8 field elements, 32 bytes serialised.
/// Used for leaf hashes, internal Merkle nodes, and the root.
pub type Digest = [F; DIGEST_ELEMS];

/// Number of field elements in a salt.
/// 8 × 31 ≈ 248 bits of entropy.
pub const SALT_ELEMS: usize = 8;

/// Salt used in attribute leaves. Holder secret
pub type Salt = [F; SALT_ELEMS];
