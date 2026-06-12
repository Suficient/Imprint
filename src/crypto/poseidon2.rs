//! Poseidon2 hashing over KoalaBear, width 16.
//!
//! Two primitives, both built from one shared permutation instance:
//!   * [`hash_many`]  — sponge hash of an arbitrary-length field slice → [`Digest`].
//!   * [`compress`]   — 2-to-1 compression of two digests → one [`Digest`].
//!
//! Config:
//!   width 16, rate 8, capacity 8, output 8.

use once_cell::sync::Lazy;
use p3_koala_bear::{default_koalabear_poseidon2_16, Poseidon2KoalaBear};
use p3_symmetric::{PaddingFreeSponge, PseudoCompressionFunction, TruncatedPermutation, CryptographicHasher};

use crate::crypto::field::{Digest, F, DIGEST_ELEMS};

const WIDTH: usize = 16;

/// Sponge rate in field elements. Per-attribute preimage block counts
/// (`Attribute::PREIMAGE_BLOCKS`) are multiples of this
pub const RATE: usize = 8;

type Perm = Poseidon2KoalaBear<WIDTH>;
type Sponge = PaddingFreeSponge<Perm, WIDTH, RATE, DIGEST_ELEMS>;
type Compress = TruncatedPermutation<Perm, 2, DIGEST_ELEMS, WIDTH>;

static SPONGE: Lazy<Sponge> = Lazy::new(|| Sponge::new(default_koalabear_poseidon2_16()));
static COMPRESS: Lazy<Compress> = Lazy::new(|| Compress::new(default_koalabear_poseidon2_16()));

/// Sponge-hash a slice of field elements into a [`Digest`].
///
/// The sponge itself accepts any length, but `PaddingFreeSponge` is only
/// collision-safe when input lengths are fixed by the protocol. Callers must
/// pass preimages padded to a per-type constant block count (see
/// `Attribute::PREIMAGE_BLOCKS`)
pub fn hash_many(inputs: &[F]) -> Digest {
    SPONGE.hash_slice(inputs)
}

/// 2-to-1 compression of two digests, collision-resistant in a Merkle setting.
pub fn compress(left: Digest, right: Digest) -> Digest {
    COMPRESS.compress([left, right])
}
