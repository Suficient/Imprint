//! Domain-separation tags, one per attribute type.
//!
//! Each leaf preimage starts with its tag so that hashes of different
//! attribute types can never collide even on identical values/salts.
//! Internal Merkle nodes need no tag: they use a 2-to-1 truncated-permutation
//! compression, a different construction from the leaf sponge, so the leaf
//! and node domains are already separated structurally.

use crate::crypto::field::F;

pub const NAME: F = F::new(1);
pub const GENDER: F = F::new(2);
pub const DOB: F = F::new(3);
pub const COUNTRY: F = F::new(4);
