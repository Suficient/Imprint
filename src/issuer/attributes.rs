use crate::crypto::{
    domain_tags,
    field::{Digest, F, SALT_ELEMS, Salt},
    poseidon2::{RATE, hash_many},
};
use crate::issuer::{
    encoding::{CHUNK_BYTES, encode_bytes},
    types::DobType,
};
use rust_iso3166;

/// Sponge blocks per name preimage. The name preimage is
/// `tag(1) + length(1) + chunks(C) + salt(8)`, zero-padded to this many rate
/// blocks, so the in-circuit hash is a static chain of exactly this many
/// permutation instances. **Protocol constant**
pub const NAME_PREIMAGE_BLOCKS: usize = 5;

// Per-attribute sponge block budgets. Every attribute owns its own constant:
// they all happen to be 2 today (`tag(1) + value(1) + salt(8)` = 10 elements,
// zero-padded to 16 — each value is a single element since gender ≤ 3,
// country numeric ≤ 999, and DOB days are bounded < 2^24 by validation), but
// they are independent protocol constants.

/// Sponge blocks per gender preimage. **Protocol constant.**
pub const GENDER_PREIMAGE_BLOCKS: usize = 2;

/// Sponge blocks per DOB preimage. **Protocol constant.**
pub const DOB_PREIMAGE_BLOCKS: usize = 2;

/// Sponge blocks per country preimage. **Protocol constant.**
pub const COUNTRY_PREIMAGE_BLOCKS: usize = 2;

/// Maximum name chunks, derived from the block budget:
/// `C_MAX = RATE x B − (tag + length + salt)`.
pub const NAME_MAX_CHUNKS: usize = NAME_PREIMAGE_BLOCKS * RATE - (1 + 1 + SALT_ELEMS);

/// Maximum name length in **bytes**, derived from the AIR block budget rather
/// than chosen independently — validation imports this, so the byte cap and
/// the circuit layout can never drift apart. With B = 5: 3 · 30 = 90 bytes,
/// which covers English names up to 80 characters (and ~30 characters of
/// 3-byte UTF-8 scripts).
pub const NAME_MAX_BYTES: usize = NAME_MAX_CHUNKS * CHUNK_BYTES;

pub trait Attribute {
    const DOMAIN_TAG: F;

    /// Number of sponge rate blocks this attribute's preimage is padded to.
    /// **protocol constant**: the in-circuit hash for this attribute type is a
    /// static chain of exactly this many permutation instances.
    const PREIMAGE_BLOCKS: usize;

    fn value_to_field(&self) -> Vec<F>;

    fn salt(&self) -> Salt;

    /// Leaf hash: sponge over `[domain_tag] ++ value ++ salt`, zero-padded to
    /// exactly `PREIMAGE_BLOCKS x RATE` elements so every preimage of this
    /// attribute type has the same fixed length. Fixed length is necessary to
    /// keep AIRs free of conditional logic.
    ///
    /// Panics if the unpadded preimage exceeds the block budget — should never
    /// happen due to validation being called before hashing.
    fn hash(&self) -> Digest {
        let padded_len = Self::PREIMAGE_BLOCKS * RATE;
        let mut preimage: Vec<F> = Vec::with_capacity(padded_len);
        preimage.push(Self::DOMAIN_TAG);
        preimage.extend(self.value_to_field());
        preimage.extend_from_slice(&self.salt());
        assert!(
            preimage.len() <= padded_len,
            "preimage ({} elements) exceeds PREIMAGE_BLOCKS budget ({} elements); \
             validation should have rejected this value",
            preimage.len(),
            padded_len,
        );
        preimage.resize(padded_len, F::new(0));
        hash_many(&preimage)
    }
}

#[derive(Debug)]
pub struct NameAttribute {
    value: String,
    salt: Salt,
}

impl NameAttribute {
    pub fn new(name: String, salt: Salt) -> Self {
        Self { value: name, salt }
    }
}

impl Attribute for NameAttribute {
    const DOMAIN_TAG: F = domain_tags::NAME;
    const PREIMAGE_BLOCKS: usize = NAME_PREIMAGE_BLOCKS;

    fn value_to_field(&self) -> Vec<F> {
        encode_bytes(self.value.as_bytes())
    }

    fn salt(&self) -> Salt {
        self.salt
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Gender {
    Male,
    Female,
    Other,
}

impl Gender {
    pub fn as_u32(&self) -> u32 {
        match self {
            Gender::Male => 1,
            Gender::Female => 2,
            Gender::Other => 3,
        }
    }
}

#[derive(Debug)]
pub struct GenderAttribute {
    value: Gender,
    salt: Salt,
}

impl GenderAttribute {
    pub fn new(gender: Gender, salt: Salt) -> Self {
        Self { value: gender, salt }
    }
}

impl Attribute for GenderAttribute {
    const DOMAIN_TAG: F = domain_tags::GENDER;
    const PREIMAGE_BLOCKS: usize = GENDER_PREIMAGE_BLOCKS;

    // One element: the value is 1, 2, or 3.
    fn value_to_field(&self) -> Vec<F> {
        vec![F::new(self.value.as_u32())]
    }

    fn salt(&self) -> Salt {
        self.salt
    }
}

#[derive(Debug)]
pub struct DOBAttribute {
    value: DobType, // days since 1900-01-01
    salt: Salt,
}

impl DOBAttribute {
    pub fn new(date: DobType, salt: Salt) -> Self {
        Self { value: date, salt }
    }
}

impl Attribute for DOBAttribute {
    const DOMAIN_TAG: F = domain_tags::DOB;
    const PREIMAGE_BLOCKS: usize = DOB_PREIMAGE_BLOCKS;

    // One element: days since 1900, bounded < 2^24 by the not-in-the-future
    // validation — which is also what makes the age predicate a plain 24-bit
    // range check in-circuit.
    fn value_to_field(&self) -> Vec<F> {
        vec![F::new(self.value.value())]
    }

    fn salt(&self) -> Salt {
        self.salt
    }
}

#[derive(Debug)]
pub struct CountryAttribute {
    value: rust_iso3166::CountryCode,
    salt: Salt,
}

impl CountryAttribute {
    pub fn new(country: rust_iso3166::CountryCode, salt: Salt) -> Self {
        Self { value: country, salt }
    }
}

impl Attribute for CountryAttribute {
    const DOMAIN_TAG: F = domain_tags::COUNTRY;
    const PREIMAGE_BLOCKS: usize = COUNTRY_PREIMAGE_BLOCKS;

    // While the alpha3 value is used everywhere else in the code, the ZK
    // circuits for country codes use the numeric value. One element: ISO
    // 3166-1 numeric codes are ≤ 999.
    fn value_to_field(&self) -> Vec<F> {
        vec![F::new(self.value.numeric as u32)]
    }

    fn salt(&self) -> Salt {
        self.salt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_salt() -> Salt {
        std::array::from_fn(|i| F::new((i + 1) as u32))
    }

    #[test]
    fn hash_pads_preimage_to_fixed_blocks() {
        // The leaf hash must equal a sponge call over the explicitly
        // zero-padded preimage — this is the layout the AIR will reproduce:
        // [tag, value, salt(8), 0, 0, 0, 0, 0, 0].
        let attr = GenderAttribute::new(Gender::Female, test_salt());

        let mut preimage = vec![GenderAttribute::DOMAIN_TAG, F::new(2)];
        preimage.extend_from_slice(&test_salt());
        preimage.resize(GENDER_PREIMAGE_BLOCKS * RATE, F::new(0));
        assert_eq!(preimage.len(), 16);

        assert_eq!(attr.hash(), hash_many(&preimage));
    }

    #[test]
    fn numeric_attributes_encode_as_single_element() {
        // Layout-freezing: each numeric attribute is exactly one field
        // element holding its natural value — no limb decomposition.
        let gender = GenderAttribute::new(Gender::Other, test_salt());
        assert_eq!(gender.value_to_field(), vec![F::new(3)]);

        let dob = DOBAttribute::new(DobType(38_882), test_salt());
        assert_eq!(dob.value_to_field(), vec![F::new(38_882)]);

        let ind = rust_iso3166::from_alpha3("IND").unwrap();
        let country = CountryAttribute::new(ind, test_salt());
        assert_eq!(country.value_to_field(), vec![F::new(356)]);
    }

    #[test]
    fn name_block_budget_constants() {
        // 5 blocks × 8 rate − (tag + length + salt) = 30 chunks = 90 bytes.
        assert_eq!(NAME_MAX_CHUNKS, 30);
        assert_eq!(NAME_MAX_BYTES, 90);
    }

    #[test]
    fn max_length_name_fits_block_budget() {
        // A NAME_MAX_BYTES-byte name fills the budget exactly: 1 tag +
        // 1 length + 30 chunks + 8 salt = 40 = 5 blocks. Must not panic.
        let name = "a".repeat(NAME_MAX_BYTES);
        let attr = NameAttribute::new(name, test_salt());
        let _ = attr.hash();
    }

    #[test]
    fn padding_is_not_ambiguous_with_short_names() {
        // Two names that pad to the same block count still hash differently
        // (the length element pins the meaningful span).
        let a = NameAttribute::new("AB".into(), test_salt());
        let b = NameAttribute::new("AB\0".into(), test_salt());
        assert_ne!(a.hash(), b.hash());
    }
}
