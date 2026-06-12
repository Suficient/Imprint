use crate::crypto::field::Digest;
use crate::issuer::{error::AttributeError, validation::validate_and_parse_dob};

// This is the Date of birth type used universally within the project.
// It is defined as the number of days since 1900-01-01. A u32 holds that
// comfortably (2^24 days ≈ 45,000 years) and it encodes as a single field
// element
#[derive(Copy, Clone, Debug)]
pub struct DobType(pub u32);

impl DobType {
    pub fn from_yyyymmdd(ymd: u32) -> Result<u32, AttributeError> {
        let days: u32 = validate_and_parse_dob(ymd)?;
        Ok(days)
    }

    pub fn value(&self) -> u32 {
        self.0
    }
}

impl From<DobType> for u32 {
    fn from(d: DobType) -> Self {
        d.0
    }
}

/// Generalised struct to contain merkle proofs.
///
/// Contains a leaf digest, a vector of its sibling digests, and a path vector.
/// A True value in the path vector means that the current node is a left child
/// at that level. The length of the vectors equals the depth of the tree.
#[derive(Debug)]
pub struct MerkleProof {
    pub leaf: Digest,
    pub leaf_index: usize,
    pub siblings: Vec<Digest>,
    pub path: Vec<bool>, // true = node is left child at this level
    pub root: Digest,
}
