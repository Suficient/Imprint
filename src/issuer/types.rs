use crate::issuer::{error::AttributeError, validation::validate_and_parse_dob};
use ark_bn254::Fr;

// This is the Date of birth type used universally within the project.
// It is defined as the number of days since 1900-01-01.
#[derive(Copy, Clone, Debug)]
pub struct DobType(pub u64);

impl DobType {
    pub fn from_yyyymmdd(ymd: u64) -> Result<u64, AttributeError> {
        let days: u64 = validate_and_parse_dob(ymd)?;
        Ok(days)
    }

    pub fn value(&self) -> u64 {
        self.0
    }

}

impl From<DobType> for u64 {
    fn from(d: DobType) -> Self {
        d.0
    }
}

/// Generalised struct to contain merkle proofs.
///
/// Contains a leaf, a vector of its siblings, and a path vector. A True value
/// in the path vector means that the current leaf is a left child. The length
/// of the vectors is always one less than the depth of the merkle tree.
pub struct MerkleProof {
    pub leaf: Fr,
    pub leaf_index: usize,
    pub siblings: Vec<Fr>,
    pub path: Vec<bool>, // true = leaf is left child at this level
    pub root: Fr,
}