
use serde::{Deserialize, Serialize};
use ml_dsa::{Signature};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attribute {
    pub name: String,
    pub value: String,
    pub salt: [u8; 32],        // each attribute has a randomised salt value
    pub leaf_index: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub credential_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    
    // Merkle tree data
    pub merkle_root: [u8; 32],
    pub attributes: Vec<Attribute>,
    
    pub signature: DilithiumSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DilithiumSignature {
    pub public_key: Vec<u8>,    // ~1952 bytes for Dilithium3
    pub signature: Vec<u8>,      // ~3293 bytes for Dilithium3
}