
use serde::{Deserialize, Serialize};

pub struct Attribute {
    pub name: String,
    pub value: AttributeValue,
    pub salt: [u8; 32],        // each attribute has a randomised salt value
    pub leaf_index: usize,
}

pub enum AttributeValue {
    String(String),
    Number(i64),
    Boolean(bool)
}

pub struct Credential {
    pub credential_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    
    // Merkle tree data
    pub merkle_root: [u8; 32],
    pub attributes: Vec<Attribute>,
    
    pub signature: DilithiumSignature,
}

pub struct DilithiumSignature {
    pub public_key: Vec<u8>,    // ~1952 bytes for Dilithium3
    pub signature: Vec<u8>,      // ~3293 bytes for Dilithium3
}