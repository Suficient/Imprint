
pub struct Credential {
    pub credential_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    
    // Merkle tree data
    pub merkle_root: [u8; 32],
    //pub attributes: AttributeSet,
    
    pub signature: DilithiumSignature,
}

pub struct DilithiumSignature {
    pub public_key: Vec<u8>,    // ~1952 bytes for Dilithium3
    pub signature: Vec<u8>,      // ~3293 bytes for Dilithium3
}