use ark_bn254::Fr;
use ark_serialize::CanonicalSerialize;

use crate::{
    crypto::poseidon_ark_import::poseidon_hash,
    issuer::{
        attribute_set::AttributeSet,
        error::{AttrTreeError},
        types::MerkleProof,
    },
};
#[derive(Debug)]
pub struct AttributeTree {
    leaves: [Fr; 4],
    nodes: [Fr; 2],
    root: Fr,
}

impl AttributeTree {
    const NODE_DOMAIN_TAG: u64 = 0;
    pub fn new(set: &AttributeSet) -> Result<Self, AttrTreeError> {
        let hashed_leaves: [Fr; 4] = Self::generate_leaves(set)?;
        let hashed_nodes: [Fr; 2] = Self::generate_nodes(hashed_leaves)?;
        let hashed_root: Fr = Self::hash_node(hashed_nodes[0], hashed_nodes[1])?;

        Ok(AttributeTree {
            leaves: hashed_leaves,
            nodes: hashed_nodes,
            root: hashed_root,
        })
    }

    pub fn root(&self) -> Fr {
        self.root
    }

    /// returns root as 32 bytes, little endian.
    pub fn root_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.root.serialize_compressed(&mut bytes[..]).unwrap(); // this unwrap is unreachable.
        bytes
    }

    /// Returns merkle proof for a specific leaf in the form of a MerkleProof Struct.
    pub fn merkle_proof(&self, leaf_index: usize) -> Result<MerkleProof, AttrTreeError> {
        // using a dumb exhaustive implementation bc tree depth is tiny.
        let (leaf, leaf_sibling, leaf_is_left, node_sibling, node_is_left) = match leaf_index {
            0 => (self.leaves[0], self.leaves[1], true, self.nodes[1], true),
            1 => (self.leaves[1], self.leaves[0], false, self.nodes[1], true),
            2 => (self.leaves[2], self.leaves[3], true, self.nodes[0], false),
            3 => (self.leaves[3], self.leaves[2], false, self.nodes[0], false),
            _ => return Err(AttrTreeError::LeafIndexOutOfBounds { leaf_index }),
        };


        let proof = MerkleProof {
            leaf,
            leaf_index,
            siblings: vec![leaf_sibling, node_sibling],
            path: vec![leaf_is_left, node_is_left],
            root: self.root,
        };

        self.verify_proof(&proof)?;

        Ok(proof)
    }

    fn verify_proof(&self, proof: &MerkleProof) -> Result<(), AttrTreeError>{
        let mut current: Fr = proof.leaf;
        for (sibling, is_left) in proof.siblings.iter().zip(proof.path.iter()) {
            let (left, right) = if *is_left {
                (current, *sibling)
            } else {
                (*sibling, current)
            };
            current = Self::hash_node(left, right)?;
        }
        
        if current != proof.root {
            panic!("merkle proof verification failed. This should not happen! There is a bug in proof generation or tree construction code")
        }

        Ok(())
    }

    fn generate_leaves(set: &AttributeSet) -> Result<[Fr; 4], AttrTreeError> {
        set.leaf_hashes()
            .map_err(|(i, e)| AttrTreeError::LeafHashFailed {
                leaf_index: (i),
                source: (e),
            })
    }

    fn hash_node(left: Fr, right: Fr) -> Result<Fr, AttrTreeError> {
        poseidon_hash(vec![Fr::from(Self::NODE_DOMAIN_TAG), left, right])
            .map_err(|e| AttrTreeError::NodeHashFailed { source: e })
    }

    fn generate_nodes(leaves: [Fr; 4]) -> Result<[Fr; 2], AttrTreeError> {
        Ok([
            Self::hash_node(leaves[0], leaves[1])?,
            Self::hash_node(leaves[2], leaves[3])?,
        ])
    }
}


/*
    ATTRIBUTE TREE

    take AttributeSet, and turn it into a merkle tree. Used for proof computation and for
    credential generation.

    DESCRIPTION OF BEHAVIOUR

    Whenever a new attributeTree object is created, it takes in an AttrSet and generates a merkle
    root from it. This is meant to be a transient data structure, only existing during credential
    issuance and when a proof needs to be generated. As such, it will have only two values accessible
    through its api

    1) The merkle root. This will be accessible as an Fr element through root() and as bytes through
    root_bytes() [this is used for the dilithium signature]

    2) Merkle proof for a given leaf node, required for proof computation.

    Thus, it will have the following methods

    PUBLIC

        new(AttributeSet) : Constructor, takes attrset as input
        root() : returns merkle root
        root_bytes() : returns merkle root as bytes
        merkle_proof() : returns merkle proof for a given leaf

    PRIVATE

        verify_proof() : called within merkle_proof(). Recomputes a root from the proof. sanity check.
        generate_leaves() : hashes the elements within AttrSet. Returns an AttrTreeError: LeafHashFailed if fails.
        generate_nodes() : hashes leaves to make internal nodes. Returns an AttrTreeError: NodeHashFailed if fails.

*/
