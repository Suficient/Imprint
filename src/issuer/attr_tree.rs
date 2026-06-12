use p3_field::PrimeField32;

use crate::{
    crypto::{
        field::Digest,
        poseidon2::compress,
    },
    issuer::{attribute_set::AttributeSet, error::AttrTreeError, types::MerkleProof},
};

#[derive(Debug)]
pub struct AttributeTree {
    leaves: [Digest; 4],
    nodes: [Digest; 2],
    root: Digest,
}

impl AttributeTree {
    pub fn new(set: &AttributeSet) -> Self {
        let leaves: [Digest; 4] = set.leaf_hashes();
        let nodes: [Digest; 2] = [
            compress(leaves[0], leaves[1]),
            compress(leaves[2], leaves[3]),
        ];
        let root: Digest = compress(nodes[0], nodes[1]);

        AttributeTree { leaves, nodes, root }
    }

    pub fn root(&self) -> Digest {
        self.root
    }

    /// Returns the root serialised as 32 bytes: each of the 8 elements as its
    /// canonical `u32`, little-endian, in order. This is the canonical form
    /// signed by ML-DSA.
    pub fn root_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (i, elem) in self.root.iter().enumerate() {
            bytes[i * 4..(i + 1) * 4]
                .copy_from_slice(&elem.as_canonical_u32().to_le_bytes());
        }
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

    /// Recompute the root from a proof. Sanity check called inside
    /// `merkle_proof`; a failure means a bug in tree construction or proof
    /// assembly, returns err `ProofInconsistent`
    fn verify_proof(&self, proof: &MerkleProof) -> Result<(), AttrTreeError> {
        let mut current: Digest = proof.leaf;
        for (sibling, is_left) in proof.siblings.iter().zip(proof.path.iter()) {
            let (left, right) = if *is_left {
                (current, *sibling)
            } else {
                (*sibling, current)
            };
            current = compress(left, right);
        }

        if current != proof.root {
            return Err(AttrTreeError::ProofInconsistent {
                leaf_index: proof.leaf_index,
            });
        }

        Ok(())
    }
}

/*
    ATTRIBUTE TREE

    take AttributeSet, and turn it into a merkle tree. Used for proof computation and for
    credential generation.

    DESCRIPTION OF BEHAVIOUR

    Whenever a new attributeTree object is created, it takes in an AttrSet and generates a merkle
    root from it. This is meant to be a transient data structure, only existing during credential
    issuance and when a proof needs to be generated.

    Leaves are Poseidon2 sponge digests of the attributes ([F; 8] each); internal
    nodes and the root are 2-to-1 truncated-permutation compressions of digest
    pairs. Domain separation between leaves and nodes comes from the two layers
    using different constructions (sponge vs compression).

    PUBLIC

        new(AttributeSet) : Constructor, takes attrset as input. Infallible.
        root() : returns merkle root digest ([F; 8])
        root_bytes() : returns merkle root as 32 bytes (8 x u32 LE) [ML-DSA message]
        merkle_proof() : returns merkle proof for a given leaf

    PRIVATE

        verify_proof() : called within merkle_proof(). Recomputes the root from
        the proof as a sanity check; errors with ProofInconsistent on mismatch.
*/

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::field::{F, Salt, SALT_ELEMS};

    fn fixed_salts() -> [Salt; 4] {
        std::array::from_fn(|i| {
            std::array::from_fn(|j| F::new((i * SALT_ELEMS + j + 1) as u32))
        })
    }

    fn test_set() -> AttributeSet {
        AttributeSet::with_test_salts(
            String::from("Sufi"),
            "X",
            20040613,
            "IND",
            fixed_salts(),
        )
        .unwrap()
    }

    #[test]
    fn merkle_proofs_roundtrip_for_all_leaves() {
        let tree = AttributeTree::new(&test_set());
        for i in 0..4 {
            let proof = tree.merkle_proof(i).unwrap();
            assert_eq!(proof.leaf_index, i);
            assert_eq!(proof.root, tree.root());
        }
    }

    #[test]
    fn leaf_index_out_of_bounds() {
        let tree = AttributeTree::new(&test_set());
        assert!(matches!(
            tree.merkle_proof(4),
            Err(AttrTreeError::LeafIndexOutOfBounds { leaf_index: 4 })
        ));
    }

    #[test]
    fn fresh_salts_give_fresh_roots() {
        // Two sets with identical attributes but random salts must not share a root.
        let a = AttributeSet::new(String::from("Sufi"), "X", 20040613, "IND").unwrap();
        let b = AttributeSet::new(String::from("Sufi"), "X", 20040613, "IND").unwrap();
        assert_ne!(
            AttributeTree::new(&a).root_bytes(),
            AttributeTree::new(&b).root_bytes()
        );
    }

    #[test]
    fn root_is_deterministic_for_fixed_salts() {
        let r1 = AttributeTree::new(&test_set()).root_bytes();
        let r2 = AttributeTree::new(&test_set()).root_bytes();
        assert_eq!(r1, r2);
    }

    // Known-vector test: locks the full leaf-hash + tree layout (domain tags,
    // length-prefixed 3-byte chunking, fixed-block zero padding, salt order,
    // compression). If this test breaks, previously issued credentials are
    // invalid — that must be a deliberate, versioned decision, never an
    // accident.
    //
    // Vector history:
    //   888dde5b…0041 — variable-length preimages (pre fixed-block padding)
    //   c7124979…7548 — re-pinned 2026-06-12: preimages zero-padded to
    //                   PREIMAGE_BLOCKS (name 5, others 2); see
    //                   claude-notes/04-name-max-bytes-and-fixed-blocks.md
    //   19505e05…575e — re-pinned 2026-06-12: numeric attributes encode as a
    //                   single element (the 3-limb encode_u64 was an ark
    //                   Fr::from(u64) leftover); see claude-notes/05.
    #[test]
    fn known_vector_root() {
        let root = AttributeTree::new(&test_set()).root_bytes();
        let expected = "19505e05024a046205c3080cb74257308953bb227cd7565b38a02b5c0d9f575e";
        assert_eq!(hex::encode(root), expected);
    }
}
