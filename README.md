
imprint - Prototype
===============================================================================

This is the prototype/proof of concept implementation of the Imprint zk-kyc solution. This readme will serve as a
design document until the implementation works, after which it will be updated to be an actual readme.

## Description

imprint is a zk-kyc system that aims to be post-quantum safe and performant on a national scale. It is based on a
verifiable credential that represents its attributes in the form of a merkle tree. A commitment over this tree
is signed with Dilithium. Attributes are proven to conform to certain predicates through the use of ZK circuits.

This technique of computing the signature outside the ZK circuit is where we gain our performance and quantum safety.
The final design involves a revocation system and other stuff that isn't included here.

## Scope

This prototype implements the following features:

1. Issuer functionality
    - Simplified raw JSON Schema
    - VC Generation
    - Merkle tree functions (constructions, proof, etc.)
    - Dilithium Signing
    - Persistent VC storage (simple files for now)
2. Holder functionality
    - Proof generation scripting and API
    - Age proof circuit
    - Merkle inclusion circuit
    - Performance and functional testing
3. Verifier functionality
    - zk proof verification
    - Dilithium signature verification
    - Script and API
4. Optional nice to haves if I have time
    - Revocation (too much work for now)
    - QR code verification pipeline
    - CLI
    - Documentation
    - End to end testing
    - a nicer readme

Assume everything is a barebones implementation with security holes. This is only a proof of concept.

## Points to keep in mind

- Poseidon should be used in everything that is to be computed within ZK, and SHA-256 elsewhere
- This solution is not entirely private, verifications are linkable through merkle roots. A potential solution is ring signatures


