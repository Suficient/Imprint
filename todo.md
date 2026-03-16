CURRENT FOCUS: ATTRIBUTE AND CREDENTIAL GENERATION LOGIC


================================================================================
OVERALL TODO LIST
================================================================================

[ ] ISSUER
    ----------------------------------------------------------------------------
    [ ] Attribute layer (issuer/attributes.rs)
        [x] Name attribute struct + hash
        [x] Gender attribute struct + hash
        [x] Country attribute struct + hash
        [x] DOB attribute struct + hash
        [x] Wire up HashError from error.rs — replace Result<Fr, String>
            with Result<Fr, HashError> across all attribute hash() impls
        [ ] Domain tags: replace u64 literals (1,2,3,4) with Fr values derived
            by hashing the attribute name string (e.g. Poseidon("IMPRINT_NAME_V1"))
            Add domain_tags.rs in crypto/ with one const per attribute type.
        [x] Name validation: enforce max 434 bytes (14 x 31-byte chunks)
        [x] DOB validation: must not be in the future, must not predate days==0
        [x] Gender and Country validation: must be valid values
;
    [x] Attribute set (issuer/attribute_set.rs)
        [x] Implement AttributeSet::new(name, gender, dob, country) -> Result<Self, IssuerError>
        [x] AttributeSet::salts() -> [Fr; 4] — needed later for witness generation
        [x] AttributeSet::leaf_hashes() — return hashed values of inner structs
;
    [x] Validation module (issuer/validation.rs — new file)
        [x] validate name
        [x] validate dob
        [x] validate gender
        [x] validate country
;
    [ ] Merkle tree (issuer/attr_tree.rs)
        [x] Define AttrTree struct
        [x] write constructor
        [x] Leaf ordering: document then code
        [x] Leaf hashes: delegate to each Attribute::hash()
        [ ] NODE_DOMAIN_TAG: add to domain_tags.rs, use in internal node hashing
        [x] Internal node hash: Poseidon(NODE_TAG, left, right)
        [x] AttrTree::root() -> Fr
        [x] AttrTree::root_bytes() -> [u8; 32]  — canonical form for signing
        [x] AttrTree::merkle_proof(leaf_index: usize) -> MerkleProof
        [x] MerkleProof struct { leaf: Fr, sibling: Fr, is_left: bool, root: Fr }
        [x] AttrTree::verify_proof(proof: &MerkleProof) -> bool
        [ ] Tests: known-vector test for root given fixed attributes and salts
;
    [ ] Credential assembly (issuer/credential.rs — new file)
        [ ] Add a schema version field
        [ ] CredentialBuilder::new(set: AttributeSet) -> Self
        [ ] CredentialBuilder::issue() -> Result<Credential, IssuerError>
            - build AttrTree from AttributeSet
            - sign root_bytes with Dilithium
            - generate credential_id (uuid v4)
            - set issued_at / expires_at timestamps
            - assemble and return Credential
        [ ] Credential should embed AttributeSet (with salts) for holder use
            NOTE: salts are private and must not be shared with verifier
;
    [ ] Dilithium signing (crypto/dilithium.rs — new file)
        [x] Figure out which dilithium library and variant to use -> pqcrypto-mldsa
        [ ] dilithium_keygen() -> (PublicKey, SecretKey)
        [ ] Sign dilithium, with secret key and attribute tree root
        [ ] verify dilithium, with pubkey, root, signature
        [ ] connect to CredentialBuilder::issue()
            Note: public key (~1952 bytes) and signature (~3293 bytes) for Dilithium3
;
    [ ] Storage (issuer/storage.rs — new file)
        [ ] Figure out what to actually do here
;
    [ ] Error handling (issuer/error.rs)
        [x] IssuerError enum covering:
            [x]AttributeError(AttributeHashError)
            [x]ValidationError(String)
            [x]TreeError(String)
            [ ]SigningError(String)
            [ ]StorageError(std::io::Error)
        [x] impl From<AttributeHashError> for IssuerError
        [x] impl std::fmt::Display for IssuerError
;
    [ ] CLI — issue command (cli/issue.rs — new file)
        [ ] imprint issue --name <str> --dob <YYYY-MM-DD> --gender <M|F|X> --country <alpha2>
        [ ] Parse and validate args, call CredentialBuilder, print credential_id on success


================================================================================

[ ] HOLDER
    ----------------------------------------------------------------------------
    [ ] Proof types (holder/proof_types.rs — new file)
        [ ] ProofRequest enum:
            - AgeOver(u8)               — proves age >= threshold
            - CountryIn(Vec<u16>)       — proves country in set of iso3166 numeric codes
            - GenderEquals(Gender)      — proves gender == value
            - NameEquals(String)        — proves name == committed value
        [ ] ZkProof struct containing attribute proofs
        [ ] ProofPackage struct containing proof, root, signature, and issuer pubkey
;
    [ ] Witness generation (holder/witness.rs — new file)
        [ ] figure out what to do here

    [ ] Proof generation (holder/prover.rs — new file)
        If Route A (snarkjs):
        [ ] Shell out to snarkjs generateWitness + snarkjs prove
        [ ] Parse returned proof.json and public.json
        [ ] Locate circuit artifacts by circuit name (configurable base path)
;
    [ ] Holder API (holder/api.rs — new file)
        [ ] generate_proof(cred_id: &str, request: ProofRequest) -> Result<ProofPackage, HolderError>
            - load credential from storage
            - extract relevant attribute + salt + merkle proof
            - build witness
            - call prover
            - bundle with root + dilithium sig + issuer pk
        [ ] HolderError enum (CredentialNotFound, WitnessError, ProofError, etc.)
;
    [ ] Circuits (circuits/ — new directory)
        [ ] Figure out what to do here
        [ ] Known-vector tests for each circuit (test with hardcoded inputs, check output)
;
    [ ] Performance testing (holder/bench.rs or benches/ — new)
        [ ] Measure: witness gen time, proof gen time, proof size per circuit
        [ ] Run on at least: age_range, country_set_membership
        [ ] Note: witness gen is typically the bottleneck, not proving
        [ ] Optional: compare snarkjs WASM vs rapidsnark native witness gen
;
    [ ] CLI — prove command (cli/prove.rs — new file)
        [ ] imprint prove --cred <id> --age-over <n>
        [ ] imprint prove --cred <id> --country-in <alpha2,alpha2,...>
        [ ] imprint prove --cred <id> --gender <M|F|X>
        [ ] Output: proof package JSON to stdout or --out <file>


================================================================================

[ ] VERIFIER
    ----------------------------------------------------------------------------
    [ ] ZK proof verification (verifier/zk_verify.rs — new file)
        [ ] Load verification key from circuits/build/<circuit>_vkey.json
        [ ] shell out to snarkjs verifyProof, parse result
        [ ] verify_zk(circuit: &str, proof: &ZkProof) -> Result<bool, VerifierError>
        [ ] Confirm public signals match expected structure (root, threshold, etc.)
;
    [ ] Dilithium signature verification (verifier/sig_verify.rs — new file)
        [ ] verify_dilithium(pk: &[u8], root_bytes: &[u8;32], sig: &DilithiumSignature) -> bool
;
    [ ] Verifier API (verifier/api.rs — new file)
        [ ] VerificationRequest { proof_package: ProofPackage, expected_predicate: ProofRequest }
        [ ] VerificationResult { valid: bool, predicate_satisfied: bool, error: Option<String> }
        [ ] verify(req: VerificationRequest) -> VerificationResult
            - verify ZK proof
            - verify Dilithium signature over root from public signals
            - confirm public signals satisfy the expected predicate
            - return unified result
;
    [ ] CLI — verify command (cli/verify.rs — new file)
        [ ] imprint verify --proof <file> --issuer-pk <file>
        [ ] Print VALID / INVALID with reason
;
    [ ] Performance testing
        [ ] Measure: ZK verify time, Dilithium verify time, total end-to-end


================================================================================

[ ] END TO END
    ----------------------------------------------------------------------------
    [ ] E2E test: issue credential -> generate age proof -> verify
    [ ] E2E test: issue credential -> generate country proof -> verify
    [ ] E2E test: tampered merkle root -> verify should fail
    [ ] E2E test: tampered dilithium signature -> verify should fail
    [ ] E2E test: wrong attribute value in witness -> proof generation should fail


================================================================================

[ ] QR CODE FLOW
    ----------------------------------------------------------------------------
    [ ] Measure actual proof package size (proof + root + dilithium sig + issuer pk)
        Expected: ~200 bytes proof + 32 bytes root + ~3293 bytes sig + ~1952 bytes pk = ~5.5KB
        This exceeds a single QR code in binary mode (~3KB at ECC level M)
    [ ] Design options:
        Option A: Two QR codes (proof+root in one, sig+pk in another)
        Option B: Drop issuer pk from QR, verifier fetches it from a known registry by issuer ID
                  This is the right long-term design and cuts payload to ~3.5KB
;
    [ ] Write QR design doc before implementing
    [ ] Implement QR encode (payload -> QR image) and decode (scan -> ProofPackage)


================================================================================

KNOWN ISSUES / TECHNICAL DEBT
================================================================================

[ ] Poseidon::new() re-parses all constants on every call to poseidon_hash().
    For bulk issuance, instantiate once and reuse. Low priority for prototype.

[ ] Linkability: the merkle root is a stable identifier — any two verifiers can
    correlate presentations from the same credential. This is a pseudonymous
    system, not anonymous. Document this explicitly.
    Near-term mitigation, to be implemented later: per-presentation nullifier 
    derived from (root, verifier_id, nonce) to at least prevent cross-verifier 
    correlation.

[ ] The verifier has no mechanism to resolve issuer public keys. A real deployment
    needs a PKI or a registry. Design the sig_verify interface to accept pk
    explicitly so it's easy to slot in later.