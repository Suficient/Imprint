These notes detail possible error types in all levels of credential issuance. Sections for holder and verifier will be added later.

# Error Hierarchy

Error types will follow this hierarchy:

1. Top level: IssuerError, ProverError, VerifierError
2. Module level: AttrTreeError, SigningError, StorageError, etc.
3. Function level: AttrHashError, InvalidLength, UnknownCountryCode, etc.

Display will be implemented for each error. 

# Issuer Errors

- IssuerError
    - Hashing Errors
        - Incorrect input length (1-16)
        - PoseidonError (needs to be expanded by adding better error handling to poseidon code)

    - Attribute Errors
        - NameError
            - empty string
            - too long
        - GenderError
            - Invalid Gender
        - DobError
            - too early
            - in the future
            - invalid date
        - CountryError
            - Unknown country codeNa
    
    - Merkle Errors
        - Failed Leaf hash
        - Failed Node hash
    
    - Signing Errors
        - Dilithium signature failed
        - Keygen failed

    - Storage errors
        - credential not found in storage
        - credential parsing error
        - credential cannot be stored
    
        