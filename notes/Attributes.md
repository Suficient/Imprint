# Attribute design/architecture

Our design is based on a merkle tree of attributes, with a commitment signed on top of the root.
Thus, for every attribute, the merkle inclusion + attribute condition is proved in ZK, and the signature is proved outside of ZK. 

In this prototype, there are 4 attributes per credential

1. Name: String
2. dob: u64 (timestamp since 1900 in days)
3. gender: GenderAttribute (M, F, X)
4. country: iso-3166 numeric

Each of these needs to be hashed with poseidon. The hash functions for different uses must be separated with domain tagging, and each attribute leaf must contain a salt. Thus, each leaf of the attribute tree looks like this:

```rust
Hash(LEAF_DOMAIN_TAG, dataVector[], Salt)
```

Each internal node is

```rust
Hash(NODE_DOMAIN_TAG, left, right)
```

etc. 

The hash function used is poseidon, parameterized in such a way that it maintains full compatibility with circomlibjs. Tests for these must be implemented. The hash functions for each attribute have different implementations, which will be as follows

1. Name: As name is a string of arbitrary length, the string must be separated into 31 byte chunks. This is hashed as a name domain tag and salt.

2. DOB: Hashed as dob tag, dob value(yyyymmdd), salt

3. gender: Hashed as gender tag, gender numeric value, salt

4. country code: hashed as country tag, iso-3166-numeric value, salt.

Attributes are saved as a struct of Attribute objects. For now, each attribute's hash function is identical, but implemented separately as this will change when more features are implemented.

>NOTE: Wherever an attribute is represented as a number to facilitate easier value -> field element conversion, use the u64 data type as this is what ark's Fr::from() function accepts.

# Salting

For this prototype, salting will be a simple

```rust
let salt = Fr::rand(&mut rng);
```

But later on, salts should be derived for each attribute from a high entropy master secret. Each attribute's salt will be stored alongside the attribute in the credential, and will be generated when the credential is generated.

# Domain tags

how are domain tags generated and defined

# Tree structure

depth, leaf ordering determinism, security considerations, how is it stored.