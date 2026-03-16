
# Introduction

Every credential requires a digital signature in order to ensure that it's authentic, and that it has
not been tampered with. There are various signature schemes out there with their own advantages and
disadvantages. For this project, we have selected Dilithium, or ML-DSA as it is called post standardization. 

ML-DSA is a lattice cryptography based signature scheme. It is post quantum safe, and well optimised.

# ML-DSA library and variant used

The rust library used for the ml-dsa implementation is `pqcrypto-mldsa`. This library wraps the PQClean
C reference implementation of mldsa, which is audited. It has AVX-2 optimised implementations, and also
a clean implementation which can be read to understand the underlying processes. As the underlying code
is written in C, a C compiler is necessary at build time.

The chosen variant of ml-dsa is ML-DSA-65. This is similar to the Dilithium3 Variant, it offers ~192 bits
of security, while keeping signature sizes manageable enough for use in QR codes. The public key is 1952
bytes,secret key is 4032 bytes, and signature is 3309 bytes. Additional information about ML-dsa and its 
variants can be found in [this nist spec doc](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf).

# Key Generation and storage

The key generation ceremony will be executed once, and then saved in the /keys directory. The 
public key will be accessible from the issuer and verifier modules, but with a different type depending
on who calls it. The secret key will only be accessible to the issuer module. The keygen function can be
called only when /keys is empty. If not empty, nothing should be done.

Keys should be stored in PEM format. 

> Note: when ccred storage is implemented, stored credentials must be deleted whenever the corresponding keys
> are deleted. Because of this, key deletion should be handled through a well designed function that 
> ensures this, rather than being done manually.

# Signing

The signature is added on top of the merkle root of the attribute tree in the credential. This merkle
root is represented as a 32 byte long little endian serialisation of the BN-254 field element produced
during the tree generation process. We use a detached signature, as the attached signature will add
redundancy and signature verification will be enforced in the verifier module anyway. 

The root is signed instead of the whole credential because that is the thesis of our design: we verify 
the signature independently from the ZK proof in order to allow quantum safe credentials with usable speed.
Refer to the Attributes design doc for more detail.

# API

The dilithium module should have the following functions:

1. keygen() : Generates a new keypair only if keys don't exist, and saves it in /keys
2. delete_keys() : Deletes existing keys. Must be called before regenerating keys. The caller should also delete stored credentials.
3. sign(root, sk) : generates a detached signature for a 32 byte little endian merkle root.
4. verify(signature,root_bytes, pk) : Verifies a detached signature. 


# Errors

Enumerate possible dilithium errors under DilithiumError. This is a stub rn.


# Scope

The following issues are known, and are out of scope for the prototype

1. Public key trust model:
    In a functional system, the verifier must get a key-id from the holder, which they use to look up
    the public key used for signing from a trusted public key registry. This will not be implemented
    in the prototype, and the verifier will simply look up the key from the generated keys directory.
    The interface is designed to accomodate the change to a PKI or registry without issues. 

2. Security features:
    This system requires the use of features such as HSM, ACL hardening, transparency logs for changes
    in key pairs, key rotation, etc. etc. None of these are implemented for the prototype. 
