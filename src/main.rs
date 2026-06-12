use imprint::{
    crypto::mldsa::{keygen, verify, DilithiumError},
    issuer::{attribute_set::AttributeSet, credential::CredentialBuilder},
};

// Manual demo of the issuance flow. The real coverage lives in `cargo test`
// (unit tests + tests/e2e.rs); this just exercises the same path visibly.
fn main() {
    let set = AttributeSet::new(String::from("Sufi"), "X", 20040613, "IND").unwrap();

    match keygen() {
        Ok(_) => println!("keygen: new ML-DSA-65 keypair written to keys/"),
        Err(DilithiumError::KeysAlreadyExist) => println!("keygen: reusing existing keys"),
        Err(e) => {
            println!("keygen failed: {e}");
            return;
        }
    }

    let credential = match CredentialBuilder::new(set).issue() {
        Ok(c) => c,
        Err(e) => {
            println!("issuance failed: {e}");
            return;
        }
    };

    println!("issued credential: {credential:#?}");

    match verify(
        &credential.signature,
        &credential.merkle_root,
        &credential.issuer_public_key,
    ) {
        Ok(_) => println!("signature verifies"),
        Err(e) => println!("signature verification failed: {e}"),
    }

    let mut tampered_root = credential.merkle_root;
    tampered_root[30] ^= 0xFF;

    match verify(
        &credential.signature,
        &tampered_root,
        &credential.issuer_public_key,
    ) {
        Ok(_) => println!("tampered root still verifies. Problematic"),
        Err(_) => println!("tampered root fails to verify, as expected"),
    }
}
