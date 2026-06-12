//! End-to-end issuance test: attribute validation → merkle tree → ML-DSA
//! signature → verification, plus tamper-detection negatives.

use imprint::{
    crypto::mldsa::{keygen, verify, DilithiumError},
    issuer::{attribute_set::AttributeSet, credential::CredentialBuilder},
};

/// Make sure issuer keys exist; tolerate a keypair already on disk.
fn ensure_keys() {
    match keygen() {
        Ok(()) | Err(DilithiumError::KeysAlreadyExist) => {}
        Err(e) => panic!("keygen failed: {e}"),
    }
}

#[test]
fn issue_sign_verify_roundtrip() {
    ensure_keys();

    let set = AttributeSet::new(String::from("Sufi"), "X", 20040613, "IND").unwrap();
    let cred = CredentialBuilder::new(set).issue().unwrap();

    assert_eq!(cred.schema_version, 1);
    assert!(cred.expires_at > cred.issued_at);

    verify(&cred.signature, &cred.merkle_root, &cred.issuer_public_key)
        .expect("freshly issued credential must verify");
}

#[test]
fn tampered_root_fails_verification() {
    ensure_keys();

    let set = AttributeSet::new(String::from("Sufi"), "F", 19991231, "AUS").unwrap();
    let cred = CredentialBuilder::new(set).issue().unwrap();

    let mut tampered = cred.merkle_root;
    tampered[30] ^= 0xFF;

    assert!(matches!(
        verify(&cred.signature, &tampered, &cred.issuer_public_key),
        Err(DilithiumError::VerificationFailed)
    ));
}

#[test]
fn invalid_attributes_are_rejected() {
    // gender, dob, and country validation must all fire.
    assert!(AttributeSet::new(String::from("A"), "Q", 20000101, "IND").is_err());
    assert!(AttributeSet::new(String::from("A"), "M", 20991231, "IND").is_err());
    assert!(AttributeSet::new(String::from("A"), "M", 20000101, "ZZZ").is_err());
    assert!(AttributeSet::new(String::new(), "M", 20000101, "IND").is_err());
}
