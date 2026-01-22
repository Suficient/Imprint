use ark_bn254::fr;
use ark_crypto_primitives::crh::poseidon::{
    constraints::CRHParametersVar,
    CRH,
    CRHParameters,
};

// Each attribute must have a way to be mapped onto the BN254 Field. This will be protocol/spec and should be standardised.

pub struct RawAttributes {
    name: String,
    dob: i32,
    gender: GenderAttribute,
    nationality: NationalityAttribute
}

pub enum GenderAttribute {
    male(u8) = 1,
    female(u8) = 2,
    intersex(u8) = 3
}

pub enum NationalityAttribute {
    India(u8) = 100,
    Ethiopia(u8) = 200,
    UK(u8) = 150
}