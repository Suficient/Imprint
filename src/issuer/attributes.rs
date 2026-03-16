use crate::{crypto::poseidon_ark_import::poseidon_hash, issuer::{types::DobType, error::HashError}};
use ark_bn254::Fr;
use ark_ff::PrimeField;
use rust_iso3166;

pub trait Attribute {
    const DOMAIN_TAG: u64;

    fn value_to_fr(&self) -> Vec<Fr>;

    fn salt(&self) -> Fr;

    fn hash(&self) -> Result<Fr, HashError>;
}

pub struct NameAttribute {
    value: String,
    salt: Fr,
}

impl NameAttribute {
    pub fn new(name: String, salt: Fr) -> Self {
        Self { value: name, salt }
    }
}

impl Attribute for NameAttribute {
    // TODO: replace with domain_tags.rs
    const DOMAIN_TAG: u64 = 1;

    // chunk the name string into 31 bytes and convert to fr.
    // chunk size must never be increased past 31, as it would
    // then be larger than the size of a bn254 field element.
    fn value_to_fr(&self) -> Vec<Fr> {
        const CHUNK_SIZE: usize = 31;
        let mut chunked: Vec<Fr> = vec![];

        let name_bytes = self.value.as_bytes();

        for chunk in name_bytes.chunks(CHUNK_SIZE) {
            let mut padded = [0u8; CHUNK_SIZE];

            padded[..chunk.len()].copy_from_slice(chunk);
            let field_element = Fr::from_be_bytes_mod_order(&padded);

            chunked.push(field_element);
        }

        chunked
    }

    fn salt(&self) -> Fr {
        self.salt
    }

    fn hash(&self) -> Result<Fr, HashError> {
        let mut to_hash: Vec<Fr> = vec![Fr::from(Self::DOMAIN_TAG)];
        to_hash.extend(self.value_to_fr());
        to_hash.push(self.salt());

        poseidon_hash(to_hash)
    }
}


#[derive(Clone, Copy, Debug)]
pub enum Gender {
    Male,
    Female,
    Other,
}

impl Gender {
    pub fn as_u64(&self) -> u64 {
        match self {
            Gender::Male => 1,
            Gender::Female => 2,
            Gender::Other => 3,
        }
    }
}

pub struct GenderAttribute {
    value: Gender,
    salt: Fr
}

impl GenderAttribute {
    pub fn new(gender: Gender, salt: Fr) -> Self {
        Self { value: gender, salt }
    }
}

impl Attribute for GenderAttribute {

    // TODO: replace with domain_tags.rs
    const DOMAIN_TAG: u64 = 2;

    fn salt(&self) -> Fr {
        self.salt
    }

    fn value_to_fr(&self) -> Vec<Fr> {
        vec![Fr::from(self.value.as_u64())]
    }

    fn hash(&self) -> Result<Fr, HashError> {
        let mut to_hash: Vec<Fr> = vec![Fr::from(Self::DOMAIN_TAG)];
        to_hash.extend(self.value_to_fr());
        to_hash.push(self.salt());

        poseidon_hash(to_hash)
    }
}


pub struct DOBAttribute {
    value: DobType, //days since 1900-01-01
    salt: Fr
}

impl DOBAttribute {
    pub fn new(date: DobType, salt: Fr) -> Self {
        Self { value: date, salt }
    }
}

impl Attribute for DOBAttribute {

    // TODO: replace with domain_tags.rs
    const DOMAIN_TAG: u64 = 3;

    fn salt(&self) -> Fr {
        self.salt
    }

    fn value_to_fr(&self) -> Vec<Fr> {
        vec![Fr::from(u64::from(self.value))]
    }

    fn hash(&self) -> Result<Fr, HashError> {
        let mut to_hash: Vec<Fr> = vec![Fr::from(Self::DOMAIN_TAG)];
        to_hash.extend(self.value_to_fr());
        to_hash.push(self.salt());

        poseidon_hash(to_hash)
    }
}


pub struct CountryAttribute {
    value: rust_iso3166::CountryCode,
    salt: Fr
}

impl CountryAttribute {
    pub fn new(country: rust_iso3166::CountryCode, salt: Fr) -> Self {
        Self { value: country, salt }
    }
}

impl Attribute for CountryAttribute {

    // TODO: replace with domain_tags.rs
    const DOMAIN_TAG: u64 = 4;

    fn salt(&self) -> Fr {
        self.salt
    }

    // while the alpha3 value is used everywhere else in the code,
    // the ZK circuits for country codes use the numeric value.
    fn value_to_fr(&self) -> Vec<Fr> {
        let countrycode_numeric = self.value.numeric;
        vec![Fr::from(countrycode_numeric as u64)]
    }

    fn hash(&self) -> Result<Fr, HashError> {
        let mut to_hash: Vec<Fr> = vec![Fr::from(Self::DOMAIN_TAG)];
        to_hash.extend(self.value_to_fr());
        to_hash.push(self.salt());

        poseidon_hash(to_hash)
    }
}


/*
    CONSTRAINTS TO BE ADDED FOR EACH ATTRIBUTE

    NAME
        - should not be too long, limit at 14 31 byte chunks worth of text
    
    GENDER
        - should fit into Gender enum

    DOB
        - should not be older than 1900-01-01
        - should not be younger than today's date
    
    COUNTRY
        - as it takes rust_iso3166::countrycode as input, no validation is needed here. 
*/