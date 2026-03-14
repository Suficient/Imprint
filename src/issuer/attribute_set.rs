use ark_bn254::Fr;
use rand::thread_rng;
use ark_ff::UniformRand;

use crate::issuer::{
    attributes::{CountryAttribute, DOBAttribute, GenderAttribute, NameAttribute}, error::{AttributeError, HashError}, types::DobType, validation::{validate_and_parse_dob, validate_country, validate_gender, validate_name}
};

// A validated set containing all four credential attributes.
pub struct AttributeSet {
    name:    NameAttribute,
    gender:  GenderAttribute,
    dob:     DOBAttribute,
    country: CountryAttribute,
}

impl AttributeSet {
    /// Construct a validated `AttributeSet` from raw user-supplied strings.
    ///
    /// # Parameters
    /// - `name`    — arbitrary UTF-8 string, max 434 bytes.
    /// - `gender`  — `"M"`, `"F"`, or `"X"` (case-insensitive).
    /// - `dob`     — date of birth as a `yyyymmdd` integer, e.g. `19900315`.
    /// - `country` — ISO 3166-1 alpha-3 code, e.g. `"IND"` (case-insensitive).
    ///
    /// # Errors
    /// Returns an [`AttributeError`] if any field fails validation. Only the
    /// first failing field is reported; fields are validated in the order:
    /// name → gender → dob → country.
    pub fn new(
        name:    String,
        gender:  &str,
        dob:     u64,
        country: &str,
    ) -> Result<Self, AttributeError> {

        validate_name(&name)?;
        let gender_enum  = validate_gender(gender)?;
        let dob_days     = validate_and_parse_dob(dob)?;
        let country_code = validate_country(country)?;

        // salt generation
        let mut rng = thread_rng();
        let salts: [Fr; 4] = std::array::from_fn(|_| Fr::rand(&mut rng));

        Ok(Self {
            name:    NameAttribute::new(name, salts[0]),
            gender:  GenderAttribute::new(gender_enum, salts[1]),
            dob:     DOBAttribute::new(DobType(dob_days), salts[2]),
            country: CountryAttribute::new(country_code, salts[3]),
        })
    }

    /// Return the four Poseidon leaf hashes in canonical order:
    /// `[name, gender, dob, country]`.
    /// If hashing fails, returns a tuple containing the index of
    /// the failed hash, and the HashError encountered.
    pub fn leaf_hashes(&self) -> Result<[Fr; 4], (usize,HashError)> {
        use crate::issuer::attributes::Attribute;
        Ok([
        self.name.hash()   .map_err(|e| (0, e))?,
        self.gender.hash() .map_err(|e| (1, e))?,
        self.dob.hash()    .map_err(|e| (2, e))?,
        self.country.hash().map_err(|e| (3, e))?,
    ])
    }

    /// Return the four salts in canonical leaf order: `[name, gender, dob, country]`.
    ///
    /// Needed by the holder when building a ZK witness. Must never be shared
    /// with the verifier. Also necessary for credential storage. 
    pub fn salts(&self) -> [Fr; 4] {
        use crate::issuer::attributes::Attribute;
        [
            self.name.salt(),
            self.gender.salt(),
            self.dob.salt(),
            self.country.salt(),
        ]
    }
}