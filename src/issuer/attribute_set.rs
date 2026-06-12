use rand::RngExt;

use crate::crypto::field::{Digest, Salt};
use crate::issuer::{
    attributes::{Attribute, CountryAttribute, DOBAttribute, GenderAttribute, NameAttribute},
    error::AttributeError,
    types::DobType,
    validation::{validate_and_parse_dob, validate_country, validate_gender, validate_name},
};

// A validated set containing all four credential attributes.
#[derive(Debug)]
pub struct AttributeSet {
    name:    NameAttribute,
    gender:  GenderAttribute,
    dob:     DOBAttribute,
    country: CountryAttribute,
}

impl AttributeSet {
    /// Construct a validated `AttributeSet` from raw user-supplied strings,
    /// with fresh uniformly random salts.
    ///
    /// # Parameters
    /// - `name`    — arbitrary UTF-8 string, max
    ///   [`attributes::NAME_MAX_BYTES`](crate::issuer::attributes::NAME_MAX_BYTES) bytes (90).
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
        dob:     u32,
        country: &str,
    ) -> Result<Self, AttributeError> {
        let mut rng = rand::rng();
        let salts: [Salt; 4] =
            std::array::from_fn(|_| std::array::from_fn(|_| rng.random()));

        Self::build(name, gender, dob, country, salts)
    }

    /// Construct an `AttributeSet` with caller-provided salts — **test-only**
    ///
    /// Exists solely so known-vector tests can be deterministic. In
    /// production, salts must be uniformly random ([`AttributeSet::new`])
    pub fn with_test_salts(
        name:    String,
        gender:  &str,
        dob:     u32,
        country: &str,
        salts:   [Salt; 4],
    ) -> Result<Self, AttributeError> {
        Self::build(name, gender, dob, country, salts)
    }

    /// Shared validation + construction. Fields are validated in the order:
    /// name → gender → dob → country; only the first failure is reported.
    fn build(
        name:    String,
        gender:  &str,
        dob:     u32,
        country: &str,
        salts:   [Salt; 4],
    ) -> Result<Self, AttributeError> {
        validate_name(&name)?;
        let gender_enum  = validate_gender(gender)?;
        let dob_days     = validate_and_parse_dob(dob)?;
        let country_code = validate_country(country)?;

        Ok(Self {
            name:    NameAttribute::new(name, salts[0]),
            gender:  GenderAttribute::new(gender_enum, salts[1]),
            dob:     DOBAttribute::new(DobType(dob_days), salts[2]),
            country: CountryAttribute::new(country_code, salts[3]),
        })
    }

    /// Return the four Poseidon2 leaf digests in canonical order:
    /// `[name, gender, dob, country]`. Infallible.
    pub fn leaf_hashes(&self) -> [Digest; 4] {
        [
            self.name.hash(),
            self.gender.hash(),
            self.dob.hash(),
            self.country.hash(),
        ]
    }

    /// Return the four salts in canonical leaf order: `[name, gender, dob, country]`.
    ///
    /// Needed by the holder when building a ZK witness. Must never be shared
    /// with the verifier. Also necessary for credential storage.
    pub fn salts(&self) -> [Salt; 4] {
        [
            self.name.salt(),
            self.gender.salt(),
            self.dob.salt(),
            self.country.salt(),
        ]
    }
}
