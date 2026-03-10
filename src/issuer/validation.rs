use chrono::{Datelike, Local, NaiveDate};
use rust_iso3166;

use crate::issuer::{attributes::Gender, error::AttributeError};

// Maximum name length in bytes (14 chunks × 31 bytes per chunk) This is due
// to the poseidon input limit. 1 domain tag + 1 salt + 14 string chunks = 16.
const NAME_MAX_BYTES: usize = 434;

// validated name by number of bytes. 
pub fn validate_name(name: &str) -> Result<(), AttributeError> {
    let byte_len = name.len();

    if byte_len == 0 {
        return Err(AttributeError::NameEmpty);
    }

    if byte_len > NAME_MAX_BYTES {
        return Err(AttributeError::NameTooLong { bytes: byte_len });
    }

    Ok(())
}

/*
    Parse a `yyyymmdd` integer and return the number of days since 1900-01-01.

    Rules:
    - The calendar date must be valid (e.g. month 1–12, day in range for month).
    - Must not predate 1900-01-01  → `DobBefore1900`.
    - Must not be in the future    → `DobInFuture`.

    On success the return value is a `u64` representing days since the epoch
    (1900-01-01 = 0).  This value is ready to be wrapped in `DobType(n)`.
*/
pub fn validate_and_parse_dob(ymd: u64) -> Result<u64, AttributeError> {
    let year  = (ymd / 10_000) as i32;
    let month = ((ymd / 100) % 100) as u32;
    let day   = (ymd % 100) as u32;

    let input_date = NaiveDate::from_ymd_opt(year, month, day)
        .ok_or(AttributeError::DobInvalid)?;

    let base = NaiveDate::from_ymd_opt(1900, 1, 1).unwrap();
    let days = input_date.signed_duration_since(base).num_days();

    if days < 0 {
        return Err(AttributeError::DobBefore1900);
    }

    let now = Local::now();
    let today = NaiveDate::from_ymd_opt(now.year(), now.month(), now.day())
        .unwrap();
    let today_days = today.signed_duration_since(base).num_days();

    if days > today_days {
        return Err(AttributeError::DobInFuture {
            provided: days as u64,
            today: today_days as u64,
        });
    }

    Ok(days as u64)
}


pub fn validate_gender(raw: &str) -> Result<Gender, AttributeError> {
    match raw.trim().to_uppercase().as_str() {
        "M" => Ok(Gender::Male),
        "F" => Ok(Gender::Female),
        "X" => Ok(Gender::Other),
        _   => Err(AttributeError::GenderInvalid),
    }
}

/*
    Look up a country by its ISO 3166-1 alpha-3 code and return the
    `rust_iso3166::CountryCode` if found.

    The lookup is case-insensitive; inputs are uppercased before matching.
    An unknown code returns `CountryCodeUnknown`.
*/
pub fn validate_country(alpha3: &str) -> Result<rust_iso3166::CountryCode, AttributeError> {
    let upper = alpha3.trim().to_uppercase();
    rust_iso3166::from_alpha3(&upper)
        .ok_or(AttributeError::CountryCodeUnknown)
}
