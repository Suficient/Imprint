use chrono::{Datelike, Local, NaiveDate};
use rust_iso3166;

use crate::issuer::{
    attributes::{Gender, NAME_MAX_BYTES},
    error::AttributeError,
};

// Validates name by number of **bytes**, not characters — the cap is derived
// from the AIR block budget (see `attributes::NAME_MAX_BYTES`), and byte caps
// on UTF-8 input can bite mid-character; communicating limits in characters
// is the product layer's job.
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

    On success the return value is a `u32` representing days since the epoch
    (1900-01-01 = 0).  This value is ready to be wrapped in `DobType(n)`.
    The day count is bounded by the not-in-the-future check (today ≈ 46k days,
    far below 2^24), which is what lets the DOB encode as a single field
    element.
*/
pub fn validate_and_parse_dob(ymd: u32) -> Result<u32, AttributeError> {
    let year  = (ymd / 10000) as i32;
    let month = (ymd / 100) % 100;
    let day   = ymd % 100;

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
            provided: days as u32,
            today: today_days as u32,
        });
    }

    Ok(days as u32)
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
*/
pub fn validate_country(alpha3: &str) -> Result<rust_iso3166::CountryCode, AttributeError> {
    let upper = alpha3.trim().to_uppercase();
    rust_iso3166::from_alpha3(&upper)
        .ok_or(AttributeError::CountryCodeUnknown)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_max_length_boundary() {
        // Exactly NAME_MAX_BYTES is accepted; one byte over is rejected.
        assert!(validate_name(&"a".repeat(NAME_MAX_BYTES)).is_ok());
        assert_eq!(
            validate_name(&"a".repeat(NAME_MAX_BYTES + 1)),
            Err(AttributeError::NameTooLong { bytes: NAME_MAX_BYTES + 1 })
        );
    }

    #[test]
    fn name_cap_counts_bytes_not_chars() {
        // 31 Devanagari chars × 3 bytes = 93 bytes > 90 — rejected even
        // though it is far fewer than 90 *characters*.
        let name = "क".repeat(31);
        assert_eq!(name.chars().count(), 31);
        assert_eq!(
            validate_name(&name),
            Err(AttributeError::NameTooLong { bytes: 93 })
        );
    }
}
