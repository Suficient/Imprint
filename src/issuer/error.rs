use crate::crypto::mldsa::DilithiumError;
use crate::issuer::attributes::NAME_MAX_BYTES;

// Top level error enum.
#[derive(Debug)]
pub enum IssuerError {
    /// An `AttributeSet` could not be constructed due to invalid input.
    AttributeSet(AttributeError),
    /// A merkle proof could not be generated from the attribute tree.
    Tree(AttrTreeError),
    /// ML-DSA key loading, generation, or signing failed.
    Signing(DilithiumError),
    /// A credential could not be written to or read from persistent storage.
    Storage(std::io::Error),
}

impl std::fmt::Display for IssuerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AttributeSet(e) => write!(f, "attribute set error: {e}"),
            Self::Tree(e)         => write!(f, "attribute tree error: {e}"),
            Self::Signing(e)      => write!(f, "credential signing error: {e}"),
            Self::Storage(e)      => write!(f, "credential storage error: {e}"),
        }
    }
}

impl std::error::Error for IssuerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::AttributeSet(e) => Some(e),
            Self::Tree(e)         => Some(e),
            Self::Signing(e)      => Some(e),
            Self::Storage(e)      => Some(e),
        }
    }
}

impl From<AttributeError> for IssuerError {
    fn from(e: AttributeError) -> Self {
        Self::AttributeSet(e)
    }
}

impl From<AttrTreeError> for IssuerError {
    fn from(e: AttrTreeError) -> Self {
        Self::Tree(e)
    }
}

impl From<DilithiumError> for IssuerError {
    fn from(e: DilithiumError) -> Self {
        Self::Signing(e)
    }
}

#[derive(Debug, PartialEq)]
pub enum AttributeError {
    NameEmpty,
    NameTooLong{bytes: usize},
    GenderInvalid,
    DobBefore1900,
    DobInFuture{ provided: u32, today: u32 },
    DobInvalid,
    CountryCodeUnknown
}

impl std::fmt::Display for AttributeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NameEmpty => {
                write!(f, "name must not be left empty")
            }
            Self::NameTooLong {bytes}=> {
                write!(f, "name is {bytes} bytes, which exceeds the maximum of {NAME_MAX_BYTES} bytes")
            }
            Self::GenderInvalid => {
                write!(f, "entered gender is invalid. Valid genders are M, F, X")
            }
            Self::DobBefore1900 => {
                write!(f, "date of birth cannot be earlier than 1900-01-01")
            }
            Self::DobInFuture{provided, today} => {
                write!(f, "date of birth ({provided} days since 1900) cannot be in the future (today's date: {today})")
            }
            Self::DobInvalid => {
                write!(f, "entered date of birth is an invalid date")
            }
            Self::CountryCodeUnknown => {
                write!(f, "entered country code does not match known list. Ensure that it is a valid Alpha3. For example: IND, AUS, USA")
            }
        }
    }
}

impl std::error::Error for AttributeError {}

#[derive(Debug, PartialEq)]
pub enum AttrTreeError {
    LeafIndexOutOfBounds{leaf_index: usize},
    /// A freshly generated proof failed to recompute the root. Indicates a bug
    /// in tree construction or proof assembly, not bad user input.
    ProofInconsistent{leaf_index: usize},
}

impl std::fmt::Display for AttrTreeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LeafIndexOutOfBounds{leaf_index} => {
                write!(f, "given leaf index: {leaf_index} is out of bounds. Cannot generate proof.")
            }
            Self::ProofInconsistent{leaf_index} => {
                write!(f, "merkle proof for leaf {leaf_index} failed to recompute the root. This is a bug in tree construction or proof generation.")
            }
        }
    }
}

impl std::error::Error for AttrTreeError {}
