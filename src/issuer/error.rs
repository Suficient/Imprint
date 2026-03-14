// Top level error enum.
#[derive(Debug)]
pub enum IssuerError {
    /// An attribute hash operation failed.
    Hash(HashError),
    /// An `AttributeSet` could not be constructed due to invalid input.
    AttributeSet(AttributeError),
    /// The merkle attribute tree could not be constructed.
    Tree(AttrTreeError),
    /// Dilithium key generation or signing failed.
    Signing(String),
    /// A credential could not be written to or read from persistent storage.
    Storage(std::io::Error)
}

impl std::fmt::Display for IssuerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hash(e)          => write!(f, "attribute hash error: {e}"),
            Self::AttributeSet(e)  => write!(f, "attribute set error: {e}"),
            Self::Tree(e)          => write!(f, "attribute tree error: {e}"),
            Self::Signing(msg)     => write!(f, "credential signing error: {msg}"),
            Self::Storage(e)       => write!(f, "credential storage error: {e}"),
        }
    }
}

impl std::error::Error for IssuerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Hash(e)         => Some(e),
            Self::AttributeSet(e) => Some(e),
            Self::Tree(e)         => Some(e),
            Self::Storage(e)      => Some(e),
            // String-wrapped errors have no structured source to chain.
            Self::Signing(_) => None,
        }
    }
}

impl From<HashError> for IssuerError {
    fn from(e: HashError) -> Self {
        Self::Hash(e)
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



#[derive(Debug, PartialEq)]
pub enum HashError {
    InvalidInputLength,
    PoseidonFailure(String)
}

impl std::fmt::Display for HashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInputLength => {
                write!(f, "poseidon input length was zero or exceeded the maximum (16 elements)")
            }
            Self::PoseidonFailure(msg) => {
                write!(f, "poseidon hash failed: {msg}")
            }
        }
    }
}

impl std::error::Error for HashError {}


#[derive(Debug, PartialEq)]
pub enum AttributeError {
    NameEmpty,
    NameTooLong{bytes: usize},
    GenderInvalid,
    DobBefore1900,
    DobInFuture{ provided: u64, today: u64 },
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
                write!(f, "name is {bytes} bytes, which exceeds the maximum of 434 bytes")
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
    LeafHashFailed{leaf_index: usize, source: HashError},
    NodeHashFailed{source: HashError},
    LeafIndexOutOfBounds{leaf_index: usize},
}

impl std::fmt::Display for AttrTreeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LeafHashFailed { leaf_index, source } => {
                write!(f, "failed to hash leaf {leaf_index}: {source}")
            }
            Self::NodeHashFailed{source} => {
                write!(f, "failed to hash node: {source}")
            }
            Self::LeafIndexOutOfBounds{leaf_index} => {
                write!(f, "given leaf index: {leaf_index} is out of bounds. Cannot generate proof.")
            }
        }
    }
}

impl std::error::Error for AttrTreeError {}

// TODO: storage errors and dilithium errors