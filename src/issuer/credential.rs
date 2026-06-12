use chrono::Utc;
use uuid::Uuid;

use crate::{
    crypto::mldsa::{load_public_key, load_secret_key, sign, MlDsaPublicKey, MlDsaSignature},
    issuer::{attr_tree::AttributeTree, attribute_set::AttributeSet, error::IssuerError},
};

pub const SCHEMA_VERSION: u32 = 1;
// temp value for now
const DEFAULT_VALIDITY_DAYS: u64 = 365;
const SECONDS_PER_DAY: u64 = 86_400;

/// A signed credential as produced by the issuer.
///
/// Embeds the full `AttributeSet` (values + salts) because the credential is
/// handed to the holder, who needs both for ZK witness generation. The salts
/// must never travel further — the verifier only ever sees the root, the
/// signature, and the issuer public key.
#[derive(Debug)]
pub struct Credential {
    pub schema_version: u32,
    pub credential_id: String, // uuid v4
    pub issued_at: u64,        // unix seconds
    pub expires_at: u64,       // unix seconds

    pub merkle_root: [u8; 32],
    pub attributes: AttributeSet,

    pub signature: MlDsaSignature,
    pub issuer_public_key: MlDsaPublicKey,
}

/// Builds a [`Credential`] from a validated [`AttributeSet`].
///
/// ```ignore
/// let cred = CredentialBuilder::new(set).issue()?;
/// ```
pub struct CredentialBuilder {
    set: AttributeSet,
    validity_days: u64,
}

impl CredentialBuilder {
    pub fn new(set: AttributeSet) -> Self {
        Self {
            set,
            validity_days: DEFAULT_VALIDITY_DAYS,
        }
    }

    /// Override the default credential validity period (365 days).
    pub fn validity_days(mut self, days: u64) -> Self {
        self.validity_days = days;
        self
    }

    /// Issue the credential: build the attribute tree, sign its root with the
    /// issuer's ML-DSA-65 key, and assemble the result.
    ///
    /// Requires issuer keys on disk (`keys/`) — run `mldsa::keygen()` once
    /// beforehand. The secret key is loaded, used, and dropped here; it is
    /// never stored in the builder or the credential.
    pub fn issue(self) -> Result<Credential, IssuerError> {
        let tree = AttributeTree::new(&self.set);
        let root = tree.root_bytes();

        let sk = load_secret_key()?;
        let pk = load_public_key()?;
        let signature = sign(&root, &sk);

        let issued_at = Utc::now().timestamp() as u64;

        Ok(Credential {
            schema_version: SCHEMA_VERSION,
            credential_id: Uuid::new_v4().to_string(),
            issued_at,
            expires_at: issued_at + self.validity_days * SECONDS_PER_DAY,
            merkle_root: root,
            attributes: self.set,
            signature,
            issuer_public_key: pk,
        })
    }
}
