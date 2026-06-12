use pqcrypto_mldsa::mldsa65::{
    self, DetachedSignature, PublicKey, SecretKey,
};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _, VerificationError};
use std::path::{Path, PathBuf};
use base64::Engine;

const KEYS_DIR:  &str = "keys";
const PK_FNAME:  &str = "mldsa65_pk.pem";
const SK_FNAME:  &str = "mldsa65_sk.pem";
const PK_LABEL:  &str = "ML-DSA-65 PUBLIC KEY";
const SK_LABEL:  &str = "ML-DSA-65 SECRET KEY";

// An ML-DSA-65 public key loaded from the keys file.
// Used by issuer to sign credentials, and verifier to verify them.
pub struct MlDsaPublicKey(PublicKey);

// An ML-DSA-65 secret key loaded from disk.
// Only used inside the issuer. Must never cross the issuer boundary,
// and must not be cached: load, sign, drop.
pub struct MlDsaSecretKey(SecretKey);

// A detached ML-DSA-65 signature over a 32-byte merkle root.
// Stored in the `Credential` struct after issuance (~3309 bytes).
pub struct MlDsaSignature(DetachedSignature);

// Manual Debug impls: the inner pqcrypto types don't derive Debug, and dumping
// kilobytes of raw bytes is useless anyway. Print length + leading bytes.
impl std::fmt::Debug for MlDsaSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b = self.0.as_bytes();
        write!(f, "MlDsaSignature({} bytes, {}…)", b.len(), hex::encode(&b[..8.min(b.len())]))
    }
}

impl std::fmt::Debug for MlDsaPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b = self.0.as_bytes();
        write!(f, "MlDsaPublicKey({} bytes, {}…)", b.len(), hex::encode(&b[..8.min(b.len())]))
    }
}

impl MlDsaSignature {
    /// Return the raw signature bytes. Used for serialisation into a credential.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Reconstruct an `MlDsaSignature` from raw bytes.
    /// Returns `Err(KeyDecodingFailed)` if the byte slice is the wrong length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DilithiumError> {
        DetachedSignature::from_bytes(bytes)
            .map(MlDsaSignature)
            .map_err(|_| DilithiumError::KeyDecodingFailed(
                format!("expected {} bytes for ML-DSA-65 signature, got {}", mldsa65::signature_bytes(), bytes.len())
            ))
    }
}

impl MlDsaPublicKey {
    /// Return the raw public key bytes. Used for serialisation into a credential.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Reconstruct an `MlDsaPublicKey` from raw bytes.
    /// Returns `Err(KeyDecodingFailed)` if the byte slice is the wrong length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DilithiumError> {
        PublicKey::from_bytes(bytes)
            .map(MlDsaPublicKey)
            .map_err(|_| DilithiumError::KeyDecodingFailed(
                format!("expected {} bytes for ML-DSA-65 public key, got {}", mldsa65::public_key_bytes(), bytes.len())
            ))
    }
}

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum DilithiumError {
    /// `keygen()` refused to run because key files are already present on disk.
    KeysAlreadyExist,
    /// A key file was expected but neither file was found in the keys directory.
    KeysNotFound,
    /// A key file existed but its PEM content was malformed, used the wrong
    /// label, or decoded to the wrong number of bytes.
    KeyDecodingFailed(String),
    /// The underlying pqcrypto signing call failed.
    SigningFailed(String),
    /// Signature verification returned false. The signature is invalid, not a
    /// system error.
    VerificationFailed,
    /// An I/O error occurred while reading or writing a key file.
    IoError(std::io::Error),
}

impl std::fmt::Display for DilithiumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeysAlreadyExist =>
                write!(f, "key generation refused: key files already exist in '{KEYS_DIR}/'"),
            Self::KeysNotFound =>
                write!(f, "no key files found in '{KEYS_DIR}/'; run keygen() first"),
            Self::KeyDecodingFailed(msg) =>
                write!(f, "key or signature decoding failed: {msg}"),
            Self::SigningFailed(msg) =>
                write!(f, "ML-DSA-65 signing failed: {msg}"),
            Self::VerificationFailed =>
                write!(f, "ML-DSA-65 signature verification failed: signature is invalid"),
            Self::IoError(e) =>
                write!(f, "key file I/O error: {e}"),
        }
    }
}

impl std::error::Error for DilithiumError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IoError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for DilithiumError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Generate a fresh ML-DSA-65 keypair and write both keys to `keys/` as PEM
/// files. This is the one-time key generation ceremony.
///
/// Returns `Err(KeysAlreadyExist)` if either file is already present, so that
/// an existing keypair is never silently overwritten. Call `delete_keys()`
/// first if you genuinely need to rotate.
pub fn keygen() -> Result<(), DilithiumError> {
    if keys_exist() {
        return Err(DilithiumError::KeysAlreadyExist);
    }

    let (pk, sk) = mldsa65::keypair();

    write_pem(&public_key_path(), PK_LABEL, pk.as_bytes())?;
    write_pem(&secret_key_path(), SK_LABEL, sk.as_bytes())?;

    Ok(())
}

/// Idempotent function to delete both key files from `keys/`.
///
/// The caller must delete all credentials signed with the current keypair
/// before calling this. See spec for rationale.
pub fn delete_keys() -> Result<(), DilithiumError> {
    let pk_path = public_key_path();
    let sk_path = secret_key_path();

    for path in [&pk_path, &sk_path] {
        if path.exists() {
            std::fs::remove_file(path)?;
        }
    }

    Ok(())
}

/// Produce a detached ML-DSA-65 signature over a 32-byte little-endian
/// merkle root. The root is the canonical form used for signing, as defined
/// in `AttributeTree::root_bytes()`.
pub fn sign(root_bytes: &[u8; 32], sk: &MlDsaSecretKey) -> MlDsaSignature {
    MlDsaSignature(mldsa65::detached_sign(root_bytes, &sk.0))
}

/// Verify a detached ML-DSA-65 signature against a 32-byte merkle root and a
/// public key.
///
/// Returns `Ok(())` if the signature is valid.
/// Returns `Err(VerificationFailed)` if the signature does not match.
/// Returns another `DilithiumError` variant on a system error.
pub fn verify(
    signature: &MlDsaSignature,
    root_bytes: &[u8; 32],
    pk: &MlDsaPublicKey,
) -> Result<(), DilithiumError> {
    mldsa65::verify_detached_signature(&signature.0, root_bytes, &pk.0)
        .map_err(|_: VerificationError| DilithiumError::VerificationFailed)
}

/// Read and decode the public key from `keys/`. Called by the issuer when
/// assembling a credential, and by the verifier before signature verification.
pub fn load_public_key() -> Result<MlDsaPublicKey, DilithiumError> {
    let bytes = read_pem(&public_key_path(), PK_LABEL)?;
    PublicKey::from_bytes(&bytes)
        .map(MlDsaPublicKey)
        .map_err(|_| DilithiumError::KeyDecodingFailed(
            format!("public key decoded to {} bytes but expected {}", bytes.len(), mldsa65::public_key_bytes())
        ))
}

/// Read and decode the secret key from `keys/`. Called by the issuer only,
/// immediately before signing. Do not cache the returned value.
pub fn load_secret_key() -> Result<MlDsaSecretKey, DilithiumError> {
    let bytes = read_pem(&secret_key_path(), SK_LABEL)?;
    SecretKey::from_bytes(&bytes)
        .map(MlDsaSecretKey)
        .map_err(|_| DilithiumError::KeyDecodingFailed(
            format!("secret key decoded to {} bytes but expected {}", bytes.len(), mldsa65::secret_key_bytes())
        ))
}

// ── Private helpers ───────────────────────────────────────────────────────────

fn public_key_path() -> PathBuf {
    Path::new(KEYS_DIR).join(PK_FNAME)
}

fn secret_key_path() -> PathBuf {
    Path::new(KEYS_DIR).join(SK_FNAME)
}

/// Returns true if both key files are present on disk.
fn keys_exist() -> bool {
    public_key_path().exists() && secret_key_path().exists()
}

/// Encode `data` as PEM with the given label and write it to `path`.
/// Creates the parent directory (`keys/`) if it does not already exist.
fn write_pem(path: &Path, label: &str, data: &[u8]) -> Result<(), DilithiumError> {
    use std::fmt::Write as FmtWrite;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // PEM: base64 body wrapped at 64 characters per line.
    let b64 = base64::engine::general_purpose::STANDARD.encode(data);
    let mut body = String::new();
    for chunk in b64.as_bytes().chunks(64) {
        body.write_str(std::str::from_utf8(chunk).unwrap()).unwrap();
        body.push('\n');
    }

    let pem = format!("-----BEGIN {label}-----\n{body}-----END {label}-----\n");
    std::fs::write(path, pem)?;

    Ok(())
}

/// Read a PEM file at `path`, verify the label matches `expected_label`, and
/// return the decoded raw bytes.
fn read_pem(path: &Path, expected_label: &str) -> Result<Vec<u8>, DilithiumError> {
    if !path.exists() {
        return Err(DilithiumError::KeysNotFound);
    }

    let pem_str = std::fs::read_to_string(path)?;

    let begin = format!("-----BEGIN {expected_label}-----");
    let end   = format!("-----END {expected_label}-----");

    let inner = pem_str
        .lines()
        .skip_while(|l| *l != begin.as_str())
        .skip(1) // skip the BEGIN line itself
        .take_while(|l| *l != end.as_str())
        .collect::<Vec<_>>()
        .join("");

    if inner.is_empty() {
        return Err(DilithiumError::KeyDecodingFailed(
            format!("PEM file at '{}' is missing or has wrong label (expected '{expected_label}')", path.display())
        ));
    }

    base64::engine::general_purpose::STANDARD
        .decode(&inner)
        .map_err(|e| DilithiumError::KeyDecodingFailed(
            format!("base64 decode failed for '{}': {e}", path.display())
        ))
}
