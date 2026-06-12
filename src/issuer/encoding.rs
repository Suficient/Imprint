//! Byte-string → field-element encoding for KoalaBear.
//!
//! A KoalaBear element holds 31 bits, so the safe byte chunk is 3 bytes
//! (24 bits): a 4-byte chunk could exceed `p = 2^31 - 2^24 + 1` and silently
//! wrap mod p, making the encoding non-injective. Never raise `CHUNK_BYTES`.
//!
//! Only byte strings (currently only name) need an encoding scheme. Numeric attributes (gender,
//! DOB days, country code) are each bounded far below 2^24 by validation and
//! encode directly as a single field element at the attribute layer.

use crate::crypto::field::F;

pub const CHUNK_BYTES: usize = 3;

/// Encode an arbitrary byte string injectively as field elements:
/// `[byte_length] ++ 3-byte big-endian chunks` (last chunk zero-padded).
///
/// The explicit length element keeps zero-padding injective
pub fn encode_bytes(bytes: &[u8]) -> Vec<F> {
    let mut out = Vec::with_capacity(1 + bytes.len().div_ceil(CHUNK_BYTES));
    out.push(F::new(bytes.len() as u32));

    for chunk in bytes.chunks(CHUNK_BYTES) {
        let mut padded = [0u8; CHUNK_BYTES];
        padded[..chunk.len()].copy_from_slice(chunk);
        // 24-bit value, always < p by construction.
        let v = u32::from_be_bytes([0, padded[0], padded[1], padded[2]]);
        out.push(F::new(v));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeField32;

    /// Test-only inverse of [`encode_bytes`]. Its existence is the injectivity
    /// argument made executable: if every encoding decodes back to its input,
    /// no two inputs share an encoding.
    fn decode_bytes(elems: &[F]) -> Vec<u8> {
        let len = elems[0].as_canonical_u32() as usize;
        let mut bytes = Vec::with_capacity(len);
        for elem in &elems[1..] {
            let v = elem.as_canonical_u32();
            assert!(v < (1 << 24), "chunk exceeds 24 bits");
            bytes.extend_from_slice(&v.to_be_bytes()[1..]);
        }
        bytes.truncate(len);
        bytes
    }

    #[test]
    fn random_roundtrip_is_injective() {
        // Seeded xorshift — deterministic, no RNG dependency needed.
        let mut state: u64 = 0x5DEECE66D;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        for _ in 0..5000 {
            let len = (next() % 128) as usize;
            let bytes: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let enc = encode_bytes(&bytes);
            assert_eq!(enc.len(), 1 + len.div_ceil(CHUNK_BYTES));
            assert_eq!(decode_bytes(&enc), bytes);
        }
    }

    #[test]
    fn multibyte_utf8_encodes_as_bytes() {
        // The unit is bytes, not characters: "सूफ़ी" is 5 chars but 15 bytes
        // (Devanagari is 3 bytes per char in UTF-8).
        let name = "सूफ़ी";
        assert_eq!(name.len(), 15);
        let enc = encode_bytes(name.as_bytes());
        assert_eq!(enc[0], F::new(15));
        assert_eq!(enc.len(), 1 + 5); // length prefix + ceil(15/3) chunks
        assert_eq!(decode_bytes(&enc), name.as_bytes());
    }

    #[test]
    fn chunk_boundary_three_bytes_max() {
        // Max 3-byte chunk must encode as exactly 0xFFFFFF — no mod-p wrap.
        let enc = encode_bytes(&[0xFF, 0xFF, 0xFF]);
        assert_eq!(enc.len(), 2); // length prefix + 1 chunk
        assert_eq!(enc[0], F::new(3));
        assert_eq!(enc[1], F::new(0x00FF_FFFF));
    }

    #[test]
    fn zero_padding_is_injective() {
        // "AB" vs "AB\0" must differ (length prefix distinguishes them).
        let a = encode_bytes(b"AB");
        let b = encode_bytes(b"AB\0");
        assert_ne!(a, b);
    }

    #[test]
    fn multi_chunk_roundtrip_layout() {
        // 7 bytes -> length prefix + 3 chunks (3+3+1 padded).
        let enc = encode_bytes(b"ABCDEFG");
        assert_eq!(enc.len(), 4);
        assert_eq!(enc[0], F::new(7));
        assert_eq!(enc[1], F::new(u32::from_be_bytes([0, b'A', b'B', b'C'])));
        assert_eq!(enc[2], F::new(u32::from_be_bytes([0, b'D', b'E', b'F'])));
        assert_eq!(enc[3], F::new(u32::from_be_bytes([0, b'G', 0, 0])));
    }

    #[test]
    fn empty_input() {
        let enc = encode_bytes(b"");
        assert_eq!(enc, vec![F::new(0)]);
    }

}
