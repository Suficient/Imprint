use std::{str::FromStr};
use crate::crypto::circomlib_poseidon_constants::*;
use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, PrimeField};
use once_cell::sync::Lazy;

// This file contains intermediate functions to convert the circomlib poseidon constants
// to a format readable by the arkworks' poseidon function implementation.

pub fn fr(s: &str) -> Fr {
    if let Some(hex_str) = s.strip_prefix("0x") {

        let hex_str = if hex_str.len() % 2 != 0 {
            format!("0{}", hex_str)
        } else {
            hex_str.to_string()
        };

        let mut bytes = hex::decode(&hex_str)
            .unwrap_or_else(|e| panic!("Invalid hex string '{}': {:?}", s, e));

        <Fr as PrimeField>::from_be_bytes_mod_order(&bytes)

    } else {
        Fr::from_str(s).unwrap_or_else(|e| {
            panic!("Failed to parse decimal field element from '{}': {:?}", s, e)
        })
    }
}

pub static POSEIDON_ARK_T3: Lazy<Vec<Vec<Fr>>> = Lazy::new(|| {
    transcode_ark_from_circomlib(3)
});

pub static POSEIDON_MDS_T3: Lazy<Vec<Vec<Fr>>> = Lazy::new(|| {
    transpose(transcode_mds_from_circomlib(3))
});

// NUM_PARTIAL_ROUNDS[t-2] is the number of partial rounds for some t value as implemented in circom.
pub const NUM_PARTIAL_ROUNDS: [u8; 16] = [
    56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68,
];

// function to transcode ark vector in a format that is usable with arkworks poseidon.
// Bounds checks and tests must be added to ensure that the code doesn't silently panic.
fn transcode_ark_from_circomlib(t: usize) -> Vec<Vec<Fr>> {



    #[derive(Clone, Debug)]
    enum ARKWidth {
        Partial, // Partial rounds where RC is added only to the first element of the state vector
        Full,    // Full rounds where RC is added to every element of the state vector
    }

    // This function takes a value of t, and derives a vector that describes the sequence of rounds
    // within a poseidon-128 hash function. These functions have 8 full rounds for each value of T,
    // but the number of partial rounds differs based on t value according to the NUM_PARTIAL_ROUNDS
    // array. The rounds are arranged as rf/2 full rounds, rp partial rounds, and then rf/2 full rounds.
    fn derive_rounds(t: usize) -> Vec<ARKWidth> {
        let partial_round_index: usize = t - 2;
        let rf: u8 = 8;
        let rp: u8 = NUM_PARTIAL_ROUNDS[partial_round_index];
        let mut rounds: Vec<ARKWidth> = Vec::with_capacity((rf + rp) as usize);

        rounds.extend(std::iter::repeat(ARKWidth::Full).take(4));
        rounds.extend(std::iter::repeat(ARKWidth::Partial).take(rp as usize));
        rounds.extend(std::iter::repeat(ARKWidth::Full).take(4));

        rounds
    }

    fn generate_partial_round_vector(
        index: &mut usize,
        circomlib_constants: &Vec<Fr>,
        t: usize,
    ) -> Vec<Fr> {
        let c: Fr = circomlib_constants[*index];
        *index += 1;

        let mut temp: Vec<Fr> = Vec::with_capacity(t);
        temp.push(c);
        temp.extend(std::iter::repeat(Fr::ZERO).take(t - 1));

        temp
    }

    fn generate_full_round_vector(
        index: &mut usize,
        circomlib_constants: &Vec<Fr>,
        t: usize,
    ) -> Vec<Fr> {
        let start: usize = *index;
        let end: usize = start + t;

        *index = end;

        circomlib_constants[start..end].to_vec()
    }

    let circomlib_constants: Vec<Fr> = get_circomlib_round_constants(t)
    .iter()
    .map(|&s| fr(s))
    .collect();

    let rounds: Vec<ARKWidth> = derive_rounds(t);
    let mut ark: Vec<Vec<Fr>> = Vec::with_capacity(rounds.len());
    let mut circomlib_constants_index: usize = 0;

    for round in rounds {
        let temp: Vec<Fr>;
        match round {
            ARKWidth::Full => {
                temp = generate_full_round_vector(
                    &mut circomlib_constants_index,
                    &circomlib_constants,
                    t,
                )
            }
            ARKWidth::Partial => {
                temp = generate_partial_round_vector(
                    &mut circomlib_constants_index,
                    &circomlib_constants,
                    t,
                )
            }
        }
        ark.push(temp);
    }

    ark
}

fn transcode_mds_from_circomlib(t: usize) -> Vec<Vec<Fr>> {
    get_circomlib_mds(t)
        .iter()
        .map(|row| {
            row.iter()
               .map(|&s| fr(s))
               .collect()
        })
        .collect()
}

fn transpose(matrix: Vec<Vec<Fr>>) -> Vec<Vec<Fr>> {
    let rows = matrix.len();
    let cols = matrix[0].len();

    let mut transposed = vec![vec![Fr::ZERO; rows]; cols];

    for i in 0..rows {
        for j in 0..cols {
            transposed[j][i] = matrix[i][j];
        }
    }

    transposed
}