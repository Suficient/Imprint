use std::{str::FromStr};
use crate::crypto::circomlib_poseidon_constants::*;
use ark_bn254::Fr;
use ark_ff::{AdditiveGroup};
use once_cell::sync::Lazy;

// This file contains intermediate functions to convert the circomlib poseidon constants
// to a format readable by the arkworks' poseidon function implementation.

// The circomlib round constants are stored as a single dimensional matrix, but arkworks poseidon
//  expects a two dimensional matrix arranged according to round number.

fn fr(hex: &'static str) -> Fr {
    Fr::from_str(hex).expect("invalid field element")
}

pub static POSEIDON_ARK_T3: Lazy<Vec<Vec<Fr>>> = Lazy::new(|| {
    derive_ark_vector(3)
});

// function to derive ark vector in a format that is usable with arkworks poseidon.
// Bounds checks and tests must be added to ensure that the code doesn't silently panic.
fn derive_ark_vector(t: usize) -> Vec<Vec<Fr>> {

    // NUM_PARTIAL_ROUNDS[t-2] is the number of partial rounds for some t value as implemented in circom.
    const NUM_PARTIAL_ROUNDS: [u8; 16] = [
        56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68,
    ];

    #[derive(Clone)]
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

        let roundvector: Vec<ARKWidth> = rounds;

        roundvector
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

    for i in rounds.iter() {
        let temp: Vec<Fr>;
        match i {
            &ARKWidth::Full => {
                temp = generate_full_round_vector(
                    &mut circomlib_constants_index,
                    &circomlib_constants,
                    t,
                )
            }
            &ARKWidth::Partial => {
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
