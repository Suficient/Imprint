use std::str::FromStr;

use crate::crypto::{poseidon::poseidon_t3, poseidon_constants::{fr}};
use ark_bn254::{Fr};
use ark_ff::{self, PrimeField};
use ark_ff::BigInteger;



pub mod crypto;

fn main() {
    let a = fr("1");
    let b = fr("2");

    let out = poseidon_t3(a, b);

    // let test = fr("0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a");
    println!("poseidon(1, 2) = {}", hex::encode(out.into_bigint().to_bytes_be()));
    println!("the number is {}", out);


    let fr = "115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a";
    println!("expected       = {}", fr);

}
