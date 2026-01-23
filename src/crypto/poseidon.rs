use ark_bn254::Fr;
use ark_crypto_primitives::crh::poseidon::CRH;
use ark_crypto_primitives::crh::CRHScheme;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use once_cell::sync::Lazy;
use crate::crypto::poseidon_constants;

pub static POSEIDON_CONFIG_T3: Lazy<PoseidonConfig<Fr>> = Lazy::new(|| {
    PoseidonConfig {
    full_rounds: 8,
    partial_rounds: 57, //poseidon_constants::NUM_PARTIAL_ROUNDS[1] as usize,
    alpha: 5,
    ark: poseidon_constants::POSEIDON_ARK_T3.clone(),
    mds: poseidon_constants::POSEIDON_MDS_T3.clone(),
    rate: 2,
    capacity: 1
    }
});

pub fn poseidon_t3(input1: Fr, input2: Fr) -> Fr {
    let inputs = [input1, input2];
    return CRH::<Fr>::evaluate(&POSEIDON_CONFIG_T3, &inputs[..]).unwrap();
}