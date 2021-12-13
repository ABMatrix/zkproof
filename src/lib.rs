pub mod constraint;
pub mod groth16;

pub mod common;
use common::*;

// #[cfg(feature="bls12_381")]
// pub mod poseidon_zk_param_bls12_381;
// #[cfg(feature="bls12_381")]
// pub use poseidon_zk_param_bls12_381::*;
#[cfg(feature="bls12_381")]
use ark_bls12_381::Bls12_381;
#[cfg(feature="bls12_381")]
pub type CurveTypeG = Bls12_381;
#[cfg(feature="bls12_381")]
pub use ark_bls12_381::*;
#[cfg(feature="bls12_381")]
pub type ConstraintF = ark_ed_on_bls12_381::Fq;
#[cfg(feature="bls12_381")]
pub use ark_ed_on_bls12_381::EdwardsProjective as JubJub;

// #[cfg(feature="bls12_377")]
// pub mod poseidon_zk_param_bls12_377;
// #[cfg(feature="bls12_377")]
// pub use poseidon_zk_param_bls12_377::*;
#[cfg(feature="bls12_377")]
use ark_bls12_377::Bls12_377;
#[cfg(feature="bls12_377")]
pub type CurveTypeG = Bls12_377;
#[cfg(feature="bls12_377")]
pub use ark_bls12_377::*;
#[cfg(feature="bls12_377")]
pub type ConstraintF = ark_ed_on_bls12_377::Fq;
#[cfg(feature="bls12_377")]
pub use ark_ed_on_bls12_377::EdwardsProjective as JubJub;

// #[cfg(feature="bn254")]
// pub mod poseidon_zk_param_bn254;
// #[cfg(feature="bn254")]
// pub use poseidon_zk_param_bn254::*;
#[cfg(feature="bn254")]
use ark_bn254::Bn254;
#[cfg(feature="bn254")]
pub type CurveTypeG= Bn254;
#[cfg(feature="bn254")]
pub use ark_bn254::*;
#[cfg(feature="bn254")]
pub type ConstraintF = ark_ed_on_bn254::Fq;
#[cfg(feature="bn254")]
pub use ark_ed_on_bn254::EdwardsProjective as JubJub;




use ark_crypto_primitives::{Path, crh::TwoToOneCRH};
/// The root of the account Merkle tree.
pub type Root = <TwoToOneHash as TwoToOneCRH>::Output;

/// A membership proof for a given leaf.
pub type MembPath = Path<MyMerkleTreeParams>;
