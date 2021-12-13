use std::hash::Hash;
use ark_crypto_primitives::CRH;
use ark_crypto_primitives::crh::TwoToOneCRH;
use ark_crypto_primitives::crh::constraints::{CRHGadget, TwoToOneCRHGadget};
use ark_crypto_primitives::crh::injective_map::constraints::{
    PedersenCRHCompressorGadget, TECompressorGadget,
};
use ark_crypto_primitives::crh::{
    injective_map::{PedersenCRHCompressor, TECompressor},
    pedersen,
};
use ark_crypto_primitives::merkle_tree::Config;
#[cfg(feature="bls12_381")]
pub use ark_ed_on_bls12_381::{constraints::EdwardsVar};
#[cfg(feature="bls12_377")]
pub use ark_ed_on_bls12_377::{constraints::EdwardsVar};
#[cfg(feature="bn254")]
pub use ark_ed_on_bn254::{constraints::EdwardsVar};
use ark_ff::Field;

use crate::{ConstraintF, JubJub, MembPath, Root};

//pub type TwoToOneHash = PedersenCRHCompressor<EdwardsProjective, TECompressor, TwoToOneWindow>;
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Window4x256;
impl pedersen::Window for Window4x256 {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 256;
}

//pub type H = pedersen::CRH<JubJub, Window4x256>;
pub type LeafHash = PedersenCRHCompressor<JubJub, TECompressor, Window4x256>;

// #[derive(Clone, PartialEq, Eq, Hash)]
// pub struct Window4x128;

// impl pedersen::Window for Window4x128 {
//     const WINDOW_SIZE: usize = 4;
//     const NUM_WINDOWS: usize = 128;
// }
//pub type TH = pedersen::CRH<JubJub, Window4x256>;
pub type TwoToOneHash = PedersenCRHCompressor<JubJub, TECompressor, Window4x256>;

#[derive(Clone)]

pub struct MyMerkleTreeParams;

impl Config for MyMerkleTreeParams {
    type LeafHash = LeafHash;
    type TwoToOneHash = TwoToOneHash;
}

pub struct MerkleTreeCircuit {
    // These are constants that will be embedded into the circuit
    pub leaf_crh_params: <LeafHash as CRH>::Parameters,
    pub two_to_one_crh_params: <TwoToOneHash as TwoToOneCRH>::Parameters,

    // This is the public input to the circuit.
    pub root: Root,

    // These are the private witnesses to the circuit.
    pub leaf: u8,
    pub authentication_path: Option<MembPath>,
}

pub type TwoToOneHashGadget = PedersenCRHCompressorGadget<
    JubJub,
    TECompressor,
    Window4x256,
    EdwardsVar,
    TECompressorGadget,
>;

pub type LeafHashGadget = PedersenCRHCompressorGadget<
    JubJub,
    TECompressor,
    Window4x256,
    EdwardsVar,
    TECompressorGadget,
>;

pub type LeafHashParamsVar = <LeafHashGadget as CRHGadget<LeafHash, ConstraintF>>::ParametersVar;
pub type TwoToOneHashParamsVar =
<TwoToOneHashGadget as TwoToOneCRHGadget<TwoToOneHash, ConstraintF>>::ParametersVar;

// pub struct HashCalCircuit<F:Field> {
//     pub seed: Option<F>,//public param
//     pub uid: Option<F>,//public input
//     pub hash: Option<F>,//witness
// }