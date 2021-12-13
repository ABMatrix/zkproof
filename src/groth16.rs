use ark_crypto_primitives::MerkleTree;
use ark_crypto_primitives::crh::CRH;
use ark_crypto_primitives::crh::TwoToOneCRHGadget;

use ark_relations::r1cs::ConstraintSynthesizer;
use ark_relations::r1cs::ConstraintSystemRef;
use ark_relations::r1cs::SynthesisError;

use ark_std::rand::{Rng, SeedableRng};
use ark_std::test_rng;

use ark_crypto_primitives::SNARK;
use ark_r1cs_std::prelude::*;
use ark_groth16::*;
use rand_chacha::ChaCha20Rng;

use crate::*;
use ark_crypto_primitives::merkle_tree::constraints::PathVar;
use crate::constraint::HashCalculate;

pub type RootVar = <TwoToOneHashGadget as TwoToOneCRHGadget<TwoToOneHash, ConstraintF>>::OutputVar;
pub type SimplePathVar =
PathVar<MyMerkleTreeParams,
    LeafHashGadget,
    TwoToOneHashGadget,
    ConstraintF>;


pub fn groth_param_gen_s() -> <Groth16<CurveTypeG> as SNARK<Fr>>::ProvingKey {

    //type MyMerkleTree=MerkleTree::<MyMerkleTreeParams>;
    let mut rng = test_rng();

    let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();
    let leaves = [0u8, 2u8, 5u8, 32u8, 3u8, 4u8, 5u8, 12u8];

    let  m= MerkleTree::<MyMerkleTreeParams>::new(
        &leaf_crh_params.clone(),
        &two_to_one_crh_params.clone(),
        &leaves)
        .unwrap();

    let proof= m.generate_proof(3).unwrap();

    let root = m.root();

    let leaf = 32u8;

    assert!(proof.verify(&leaf_crh_params, &two_to_one_crh_params, &root, &leaf).unwrap());

    let circuit= MerkleTreeCircuit{
        leaf_crh_params: (leaf_crh_params.clone()),
        two_to_one_crh_params: (two_to_one_crh_params.clone()),
        root: (root.clone()),
        leaf: (leaf.clone()),
        authentication_path: Some(proof.clone()),
    };
    generate_random_parameters::<CurveTypeG, _, _>(circuit, &mut rng).unwrap()
}

pub fn groth_proof_gen_s(
    param: &<Groth16<CurveTypeG> as SNARK<Fr>>::ProvingKey,
    circuit: MerkleTreeCircuit,
    seed: &[u8; 32],
) -> <Groth16<CurveTypeG> as SNARK<Fr>>::Proof {
    let mut rng = ChaCha20Rng::from_seed(*seed);
    create_random_proof(circuit, &param, &mut rng).unwrap()
}


pub fn groth_verify_s(
    param: &<Groth16<CurveTypeG> as SNARK<Fr>>::ProvingKey,
    proof: &<Groth16<CurveTypeG> as SNARK<Fr>>::Proof,
    output: Root,
) -> bool {
    let pvk = prepare_verifying_key(&param.vk);
    //let output_fq: Vec<Fq> = ToConstraintField::<Fq>::to_field_elements(output).unwrap();
    verify_proof(&pvk, &proof, &[output]).unwrap()
}

pub fn groth_param_hash()-><Groth16<CurveTypeG> as SNARK<Fr>>::ProvingKey{
    let mut rng = test_rng();
    // let seed:u64 = rng.gen();
    // let uid:u64 = rng.gen();
    // let hash = HashCalculate(seed,uid);
    let circuit = HashCalCircuit{
        seed: None,
        uid: None,
        hash: None
    };
    generate_random_parameters::<CurveTypeG, _, _>(circuit, &mut rng).unwrap()
}

pub fn groth_proof_hash(param: &<Groth16<CurveTypeG> as SNARK<Fr>>::ProvingKey,
                        circuit: MerkleTreeCircuit,)-> <Groth16<CurveTypeG> as SNARK<Fr>>::Proof{
    let mut rng = test_rng();
    create_random_proof(circuit, &param, &mut rng).unwrap()
}

pub fn groth_verify_hash(param: &<Groth16<CurveTypeG> as SNARK<Fr>>::ProvingKey,
                         proof: &<Groth16<CurveTypeG> as SNARK<Fr>>::Proof,
                         uid: u64,) -> bool {
    let pvk = prepare_verifying_key(&param.vk);
    verify_proof(&pvk, &proof, &[uid]).unwrap();
    true
}