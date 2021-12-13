use std::time::Instant;
use ark_crypto_primitives::CRH;
use ark_crypto_primitives::MerkleTree;
use ark_crypto_primitives::crh::TwoToOneCRH;
use ark_std::test_rng;
use merkletree::common::*;
use merkletree::constraint::*;
use merkletree::groth16::*;


fn main() {
    let start_param_gen = Instant::now();

    let mut rng = test_rng();

    let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();
    let leaves = [0u8, 2u8, 5u8, 32u8, 3u8, 4u8, 5u8, 12u8];

    let mut m= MerkleTree::<MyMerkleTreeParams>::new(
        &leaf_crh_params.clone(),
        &two_to_one_crh_params.clone(),
        &leaves)
        .unwrap();

    let proof= m.generate_proof(3).unwrap();

    let root = m.root();

    let leaf = 32u8;

    assert!(proof.verify(&leaf_crh_params, &two_to_one_crh_params, &root, &leaf).unwrap());
    m.update(2, &leaf).unwrap();

    let circuit= MerkleTreeCircuit{
        leaf_crh_params: (leaf_crh_params.clone()),
        two_to_one_crh_params: (two_to_one_crh_params.clone()),
        root: (root.clone()),
        leaf: (leaf.clone()),
        authentication_path: Some(proof.clone()),
    };
    let elapsed_param_gen = start_param_gen.elapsed();
    println!("time to generate public paremeters and comm: {:?}", elapsed_param_gen);
    // generate ZK_param
    let start_zk_param = Instant::now();
    let zk_param = groth_param_gen_s();
    let elapsed_zk_param = start_zk_param.elapsed();
    println!("time to gen zk_param: {:?}", elapsed_zk_param);

    let start_proof = Instant::now();

    let proof = groth_proof_gen_s(&zk_param, circuit, &[32u8; 32]);

    let elapse_proof = start_proof.elapsed();
    println!("time to gen proof: {:?}", elapse_proof);

    let start_verify = Instant::now();
    assert!(groth_verify_s(&zk_param, &proof, root));
    let elapse_verify = start_verify.elapsed();
    println!("time to verify proof: {:?}", elapse_verify);

}
