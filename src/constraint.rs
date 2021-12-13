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

pub type RootVar = <TwoToOneHashGadget as TwoToOneCRHGadget<TwoToOneHash, ConstraintF>>::OutputVar;
pub type SimplePathVar =
PathVar<MyMerkleTreeParams,
    LeafHashGadget,
    TwoToOneHashGadget,
    ConstraintF>;

impl ConstraintSynthesizer<ConstraintF> for MerkleTreeCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        // First, we allocate the public inputs
        let root = RootVar::new_input(ark_relations::ns!(cs, "root_var"), || Ok(&self.root))?;

        let leaf = UInt8::new_witness(ark_relations::ns!(cs, "leaf_var"), || Ok(&self.leaf))?;

        // Then, we allocate the public parameters as constants:
        let leaf_crh_params = LeafHashParamsVar::new_constant(cs.clone(), &self.leaf_crh_params)?;
        let two_to_one_crh_params =
            TwoToOneHashParamsVar::new_constant(cs.clone(), &self.two_to_one_crh_params)?;

        // Finally, we allocate our path as a private witness variable:
        let path = SimplePathVar::new_witness(ark_relations::ns!(cs, "path_var"), || {
            Ok(self.authentication_path
                .as_ref()
                .unwrap())
        })?;

        let leaf_bytes = vec![leaf; 1];
        let leaf_g :&[_] =leaf_bytes.as_slice();
        // Now, we have to check membership. How do we do that?
        // Hint: look at https://github.com/arkworks-rs/crypto-primitives/blob/6be606259eab0aec010015e2cfd45e4f134cd9bf/src/merkle_tree/constraints.rs#L135

        // TODO: FILL IN THE BLANK!
        let is_member = path.verify_membership(
            &leaf_crh_params,
            &two_to_one_crh_params,
            &root,
            &leaf_g)?;
        //
        is_member.enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}

#[test]
pub fn constraint_test(){
    use ark_crypto_primitives::crh::TwoToOneCRH;
    use ark_crypto_primitives::merkle_tree::*;
    use ark_crypto_primitives::crh::CRH;
    use crate::common::{LeafHash, MyMerkleTreeParams, TwoToOneHash};
    //use crate::common::MerkleTreeCircuit;

    use ark_std::{test_rng};

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

    // let circuit= MerkleTreeCircuit{
    //     leaf_crh_params: (leaf_crh_params.clone()),
    //     two_to_one_crh_params: (two_to_one_crh_params.clone()),
    //     root: (root.clone()),
    //     leaf: (leaf.clone()),
    //     authentication_path: Some(proof.clone()),
    // };
}

// impl ConstraintSynthesizer<ConstraintF> for HashCalCircuit<F> {
//     fn generate_constraints(
//         self,
//         cs: ConstraintSystemRef<ConstraintF>,
//     ) -> Result<(), SynthesisError> {
//         let mut seed_value = self.seed;
//         let mut seed = cs.new_witness_variable(seed_value.clone());
//         let mut hash_value = self.hash;
//         let mut hash = cs.new_witness_variable(hash_value.clone());
//         let mut uid_value = self.uid;
//         let mut uid = cs.new_input_variable(uid_value.clone());
//         let is_satisfied = HashVerify(seed_value as u64,uid_value as u64,hash_value as u64);
//         // if is_satisfied{
//         //     cs.enforce_constraint(
//         //         lc!() + seed,
//         //         lc!() + hash,
//         //         lc!() + uid,
//         //     )?;
//         // }else {
//         //     panic!("HashVerify failed.");
//         // }
//         Ok(())
//     }
//
// }
//
// pub fn HashVerify(seed_value:u64,uid_value:u64,hash_value:u64) -> bool {
//     use std::collections::hash_map::DefaultHasher;
//     use std::hash::Hasher;
//     let mut hasher = DefaultHasher::new();
//     hasher.write_u64(seed_value);
//     hasher.write_u64(uid_value);
//     let mut cal = hasher.finish();
//     let mut i = 0;
//     loop {
//         let mut hasher = DefaultHasher::new();
//         hasher.write_u64(cal);
//         cal = hasher.finish();
//         i += 1;
//         if i == 1000 {break;}
//     };
//     //println!("cal: {:?}",cal);
//     hash_value == cal
// }
//
// pub fn HashCalculate(seed:u64,uid:u64) -> u64{
//     use std::collections::hash_map::DefaultHasher;
//     use std::hash::Hasher;
//     let mut hasher = DefaultHasher::new();
//     hasher.write_u64(seed);
//     hasher.write_u64(uid);
//     let mut cal = hasher.finish();
//     let mut i = 0;
//     loop {
//         let mut hasher = DefaultHasher::new();
//         hasher.write_u64(cal);
//         cal = hasher.finish();
//         i += 1;
//         if i == 1000 {break cal;}
//     }
// }
//
// #[test]
// pub fn hash_constraint_test(){
//     let mut rng = test_rng();
//     let seed:u64 = rng.gen();
//     let uid:u64 = rng.gen();
//     let hash = HashCalculate(seed,uid);
//     //println!("hash: {:?}",hash);
//     assert!(HashVerify(seed,uid,hash))
// }