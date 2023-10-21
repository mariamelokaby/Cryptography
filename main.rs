
use sha2::{Digest, Sha256};
use generic_array::typenum::U32;
use generic_array::GenericArray;

use std::fmt::Debug;

// Define the SumCommitment trait
pub trait SumCommitment: Debug + Clone {
    fn amount(&self) -> u64;
    fn digest(&self) -> GenericArray<u8, U32>;
    fn combine_commitments(left: &Self, right: &Self) -> Self;
    fn new(balance: u64) -> Self;
}

// Define the ExclusiveAllotmentProof trait
pub trait ExclusiveAllotmentProof<C: SumCommitment>: Debug {
    fn new(position: usize, sibling: Option<C>) -> Self;
    fn position(&self) -> usize;
    fn sibling(&self) -> Option<C>;
    fn verify(&self, root_commitment: &C) -> bool;
    fn reconstruct_commitment(&self, root_commitment: &C) -> C;
    fn reconstruct_commitment_recursive(&self, node_index: usize, root_commitment: &C) -> C;
}

// Define the MerkleProof struct
#[derive(Debug)]
pub struct MerkleProof<C: SumCommitment> {
    sibling: Option<C>,
    sibling_position: usize,
}

impl<C: SumCommitment> MerkleProof<C> {
    pub fn new(sibling: Option<C>, sibling_position: usize) -> Self {
        MerkleProof {
            sibling,
            sibling_position,
        }
    }

    pub fn sibling(&self) -> Option<C> {
        self.sibling.clone()
    }

    pub fn sibling_position(&self) -> usize {
        self.sibling_position
    }
}

// Define MimiSumCommitment struct
#[derive(Debug, Clone)]
pub struct MimiSumCommitment {
    amount: u64,
    digest: GenericArray<u8, U32>,
}

impl SumCommitment for MimiSumCommitment {
    fn amount(&self) -> u64 {
        self.amount
    }

    fn digest(&self) -> GenericArray<u8, U32> {
        self.digest.clone()
    }

    fn combine_commitments(left: &Self, right: &Self) -> Self {
        let combined_amount = left.amount() + right.amount();
        let combined_digest = hash_bytes(&[left.digest(), right.digest()].concat());

        MimiSumCommitment {
            amount: combined_amount,
            digest: combined_digest,
        }
    }

    fn new(balance: u64) -> Self {
        MimiSumCommitment {
            amount: balance,
            digest: hash_bytes(&balance.to_le_bytes()),
        }
    }
}

fn hash_bytes(slice: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(slice);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(result.as_slice());
    output
}

// Define MimiMerkleTree struct
pub struct MimkMerkleTree<C: SumCommitment, P: ExclusiveAllotmentProof<C>> {
    leaf_nodes: Vec<C>,
}

impl<C, P> MimkMerkleTree<C, P>
where
    C: SumCommitment + Clone + PartialEq,
    P: ExclusiveAllotmentProof<C>,
{
    pub fn new(values: Vec<u64>) -> Self {
        let leaf_nodes: Vec<C> = values.into_iter().map(|balance| C::new(balance)).collect();
        Self { leaf_nodes }
    }

    pub fn commit(&self) -> C {
        self.build_merkle_tree(0, &self.leaf_nodes)
    }

    pub fn prove(&self, position: usize) -> P {
        let proof = self.construct_inclusion_proof(position, 0, &self.leaf_nodes);
        P::new(position, proof.sibling)
    }

    fn build_merkle_tree(&self, node_index: usize, nodes: &[C]) -> C {
        if nodes.len() == 1 {
            return nodes[0].clone();
        }
        let middle = nodes.len() / 2;
        let left = &nodes[0..middle];
        let right = &nodes[middle..];

        let left_commitment = self.build_merkle_tree(node_index * 2 + 1, left);
        let right_commitment = self.build_merkle_tree(node_index * 2 + 2, right);

        C::combine_commitments(&left_commitment, &right_commitment)
    }

    fn construct_inclusion_proof(
        &self,
        position: usize,
        node_index: usize,
        nodes: &[C],
    ) -> MerkleProof<C> {
        if nodes.len() == 1 {
            return MerkleProof::new(None, node_index);
        }

        let middle = nodes.len() / 2;
        if position < middle {
            // The position is in the left subtree
            let right_commitment = self.build_merkle_tree(node_index * 2 + 2, &nodes[middle..]);
            let right_sibling_position = node_index * 2 + 1;
            MerkleProof::new(Some(right_commitment), right_sibling_position)
        } else {
            // The position is in the right subtree
            let left_commitment = self.build_merkle_tree(node_index * 2 + 1, &nodes[0..middle]);
            let left_sibling_position = node_index * 2 + 2;
            MerkleProof::new(Some(left_commitment), left_sibling_position)
        }
    }
}

fn main() {
    let values = vec![100, 200, 300, 400, 500];
    let merkle_tree = MimkMerkleTree::<MimiSumCommitment, MerkleProof<MimiSumCommitment>>::new(values);
    let commitment = merkle_tree.commit();
    let proof = merkle_tree.prove(2);

    println!("Root Commitment: {:?}", commitment);
    println!("Proof: {:?}", proof);
}

