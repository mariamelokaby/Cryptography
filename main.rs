use sha2::{Digest, Sha256};
pub trait SumCommitment {
    fn amount(&self) -> u64;
    fn digest(&self) -> [u8; 32];
}

pub trait ExclusiveAllotmentProof<C: SumCommitment> {
    fn position(&self) -> usize;
    fn sibling(&self) -> Option<&C>;
    fn verify(&self, root_commitment: &C) -> bool;
    fn generate_proof(position: usize, sibling: Option<&C>) -> Self;
}

pub trait MerkleTree<C: SumCommitment> {
    type P: ExclusiveAllotmentProof<C>;

    fn new(values: Vec<u64>) -> Self;
    fn commit(&self) -> C;
    fn prove(&self, position: usize) -> Self::P;
}

fn hash_bytes(slice: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(slice);
    hasher.finalize().into()
}
#[derive(Clone, PartialEq)]
pub struct MimiSumCommitmentWrapper {
    inner: MimiSumCommitment,
}

impl MimiSumCommitmentWrapper {
    pub fn new(amount: u64, digest: [u8; 32]) -> Self {
        let inner = MimiSumCommitment { amount, digest };
        MimiSumCommitmentWrapper { inner }
    }
}

impl SumCommitment for MimiSumCommitmentWrapper {
    fn amount(&self) -> u64 {
        self.inner.amount
    }

    fn digest(&self) -> [u8; 32] {
        self.inner.digest
    }
}
impl MimiSumCommitment {
    pub fn new(amount: u64, digest: [u8; 32]) -> Self {
        MimiSumCommitment { amount, digest }
    }
}


#[derive(Clone, PartialEq)]
pub struct MimiSumCommitment {
    pub amount: u64,
    pub digest: [u8; 32],
}

impl SumCommitment for MimiSumCommitment {
    fn amount(&self) -> u64 {
        self.amount
    }

    fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

pub struct MimiExclusiveAllotmentProof<C: SumCommitment> {
    pub position: usize,
    pub sibling: Option<C>,
}

impl<C> ExclusiveAllotmentProof<C> for MimiExclusiveAllotmentProof<C>
where
    C: SumCommitment + Clone + PartialEq,
{
    fn position(&self) -> usize {
        self.position
    }

    fn sibling(&self) -> Option<&C> {
        self.sibling.as_ref()
    }

    fn verify(&self, root_commitment: &C) -> bool {
        if let Some(sibling) = &self.sibling {
            let computed_commitment = compute_merkle_commitment(self.position(), sibling, root_commitment);
            computed_commitment == *root_commitment
        } else {
            false
        }
    }

    fn generate_proof(position: usize, sibling: Option<&C>) -> Self {
        MimiExclusiveAllotmentProof {
            position,
            sibling: sibling.cloned(),
        }
    }
}

pub struct MimiMerkleTree<C: SumCommitment, P: ExclusiveAllotmentProof<C>> {
    leaf_nodes: Vec<C>,
    proof: P,
}

impl<C, P> MimiMerkleTree<C, P>
where
    C: SumCommitment + Clone + PartialEq,
    P: ExclusiveAllotmentProof<C>, Vec<C>: FromIterator<MimiSumCommitment>
{
    pub fn new(values: Vec<u64>) -> Self {
        let leaf_nodes: Vec<C> = values
            .iter()
            .map(|&amount| MimiSumCommitment {
                amount,
                digest: [0; 32],
            })
            .collect();

        // Initialize proof as needed based on your requirements
        let proof = P::generate_proof(0, None);

        MimiMerkleTree {
            leaf_nodes,
            proof,
        }
    }

    pub fn commit(&self) -> C {
        self.compute_root_commitment(0, 0, self.leaf_nodes.len())
    }

    pub fn prove(&self, position: usize) -> P {
        self.generate_proof(position, None)
    }

    fn compute_root_commitment(&self, node_index: usize, start: usize, end: usize) -> C {
        if start == end {
            self.leaf_nodes[node_index].clone()
        } else {
            let midpoint = (start + end) / 2;
            let left_commitment = self.compute_root_commitment(node_index * 2 + 1, start, midpoint);
            let right_commitment = self.compute_root_commitment(node_index * 2 + 2, midpoint, end);
            self.combine_commitments(&left_commitment, &right_commitment)
        }
    }

    fn combine_commitments(&self, left: &C, right: &C) -> C {
        let mut hasher = Sha256::new();
        hasher.update(&left.digest());
        hasher.update(&right.digest());
        let result = hasher.finalize();
    
        C::new(left.amount() + right.amount(), result.into())
    }

    fn generate_proof(&self, position: usize, sibling: Option<C>) -> P {
        P::generate_proof(position, sibling.as_ref())
    }
}

fn compute_merkle_commitment<C: SumCommitment>(position: usize, sibling: &C, root_commitment: &C) -> MimiSumCommitmentWrapper {
    let sibling_digest = hash_bytes(&sibling.digest());
    let root_digest = hash_bytes(&root_commitment.digest());

    let mut hasher = Sha256::new();
    hasher.update(&sibling_digest);
    hasher.update(&root_digest);
    let result = hasher.finalize();

    MimiSumCommitmentWrapper {
        inner: MimiSumCommitment {
            amount: root_commitment.amount(),
            digest: result.into(),
        },
    }
}


fn main() {
    let wrapper = MimiSumCommitmentWrapper::new(42, [0; 32]);
    let merkle_tree = MimiMerkleTree::new(vec![100, 200, 300, 400]);
    let commitment: MimiSumCommitment = merkle_tree.commit();
    let proof: MimiExclusiveAllotmentProof<MimiSumCommitment> = merkle_tree.prove(2);
    println!("Is the proof valid? {}", proof.verify(&commitment));
}
