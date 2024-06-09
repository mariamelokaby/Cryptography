# Rust Merkle Tree with Commitment and Proof

## Project Overview

This project implements a Merkle Tree with custom commitment and proof mechanisms in Rust. The goal is to provide a robust structure for managing commitments and generating proofs, essential for applications requiring data integrity and proof of inclusion, such as blockchain and cryptographic protocols.

## Key Features

- **SumCommitment Trait**:
  - Defines an interface for creating and combining commitments.
  - Methods to retrieve the amount and digest of a commitment.

- **ExclusiveAllotmentProof Trait**:
  - Provides an interface for generating and verifying exclusive allotment proofs.
  - Methods for creating new proofs, verifying them, and reconstructing commitments.

- **MerkleProof Struct**:
  - Represents a proof for a Merkle tree, containing an optional sibling node and its position.

- **MimiSumCommitment Struct**:
  - Implements the `SumCommitment` trait with SHA-256 hashing for creating and combining commitments.

- **MimkMerkleTree Struct**:
  - Defines a Merkle tree structure.
  - Methods to create commitments from a list of values, construct inclusion proofs, and verify them.


## Technologies Used

- **Programming Language**: Rust
- **Cryptographic Hashing**: SHA-256 from the `sha2` crate
- **Data Structures**: GenericArray for fixed-size arrays
  
## Developer:
-Mariam Khaled
  
