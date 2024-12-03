pragma circom 2.1.5;

include "babyjub.circom";
include "poseidon.circom";
include "binary-merkle-root.circom";
include "comparators.circom";

template Semaphore(MAX_DEPTH) {
    signal input secret;
    signal input merkleProofLength, merkleProofIndices[MAX_DEPTH], merkleProofSiblings[MAX_DEPTH];
    signal input message;
    signal input scope;

    signal output merkleRoot, nullifier;

    // Keep BabyJubjub curve parameters
    var l = 2736030358979909402780800718157159386076813972158567259200215660948447373041;

    component isLessThan = LessThan(251);
    isLessThan.in <== [secret, l];
    isLessThan.out === 1;

    // Use existing BabyJubjub implementation
    var Ax, Ay;
    (Ax, Ay) = BabyPbk()(secret);

    var identityCommitment = Poseidon(2)([Ax, Ay]);

    merkleRoot <== BinaryMerkleRoot(MAX_DEPTH)(identityCommitment, merkleProofLength, merkleProofIndices, merkleProofSiblings);

    nullifier <== Poseidon(2)([scope, secret]);

    signal dummySquare <== message * message;
}