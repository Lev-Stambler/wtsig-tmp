pragma circom 2.0.0;

include "../circomlib/circuits/eddsamimc.circom";
include "../circomlib/circuits/mimc.circom";
include "../circomlib/circuits/comparators.circom";
include "./merkle_challenge.circom";

// n_parties is the number of parties
// mess_size is the message size
template VerifyWtSig(n_parties, tree_depth, merkle_root, M, threshold) {
    signal input from_x[n_parties];
    signal input from_y[n_parties];
    signal input R8x[n_parties];
    signal input R8y[n_parties];
    signal input S[n_parties];
		
		// Weight proofs
		signal input leafs[n_parties];
		signal input path_proofs[n_parties][tree_depth];
		signal input path_positions[n_parties][tree_depth];

		signal input weights[n_parties];
    
    component verifier[n_parties];   
		component merkle_challenge[n_parties];
		// Verify the inputed signatures
		var total_weight = 0;
		for (var p = 0; p < n_parties; p++) {
			//  Verify Signatures
 			verifier[p] = EdDSAMiMCVerifier();
    	verifier[p].enabled <== 1;
    	verifier[p].Ax <== from_x[p];
    	verifier[p].Ay <== from_y[p];
    	verifier[p].R8x <== R8x[p];
    	verifier[p].R8y <== R8y[p];
    	verifier[p].S <== S[p];
    	verifier[p].M <== M;
			total_weight += weights[p];
			

			// Verify Merkle Data such that the weight party data is correct
			merkle_challenge[p] = LeafExistence(tree_depth, 3);
			merkle_challenge[p].preimage[0] <== weights[p];
			merkle_challenge[p].preimage[1] <== from_x[p];
			merkle_challenge[p].preimage[2] <== from_y[p];
			merkle_challenge[p].root <== merkle_root;
			for (var i = 0; i < tree_depth; i++) {
				merkle_challenge[p].paths2_root[i] <== path_proofs[p][i];
				merkle_challenge[p].paths2_root_pos[i] <== path_positions[p][i];
			}
		}
		component geq = GreaterEqThan(16); // 16 bits should be enough??
		geq.in[0] <== total_weight;
		geq.in[1] <== threshold;

		geq.out === 1;
}