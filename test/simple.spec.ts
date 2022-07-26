import chai from "chai";
import * as path from "path";
const mimcMerkle = require("../utils/MiMCMerkle.js");

import { wasm as wasm_tester } from "circom_tester";
import { buildEddsa } from "circomlibjs";
import { buildBabyjub, buildMimc7 } from "circomlibjs";
import { writeFileSync } from "fs";

const assert = chai.assert;
let F;
let mimc7;

const computeMerkleTree = (F, weights: number[], pks: [any, any][]) => {
  const leafArray = weights.map((w, i) =>
    mimc7.multiHash([w, F.toObject(pks[i][0]), F.toObject(pks[i][1])])
  );
  console.log("AAAA", leafArray);
  const tree = mimcMerkle.treeFromLeafArray(mimc7, F, leafArray);
  return { tree, leafArray };
};

const generateCircuit = async (
  nParties,
  treeDepth,
  merkleRoot,
  messageHash,
  threshold
) => {
  writeFileSync(
    path.join(__dirname, "tmp", "test_circuit.circom"),
    `pragma circom 2.0.0;
include "../../circuits/wtsig.circom";
component main = VerifyWtSig(${nParties}, ${treeDepth}, ${merkleRoot}, ${messageHash}, ${threshold});`
  );
  const circuit = await wasm_tester(
    path.join(__dirname, "tmp", "test_circuit.circom")
  );
  return circuit;
};

describe("EdDSA MiMC test", function () {
  let circuit;
  let eddsa;
  let babyJub;

  this.timeout(100000);

  before(async () => {
    babyJub = await buildBabyjub();
    mimc7 = await buildMimc7();
    eddsa = await buildEddsa();
    F = babyJub.F;
  });

  it("Sign a couple of parties number", async () => {
    const weights = [10, 20, 30, 40];
    const thresh = [100];
    const msg = F.e(1234);

    // TODO: randomly generate keys
    const prvKey = Buffer.from(
      "0001020304050607080900010203040506070809000102030405060708090001",
      "hex"
    );

    const prvKeys = weights.map((_) => Buffer.from(prvKey));
    const pubKeys = prvKeys.map((p) => eddsa.prv2pub(p));

    // const pubKey = eddsa.prv2pub(prvKey);

    const signatures = prvKeys.map((p) => eddsa.signMiMC(p, msg));

    signatures.forEach((sig, i) => {
      assert(eddsa.verifyMiMC(msg, sig, pubKeys[i]));
    });
    console.log("bbbb");
    const { tree, leafArray } = computeMerkleTree(F, weights, pubKeys);
    const root = tree[0][0];
    const proofs = pubKeys.map((_, i) =>
      mimcMerkle.getProof(F, i, tree, leafArray)
    );
    // for index i, 1 signals that a proof hash is on the right, a 0 specifies left for the ith level counted from
    // the BOTTOM of the tree
    const pathPositions = [
      [1, 1],
      [0, 1],
      [1, 0],
      [0, 0],
    ].map((p) => [F.toObject(p[0]), F.toObject(p[1])]);
    console.log("AAA", mimcMerkle.idxToBinaryPos(0));

    circuit = await generateCircuit(
      weights.length,
      2,
      F.toObject(root),
      F.toObject(msg),
      100
    );
    const w = await circuit.calculateWitness(
      {
        // enabled: 1,
        from_x: pubKeys.map((pk) => F.toObject(pk[0])),
        from_y: pubKeys.map((pk) => F.toObject(pk[1])),
        R8x: signatures.map((s) => F.toObject(s.R8[0])),
        R8y: signatures.map((s) => F.toObject(s.R8[1])),
        S: signatures.map((s) => s.S),
        weights: weights,
        // merkle_root: F.toObject(root),
        leafs: leafArray.map((leaf) => F.toObject(leaf)),
        path_proofs: proofs,
        path_positions: pathPositions,
      },
      true
    );

    const tVerifStart = Date.now();
    await circuit.checkConstraints(w);
    console.log(`Verification times occurred ${Date.now() - tVerifStart} ms`);
  });

  it("Detect Invalid signature", async () => {
    // TODO:
  });
});
