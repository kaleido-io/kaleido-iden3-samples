// Copyright © 2022 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

const { utils } = require("ffjavascript");
const { unstringifyBigInts } = utils;
const hre = require("hardhat");
const ethers = hre.ethers;
const os = require("os");
const fs = require("fs");
const path = require("path");

const identityName = process.env.IDEN3_NAME;
const workDir = process.env.IDEN3_WORKDIR || path.join(os.homedir(), "iden3");
const pathOutputJson = path.join(workDir, `deploy_output.json`);
const genesisJson = path.join(
  workDir,
  `${identityName}/private/states/genesis_state.json`
);
const zkinputJson = path.join(
  workDir,
  `${identityName}/private/states/stateTransition_inputs.json`
);

// The following files are for record purpose to assist diagnose
const zkpreviousJson = path.join(
  workDir,
  `${identityName}/private/states/stateTransition_inputs_previous.json`
);
const treeStatesJson = path.join(
  workDir,
  `${identityName}/private/states/treeStates.json`
);
const treeStatesPreviousJson = path.join(
  workDir,
  `${identityName}/private/states/treeStates_previous.json`
);
const archiveFolder = path.join(
  workDir,
  `${identityName}/private/states/archived_transitions`
);
const { generateWitness } = require("./snark/generate_witness");
const { prove } = require("./snark/prove");
const { verify } = require("./snark/verify");

function archiveOldFiles() {
  const timestampString = Date.now().toString();
  if (!fs.existsSync(archiveFolder)) {
    fs.mkdirSync(archiveFolder);
  }
  if (fs.existsSync(zkpreviousJson)) {
    fs.renameSync(
      zkpreviousJson,
      path.join(
        archiveFolder,
        `${timestampString}-stateTransition_inputs_previous.json`
      )
    );
  }
  if (fs.existsSync(treeStatesPreviousJson)) {
    fs.renameSync(
      treeStatesPreviousJson,
      path.join(archiveFolder, `${timestampString}-treeStates_previous.json`)
    );
  }
}

async function main() {
  if (!fs.existsSync(zkinputJson)) {
    throw new Error(
      `No state transition input file found for ${identityName} at: ${zkinputJson}`
    );
  }
  archiveOldFiles();
  let stateContractAddress;
  if (hre.network.name === "mumbai") {
    stateContractAddress = "0x46Fd04eEa588a3EA7e9F055dd691C688c4148ab3";
  } else if (hre.network.name === "kaleido") {
    let content = fs.readFileSync(pathOutputJson);
    if (!content) {
      throw new Error("Must run the deploy script first");
    }
    const { state } = JSON.parse(content);
    stateContractAddress = state;
  }

  const contract = await ethers.getContractAt("State", stateContractAddress);

  // gather the inputs for generating the proof
  if (!fs.existsSync(zkinputJson)) {
    console.log(
      `State transition skipped as new state detected - no state input file found at: ${zkinputJson}`
    );
    process.exit(0);
  }
  let genesisInfo = JSON.parse(fs.readFileSync(genesisJson));
  let identityInfo = {
    userID: genesisInfo.userID,
  };
  const issuerId = genesisInfo.userID;
  const stateTransitionInputs = JSON.parse(fs.readFileSync(zkinputJson));

  const oldState = stateTransitionInputs.oldUserState;
  const newState = stateTransitionInputs.newUserState;
  const isOldStateGenesis = stateTransitionInputs.isOldStateGenesis;

  let existingState = await contract.getState(issuerId);
  let existingStateString = existingState.toString();
  console.log("State before transaction: ", existingStateString);
  if (existingStateString !== oldState) {
    if (existingStateString === newState) {
      console.log(
        "State on chain is already the latest, rename the local state input files to a previous state file"
      );
      fs.renameSync(zkinputJson, zkpreviousJson);
      fs.renameSync(treeStatesJson, treeStatesPreviousJson);
      process.exit(0);
    } else {
      if (isOldStateGenesis && existingStateString === "0") {
        // genesis state, continue
      } else {
        console.log(
          `The recorded identity state: ${existingStateString} does not equal to the old identity state: ${oldState} in file ${zkinputJson}.`
        );
        process.exit(1);
      }
    }
  } else {
    if (existingStateString === newState) {
      console.log("No state change detected, ignoring this operation...");
      process.exit(0);
    }
  }

  let inputs = {
    ...identityInfo,
    ...stateTransitionInputs,
  };
  console.log(inputs);

  await generateWitness(inputs);
  const { proof, publicSignals } = await prove();
  await verify(proof, publicSignals);

  const result = await groth16ExportSolidityCallData(proof, publicSignals);
  const a = result[0];
  const b = result[1];
  const c = result[2];
  console.log("Invoking state transaction on chain ...");
  const tx = await contract.transitState(
    issuerId,
    oldState,
    newState,
    isOldStateGenesis === "1",
    a,
    b,
    c
  );
  await tx.wait();
  let updatedState = await contract.getState(issuerId);
  console.log("State after transaction: ", updatedState.toString());
  // clean up the used inputs
  fs.renameSync(zkinputJson, zkpreviousJson);
  fs.renameSync(treeStatesJson, treeStatesPreviousJson);
}

// modified from snarkjs.groth16.exportSolidityCallData()
async function groth16ExportSolidityCallData(_proof, _pub) {
  const proof = unstringifyBigInts(_proof);
  const pub = unstringifyBigInts(_pub);

  let inputs = "";
  for (let i = 0; i < pub.length; i++) {
    if (inputs != "") inputs = inputs + ",";
    inputs = inputs + p256(pub[i]);
  }

  let S = [];
  S.push([p256(proof.pi_a[0]), p256(proof.pi_a[1])]);
  S.push([
    [p256(proof.pi_b[0][1]), p256(proof.pi_b[0][0])],
    [p256(proof.pi_b[1][1]), p256(proof.pi_b[1][0])],
  ]);
  S.push([p256(proof.pi_c[0]), p256(proof.pi_c[1])]);

  return S;
}

function p256(n) {
  let nstr = n.toString(16);
  while (nstr.length < 64) nstr = "0" + nstr;
  nstr = `0x${nstr}`;
  return nstr;
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
