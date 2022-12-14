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

const path = require('path');
const os = require('os');
const snarkjs = require('snarkjs');
const { writeFileSync } = require('fs');

const { WITNESS_FILE } = require('./generate_witness');

const PUBLIC_JSON_FILE = path.join(os.homedir(), 'iden3_public.json');
const PROOF_JSON_FILE = path.join(os.homedir(), 'iden3_proof.json');

async function prove() {
  const zkeyFile = path.join(__dirname, 'circuit_final.zkey');
  const { proof, publicSignals } = await snarkjs.groth16.prove(zkeyFile, WITNESS_FILE);
  writeFileSync(PROOF_JSON_FILE, JSON.stringify(proof, null, 2));
  console.log(`Generated proof written to file ${PROOF_JSON_FILE}`);
  writeFileSync(PUBLIC_JSON_FILE, JSON.stringify(publicSignals, null, 2));
  console.log(`Generated public signals written to file ${PUBLIC_JSON_FILE}`);
  return { proof, publicSignals };
}

module.exports = {
  prove,
  PUBLIC_JSON_FILE,
  PROOF_JSON_FILE,
};
