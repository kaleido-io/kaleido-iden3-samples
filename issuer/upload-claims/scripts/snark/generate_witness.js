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

// modified from https://github.com/iden3/tutorial-examples/blob/main/compiled-circuits/stateTransition/stateTransition_js/generate_witness.js
const WitnessCalc = require('./witness_calculator.js');
const os = require('os');
const path = require('path');
const { readFileSync, writeFileSync } = require('fs');

const WITNESS_FILE = path.join(os.homedir(), 'iden3_witness.wtns');

async function generateWitness(input) {
  const circuit = readFileSync(path.join(__dirname, 'circuit.wasm'));
  const wc = await WitnessCalc(circuit);
  const buff = await wc.calculateWTNSBin(input, 0);
  await writeFileSync(WITNESS_FILE, buff);
  console.log(`Calculated witness successfully written to file ${WITNESS_FILE}`);
}

module.exports = {
  generateWitness,
  WITNESS_FILE,
};
