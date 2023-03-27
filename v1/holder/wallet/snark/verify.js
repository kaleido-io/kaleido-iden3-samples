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

const snarkjs = require('snarkjs');
const path = require('path');
const { readFileSync } = require('fs');

async function verify(proof, publicSignals) {
  const verifier = JSON.parse(readFileSync(path.join(__dirname, 'verification_key.json')));
  const result = await snarkjs.groth16.verify(verifier, publicSignals, proof);
  if (result) {
    console.log('Successfully generated proof!');
  }
}

module.exports = {
  verify,
};
