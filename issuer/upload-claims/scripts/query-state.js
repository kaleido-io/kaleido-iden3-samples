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

const { utils } = require('ffjavascript');
const hre = require('hardhat');
const ethers = hre.ethers;
const os = require('os');
const fs = require('fs');
const path = require('path');

const identityName = process.env.IDEN3_NAME;
const pathOutputJson = path.join(os.homedir(), `iden3/deploy_output.json`);
const genesisJson = path.join(os.homedir(), `iden3/${identityName}/genesis_state.json`);

async function main() {
  let stateContractAddress;
  if (hre.network.name === 'mumbai') {
    stateContractAddress = '0x46Fd04eEa588a3EA7e9F055dd691C688c4148ab3';
  } else if (hre.network.name === 'kaleido') {
    let content = fs.readFileSync(pathOutputJson);
    if (!content) {
      throw new Error('Must run the deploy script first');
    }
    const { state } = JSON.parse(content);
    stateContractAddress = state;
  }

  const contract = await ethers.getContractAt('State', stateContractAddress);

  let genesisInfo = JSON.parse(fs.readFileSync(genesisJson));
  const issuerId = genesisInfo.userID;
  console.log('Issuer id', issuerId);

  let state = await contract.getState(issuerId);
  console.log('Issuer state', state);

  let transitionInfo = await contract.getTransitionInfo(state);
  console.log('Transition info', transitionInfo);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
