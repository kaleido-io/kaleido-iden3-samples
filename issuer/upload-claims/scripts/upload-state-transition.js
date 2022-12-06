const prompt = require('prompt-sync')();
const { utils } = require('ffjavascript');
const { unstringifyBigInts } = utils;
const hre = require('hardhat');
const ethers = hre.ethers;
const os = require('os');
const fs = require('fs');
const path = require('path');

const pathOutputJson = path.join(os.homedir(), './iden3_deploy_output.json');
const zkinputJson = path.join(os.homedir(), './iden3_input.json');

const { generateWitness } = require('./snark/generate_witness');
const { prove } = require('./snark/prove');
const { verify } = require('./snark/verify');

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

  // gather the inputs for generating the proof
  const content = JSON.parse(fs.readFileSync(zkinputJson));

  const issuerId = content.userID;
  const oldState = content.oldUserState;
  const newState = content.newUserState;
  const isOldStateGenesis = content.isOldStateGenesis;

  await generateWitness(content);
  const { proof, publicSignals } = await prove();
  await verify(proof, publicSignals);

  const result = await groth16ExportSolidityCallData(proof, publicSignals);
  const a = result[0];
  const b = result[1];
  const c = result[2];

  let identityState0 = await contract.getState(issuerId);
  console.log('State before transaction: ', identityState0);

  const tx = await contract.transitState(issuerId, oldState, newState, isOldStateGenesis, a, b, c);
  await tx.wait();
  let identityState1 = await contract.getState(issuerId);
  console.log('State after transaction: ', identityState1);
}

// copied from snarkjs.groth16.exportSolidityCallData()
async function groth16ExportSolidityCallData(_proof, _pub) {
  const proof = unstringifyBigInts(_proof);
  const pub = unstringifyBigInts(_pub);

  let inputs = '';
  for (let i = 0; i < pub.length; i++) {
    if (inputs != '') inputs = inputs + ',';
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
  while (nstr.length < 64) nstr = '0' + nstr;
  nstr = `0x${nstr}`;
  return nstr;
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
