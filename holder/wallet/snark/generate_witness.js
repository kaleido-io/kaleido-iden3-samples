const WitnessCalc = require('./witness_calculator.js');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { readFileSync, writeFileSync } = require('fs');

const identityName = process.env.IDEN3_NAME;
const random = crypto.randomBytes(10).toString('hex');
const WITNESS_FILE = path.join(os.homedir(), 'iden3', identityName, `witness-${random}.wtns`);

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
