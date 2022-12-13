const WitnessCalc = require('./witness_calculator.js');
const os = require('os');
const path = require('path');
const { readFileSync, writeFileSync } = require('fs');

const WITNESS_FILE = path.join(os.homedir(), 'iden3_witness_holder.wtns');

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
