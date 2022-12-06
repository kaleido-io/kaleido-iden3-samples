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
