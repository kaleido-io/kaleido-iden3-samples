const fs = require('fs');
const os = require('os');
const path = require('path');
const Jimp = require('jimp');
const jsQR = require('jsqr');
const { v4: uuidv4 } = require('uuid');
const { protocol } = require('@iden3/js-iden3-auth');
const { Id } = require('@iden3/js-iden3-core');
const { AUTHORIZATION_RESPONSE_MESSAGE_TYPE } = protocol;
const axios = require('axios');
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const argv = yargs(hideBin(process.argv)).argv;

const { generateWitness } = require('./snark/generate_witness');
const { prove } = require('./snark/prove');
const { verify } = require('./snark/verify');

const holderName = argv['holder'];
const qrFile = argv['qrcode'];

const HOLDER_GENESIS_STATE_FILE = path.join(os.homedir(), `iden3/${holderName}/genesis_state.json`);
const HOLDER_CHALLENGE_FILE = path.join(os.homedir(), `iden3/${holderName}/challenge.json`);

const NOOP = '0'; // = - no operation, skip query verification if set
const EQUALS = '1'; // = - equals sign
const LESS = '2'; // = - less-than sign
const GREATER = '3'; // = - greter-than sign
const IN = '4'; // = - in
const NOTIN = '5'; // = - notin

function checkArgs() {
  if (!holderName) {
    throw new Error('Must provide the name of the holder with --holder');
  }
  if (!qrFile) {
    throw new Error('Must provide the file path of the QR image with --qrcode');
  }
}

async function getHolderInputs() {
  const content = fs.readFileSync(HOLDER_GENESIS_STATE_FILE);
  const inputs = JSON.parse(content);

  return {
    userAuthClaim: inputs.authClaim,
    userAuthClaimMtp: inputs.authClaimMtp,
    userAuthClaimNonRevMtp: inputs.authClaimNonRevMtp,
    userAuthClaimNonRevMtpAuxHi: inputs.authClaimNonRevMtpAuxHi,
    userAuthClaimNonRevMtpAuxHv: inputs.authClaimNonRevMtpAuxHv,
    userAuthClaimNonRevMtpNoAux: inputs.authClaimNonRevMtpNoAux,
    userID: inputs.userID,
    userState: inputs.newUserState,
    userClaimsTreeRoot: inputs.claimsTreeRoot,
    userRevTreeRoot: inputs.revTreeRoot,
    userRootsTreeRoot: inputs.rootsTreeRoot,
  };
}

async function getClaimInputs() {
  const claimsDir = path.join(os.homedir(), `iden3/${holderName}/received-claims`);
  const claimFiles = fs.readdirSync(claimsDir);
  const content = fs.readFileSync(path.join(claimsDir, claimFiles[0]));
  const inputs = JSON.parse(content);
  return {
    issuerID: inputs.issuerAuthState.userID,
    issuerAuthClaim: inputs.issuerAuthState.authClaim,
    issuerAuthClaimMtp: inputs.issuerAuthState.authClaimMtp,
    issuerAuthClaimNonRevMtp: inputs.issuerAuthState.authClaimNonRevMtp,
    issuerAuthClaimNonRevMtpAuxHi: inputs.issuerAuthState.authClaimNonRevMtpAuxHi,
    issuerAuthClaimNonRevMtpAuxHv: inputs.issuerAuthState.authClaimNonRevMtpAuxHv,
    issuerAuthClaimNonRevMtpNoAux: inputs.issuerAuthState.authClaimNonRevMtpNoAux,
    issuerAuthClaimsTreeRoot: inputs.issuerAuthState.claimsTreeRoot,
    issuerAuthRevTreeRoot: inputs.issuerAuthState.revTreeRoot,
    issuerAuthRootsTreeRoot: inputs.issuerAuthState.rootsTreeRoot,
    issuerClaim: inputs.issuerClaim,
    issuerClaimNonRevClaimsTreeRoot: inputs.issuerState_ClaimsTreeRoot,
    issuerClaimNonRevRevTreeRoot: inputs.issuerState_RevTreeRoot,
    issuerClaimNonRevRootsTreeRoot: inputs.issuerState_RootsTreeRoot,
    issuerClaimNonRevState: inputs.issuerState_State,
    issuerClaimNonRevMtp: inputs.issuerClaimNonRevMtp,
    issuerClaimNonRevMtpAuxHi: inputs.issuerClaimNonRevMtpAuxHi,
    issuerClaimNonRevMtpAuxHv: inputs.issuerClaimNonRevMtpAuxHv,
    issuerClaimNonRevMtpNoAux: inputs.issuerClaimNonRevMtpNoAux,
    claimSchema: inputs.claimSchema,
    issuerClaimSignatureR8x: inputs.issuerClaimSignatureR8x,
    issuerClaimSignatureR8y: inputs.issuerClaimSignatureR8y,
    issuerClaimSignatureS: inputs.issuerClaimSignatureS,
  };
}

async function getChallengeInputs() {
  const content = fs.readFileSync(HOLDER_CHALLENGE_FILE);
  const inputs = JSON.parse(content);
  return {
    challenge: inputs.challenge,
    challengeSignatureR8x: inputs.challengeSignatureR8x,
    challengeSignatureR8y: inputs.challengeSignatureR8y,
    challengeSignatureS: inputs.challengeSignatureS,
  };
}

async function scanQR() {
  var buffer = fs.readFileSync(qrFile);
  const image = await Jimp.read(buffer);
  const result = jsQR(new Uint8ClampedArray(image.bitmap.data), image.bitmap.width, image.bitmap.height);
  if (!result) {
    throw new Error('Failed to parse qr_code');
  }
  return JSON.parse(result.data);
}

async function generateProof(challenge) {
  const holderInputs = await getHolderInputs();
  const claimInputs = await getClaimInputs();
  const challengeInputs = await getChallengeInputs();

  const queryRequest = challenge.body.scope[0].rules.query.req;
  const queryProperty = Object.keys(queryRequest)[0];
  if (queryProperty != 'birthDay') {
    const msg = `As of now only the 'birthDay' property is supported in the challenge query. Had ${queryProperty}`;
    throw new Error(msg);
  }
  const queryExp = queryRequest[queryProperty];
  const exp = Object.entries(queryExp)[0];

  const inputs = {
    ...holderInputs,
    ...claimInputs,
    ...challengeInputs,
    slotIndex: 2, // index of slot A is where we store the claim's birthday (eg. "20000704")
    operator: translateOperator(exp[0]), // the "EQUAL" operator
    value: [
      exp[1],
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
    ],
    timestamp: Math.floor(Date.now() / 1000),
  };
  console.log(inputs);
  await generateWitness(inputs);
  const { proof, publicSignals } = await prove();
  await verify(proof, publicSignals);
  await sendCallback(challenge, proof, publicSignals, holderInputs.userID);
}

async function sendCallback(challengeRequest, proof, publicSignals, holderId) {
  const zkresponse = {
    id: challengeRequest.body.scope[0].id,
    circuit_id: challengeRequest.body.scope[0].circuit_id,
    proof,
    pub_signals: publicSignals,
  };
  const challengeResponse = {
    id: uuidv4(),
    thid: challengeRequest.thid,
    typ: challengeRequest.typ,
    type: AUTHORIZATION_RESPONSE_MESSAGE_TYPE,
    from: Id.fromBigInt(BigInt(holderId)).string(),
    to: challengeRequest.from,
    body: {
      message: challengeRequest.body.message,
      scope: [zkresponse],
    },
  };

  const url = challengeRequest.body.callbackUrl;
  console.log('Sending callback to', url);
  try {
    const result = await axios({
      method: 'post',
      url,
      data: challengeResponse,
    });
  } catch (error) {
    if (error.response) {
      // The request was made and the server responded with a status code
      // that falls out of the range of 2xx
      console.log('error data', error.response.data);
      console.log('error status', error.response.status);
      console.log('error headers', error.response.headers);
    } else if (error.request) {
      // The request was made but no response was received
      // `error.request` is an instance of XMLHttpRequest in the browser and an instance of
      // http.ClientRequest in node.js
      console.log(error.request);
    } else {
      // Something happened in setting up the request that triggered an Error
      console.log('Error', error.message);
    }
  }
}

function translateOperator(op) {
  switch (op) {
    case '$eq':
      return EQUALS;
    case '$lt':
      return LESS;
    case '$gt':
      return GREATER;
    case '$in':
      return IN;
    case '$nin':
      return NOTIN;
    default:
      return NOOP;
  }
}

try {
  checkArgs();
  scanQR()
    .then((result) => {
      return generateProof(result);
    })
    .then(() => {
      console.log('Done!');
      process.exit(0);
    })
    .catch((err) => {
      console.error(err);
    });
} catch (err) {
  console.error(err);
}
