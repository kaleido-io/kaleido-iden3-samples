const fs = require("fs");
const os = require("os");
const path = require("path");
const Jimp = require("jimp");
const jsQR = require("jsqr");
const { v4: uuidv4 } = require("uuid");
const { protocol } = require("@iden3/js-iden3-auth");

// HACK: Needed to obtain the Id class since it and other `core` package members are not exported from js-iden3-auth,
// and js-iden3-core is not considered released yet.
// See https://github.com/iden3/js-iden3-auth/issues/37#issuecomment-1402491741
const { Id } = require("@iden3/js-iden3-auth/dist/cjs/core/id");
// Patch to use the expected factory method names from js-iden3-core's Id class.
Id.fromBigInt ||= Id.idFromInt;
Id.fromString ||= Id.idFromString;

const { AUTHORIZATION_RESPONSE_MESSAGE_TYPE } = protocol;
const axios = require("axios");
const yargs = require("yargs/yargs");
const { hideBin } = require("yargs/helpers");
const argv = yargs(hideBin(process.argv)).argv;

const crypto = require("crypto");
const random = crypto.randomBytes(10).toString("hex");
const { generateWitness } = require("./snark/generate_witness");
const { prove } = require("./snark/prove");
const { verify } = require("./snark/verify");

const holderName = argv["holder"];
const qrFile = argv["qrcode"];

const workDir = process.env.IDEN3_WORKDIR || path.join(os.homedir(), "iden3");

const HOLDER_GENESIS_STATE_FILE = path.join(
  workDir,
  `${holderName}/private/states/genesis_state.json`
);
const HOLDER_CHALLENGE_FILE = path.join(
  workDir,
  `${holderName}/challenge.json`
);

const CLAIM_FILE_PATTERN = /^genericClaim.*-via-signature.json$/;

const NOOP = "0"; // = - no operation, skip query verification if set
const EQUALS = "1"; // = - equals sign
const LESS = "2"; // = - less-than sign
const GREATER = "3"; // = - greter-than sign
const IN = "4"; // = - in
const NOTIN = "5"; // = - notin

function checkArgs() {
  if (!holderName) {
    throw new Error("Must provide the name of the holder with --holder");
  }
  if (!qrFile) {
    throw new Error("Must provide the file path of the QR image with --qrcode");
  }
}

async function getHolderInputs() {
  // these inputs prove the auth claim of the holder is still valid
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
  const claimsDir = path.join(workDir, `${holderName}/private/received-claims`);
  const claimFiles = fs
    .readdirSync(claimsDir)
    .filter((file) => file.match(CLAIM_FILE_PATTERN));
  if (claimFiles.length === 0) {
    throw Error(`There are no received claims in ${claimsDir}`);
  }
  if (claimFiles.length > 1) {
    throw Error(
      `There are multiple received claims in ${claimsDir}. Currently only a single one is supported.`
    );
  }
  const content = fs.readFileSync(path.join(claimsDir, claimFiles[0]));
  const inputs = JSON.parse(content);
  return {
    // id of the issuer
    issuerID: inputs.issuerAuthState.userID,

    // proof of the issuer auth claim is still valid
    // the circuit will check the signature of the claim
    // is generated using the bjj private key linked to this auth claim
    issuerAuthClaim: inputs.issuerAuthState.authClaim,

    // proof of the auth claim is included in the claim tree of issuer
    issuerAuthClaimMtp: inputs.issuerAuthState.authClaimMtp,

    // proof of the auth claim is not revoked
    issuerAuthClaimNonRevMtp: inputs.issuerAuthState.authClaimNonRevMtp,
    issuerAuthClaimNonRevMtpAuxHi:
      inputs.issuerAuthState.authClaimNonRevMtpAuxHi,
    issuerAuthClaimNonRevMtpAuxHv:
      inputs.issuerAuthState.authClaimNonRevMtpAuxHv,
    issuerAuthClaimNonRevMtpNoAux:
      inputs.issuerAuthState.authClaimNonRevMtpNoAux,

    // tree roots for validating auth claims
    issuerAuthClaimsTreeRoot: inputs.issuerAuthState.claimsTreeRoot,
    issuerAuthRevTreeRoot: inputs.issuerAuthState.revTreeRoot,
    issuerAuthRootsTreeRoot: inputs.issuerAuthState.rootsTreeRoot,

    // proof of the claim is still valid from issuer
    issuerClaim: inputs.issuerClaim,

    // NOTE: because the claim was issued via Signature, there is no need to prove the generic claim is in the claim tree of issuer

    // Identity state of the issuer when the proof of the generic claim is generated
    issuerClaimNonRevState: inputs.issuerState_State,

    // proof of the generic claim is not revoked
    issuerClaimNonRevMtp: inputs.issuerClaimNonRevMtp,
    issuerClaimNonRevMtpAuxHi: inputs.issuerClaimNonRevMtpAuxHi,
    issuerClaimNonRevMtpAuxHv: inputs.issuerClaimNonRevMtpAuxHv,
    issuerClaimNonRevMtpNoAux: inputs.issuerClaimNonRevMtpNoAux,

    // tree roots for validating the generic claims
    issuerClaimNonRevClaimsTreeRoot: inputs.issuerState_ClaimsTreeRoot,
    issuerClaimNonRevRevTreeRoot: inputs.issuerState_RevTreeRoot,
    issuerClaimNonRevRootsTreeRoot: inputs.issuerState_RootsTreeRoot,

    // schema of the claim
    claimSchema: inputs.claimSchema,

    // signature of the claim
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
  const result = jsQR(
    new Uint8ClampedArray(image.bitmap.data),
    image.bitmap.width,
    image.bitmap.height
  );
  if (!result) {
    throw new Error("Failed to parse qr_code");
  }
  return JSON.parse(result.data);
}

async function generateProof(challenge) {
  const WITNESS_FILE = path.join(
    workDir,
    holderName,
    `private/witness-${random}.wtns`
  );

  const holderInputs = await getHolderInputs();
  const claimInputs = await getClaimInputs();
  const challengeInputs = await getChallengeInputs();

  const queryRequest = challenge.body.scope[0].rules.query.req;
  const queryProperty = Object.keys(queryRequest)[0];
  if (queryProperty != "birthDay") {
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
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
    ],
    timestamp: Math.floor(Date.now() / 1000),
  };
  console.log(inputs);
  await generateWitness(inputs, WITNESS_FILE);
  const { proof, publicSignals } = await prove(WITNESS_FILE);
  await verify(proof, publicSignals);
  await sendCallback(challenge, proof, publicSignals, holderInputs.userID);
}

async function sendCallback(challengeRequest, proof, publicSignals, holderId) {
  console.log("holderId:", holderId);
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
  console.log("Sending callback to the verifier server: ", url);
  try {
    const result = await axios({
      method: "post",
      url,
      data: challengeResponse,
    });
    console.log(
      `Success response from the verifier server: ${JSON.stringify({
        status: result.status,
        message: result.data,
      })}`
    );
  } catch (error) {
    if (error.response) {
      // The request was made and the server responded with a status code
      // that falls out of the range of 2xx
      console.log("error data", error.response.data);
      console.log("error status", error.response.status);
      console.log("error headers", error.response.headers);
    } else if (error.request) {
      // The request was made but no response was received
      // `error.request` is an instance of XMLHttpRequest in the browser and an instance of
      // http.ClientRequest in node.js
      console.log(error.request);
    }
    console.log(
      `Callback to ${url} failed: ${error.message}. Please check the verifier server logs for more details.`
    );
    throw error;
  }
}

function translateOperator(op) {
  switch (op) {
    case "$eq":
      return EQUALS;
    case "$lt":
      return LESS;
    case "$gt":
      return GREATER;
    case "$in":
      return IN;
    case "$nin":
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
      console.log("Done!");
      process.exit(0);
    })
    .catch((err) => {
      console.error("Error:", err.message);
      process.exit(1);
    });
} catch (err) {
  console.error(err);
}
