const fs = require('fs');
const os = require('os');
const path = require('path');

const { generateWitness } = require('./snark/generate_witness');

const ISSUER_INPUT_FILE = path.join(os.homedir(), 'iden3_input_issuer.json');
const HOLDER_INPUT_FILE = path.join(os.homedir(), 'iden3_input_holder.json');
const HOLDER_CLAIM_INPUT_FILE = path.join(os.homedir(), 'iden3_input_issuer_to_user.json');
const HOLDER_CHALLENGE_INPUT_FILE = path.join(os.homedir(), 'iden3_input_holder_challenge.json');

async function getIssuerInputs() {
  const content = fs.readFileSync(ISSUER_INPUT_FILE);
  const inputs = JSON.parse(content);

  return {
    issuerID: inputs.userID,
    issuerClaimSignatureR8x: inputs.signatureR8x,
    issuerClaimSignatureR8y: inputs.signatureR8y,
    issuerClaimSignatureS: inputs.signatureS,
    issuerAuthClaim: inputs.authClaim,
    issuerAuthClaimMtp: inputs.authClaimMtp,
    issuerAuthClaimNonRevMtp: inputs.authClaimNonRevMtp,
    issuerAuthClaimNonRevMtpAuxHi: inputs.authClaimNonRevMtpAuxHi,
    issuerAuthClaimNonRevMtpAuxHv: inputs.authClaimNonRevMtpAuxHv,
    issuerAuthClaimNonRevMtpNoAux: inputs.authClaimNonRevMtpNoAux,
    issuerAuthClaimsTreeRoot: inputs.claimsTreeRoot,
    issuerAuthRevTreeRoot: inputs.revTreeRoot,
    issuerAuthRootsTreeRoot: inputs.rootsTreeRoot,
  };
}

async function getHolderInputs() {
  const content = fs.readFileSync(HOLDER_INPUT_FILE);
  const inputs = JSON.parse(content);

  return {
    userAuthClaim: inputs.authClaim,
    userAuthClaimMtp: inputs.authClaimMtp,
    userAuthClaimNonRevMtp: inputs.authClaimNonRevMtp,
    userAuthClaimNonRevMtpAuxHi: inputs.authClaimNonRevMtpAuxHi,
    userAuthClaimNonRevMtpAuxHv: inputs.authClaimNonRevMtpAuxHv,
    userAuthClaimNonRevMtpNoAux: inputs.authClaimNonRevMtpNoAux,
    userID: inputs.userID,
  };
}

async function getClaimInputs() {
  const content = fs.readFileSync(HOLDER_CLAIM_INPUT_FILE);
  const inputs = JSON.parse(content);
  return {
    issuerClaim: inputs.issuerClaim,
    issuerClaimNonRevClaimsTreeRoot: inputs.issuerClaimNonRevClaimsTreeRoot,
    issuerClaimNonRevRevTreeRoot: inputs.issuerClaimNonRevRevTreeRoot,
    issuerClaimNonRevRootsTreeRoot: inputs.issuerClaimNonRevRootsTreeRoot,
    issuerClaimNonRevState: inputs.issuerClaimNonRevState,
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
  const content = fs.readFileSync(HOLDER_CHALLENGE_INPUT_FILE);
  const inputs = JSON.parse(content);
  return {
    userState: inputs.newUserState,
    userClaimsTreeRoot: inputs.claimsTreeRoot,
    userRevTreeRoot: inputs.revTreeRoot,
    userRootsTreeRoot: inputs.rootsTreeRoot,
    challenge: inputs.challenge,
    challengeSignatureR8x: inputs.challengeSignatureR8x,
    challengeSignatureR8y: inputs.challengeSignatureR8y,
    challengeSignatureS: inputs.challengeSignatureS,
  };
}

async function prove() {
  const issuerInputs = await getIssuerInputs();
  const holderInputs = await getHolderInputs();
  const claimInputs = await getClaimInputs();
  const challengeInputs = await getChallengeInputs();

  const inputs = {
    ...issuerInputs,
    ...holderInputs,
    ...claimInputs,
    ...challengeInputs,
    slotIndex: 2, // index of slot A
    operator: '1',
    value: [
      '25',
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
    timestamp: '1642074362',
  };

  console.log(inputs);

  await generateWitness(inputs);
}

prove()
  .then(() => {
    console.log('Done!');
  })
  .catch((err) => {
    console.error(err);
  });

// challenge: "1",
// challengeSignatureR8x: "8553678144208642175027223770335048072652078621216414881653012537434846327449",
// challengeSignatureR8y: "5507837342589329113352496188906367161790372084365285966741761856353367255709",
// challengeSignatureS: "2093461910575977345603199789919760192811763972089699387324401771367839603655",
// operator: 1,
// slotIndex: 2,
// timestamp: "1642074362",
// value: ["10", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],

// userAuthClaim: ["304427537360709784173770334266246861770", "0", "17640206035128972995519606214765283372613874593503528180869261482403155458945", "20634138280259599560273310290025659992320584624461316485434108770067472477956", "15930428023331155902", "0", "0", "0"],
// userAuthClaimMtp: ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
// userAuthClaimNonRevMtp: ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
// userAuthClaimNonRevMtpAuxHi: "0",
// userAuthClaimNonRevMtpAuxHv: "0",
// userAuthClaimNonRevMtpNoAux: "1",
// userClaimsTreeRoot: "9763429684850732628215303952870004997159843236039795272605841029866455670219",
// userState: "18656147546666944484453899241916469544090258810192803949522794490493271005313",
// userRevTreeRoot: "0",
// userRootsTreeRoot: "0",
// userID: "379949150130214723420589610911161895495647789006649785264738141299135414272",
// issuerID: "26599707002460144379092755370384635496563807452878989192352627271768342528",
// issuerClaimSignatureR8x: "18625305647089498634672127449050652473073470525382360069529718632627474482386",
// issuerClaimSignatureR8y: "14539700345423181413201048131770723125531044953576671601029329833956725811279",
// issuerClaimSignatureS: "772934080142423067561028786350670095248312416624185973552603152377549415467",
// issuerAuthClaim: ["304427537360709784173770334266246861770", "0", "9582165609074695838007712438814613121302719752874385708394134542816240804696", "18271435592817415588213874506882839610978320325722319742324814767882756910515", "11203087622270641253", "0", "0", "0"],
// issuerAuthClaimMtp: ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
// issuerAuthClaimNonRevMtp: ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
// issuerAuthClaimNonRevMtpAuxHi: "0",
// issuerAuthClaimNonRevMtpAuxHv: "0",
// issuerAuthClaimNonRevMtpNoAux: "1",
// issuerAuthClaimsTreeRoot: "18337129644116656308842422695567930755039142442806278977230099338026575870840",
// issuerAuthRevTreeRoot: "0",
// issuerAuthRootsTreeRoot: "0",

// issuerClaim: ["3583233690122716044519380227940806650830", "379949150130214723420589610911161895495647789006649785264738141299135414272", "10", "0", "30803922965249841627828060161", "0", "0", "0"],
// issuerClaimNonRevClaimsTreeRoot: "3077200351284676204723270374054827783313480677490603169533924119235084704890",
// issuerClaimNonRevRevTreeRoot: "0",
// issuerClaimNonRevRootsTreeRoot: "0",
// issuerClaimNonRevState: "18605292738057394742004097311192572049290380262377486632479765119429313092475",
// issuerClaimNonRevMtp: ["0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
// issuerClaimNonRevMtpAuxHi: "0",
// issuerClaimNonRevMtpAuxHv: "0",
// issuerClaimNonRevMtpNoAux: "1",
// claimSchema: "180410020913331409885634153623124536270",
