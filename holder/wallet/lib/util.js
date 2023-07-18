const {
  CircuitId,
  CircuitStorage,
  FSKeyLoader,
  InMemoryDataSource,
  CredentialStorage,
  defaultEthConnectionConfig,
  EthStateStorage,
  IdentityStorage,
  MerkleTreeLocalStorage,
  ProofService,
  DataPrepareHandlerFunc,
  VerificationHandlerFunc,
  PackageManager,
  ZKPPacker,
  PlainPacker,
} = require('@0xpolygonid/js-sdk');
const { proving } = require('@iden3/js-jwz');
const { join } = require('path');
const fs = require('fs');
const Jimp = require('jimp');
const jsQR = require('jsqr');
const config = require('./config');
const { CredentialsDataSource, IdentitiesDataSource, ProfilesDataSource } = require('./extensions/storage');

async function initDataStorage(db, network) {
  const conf = Object.assign({}, defaultEthConnectionConfig, config[network]);

  const dataStorage = {
    credential: new CredentialStorage(new CredentialsDataSource(db)),
    identity: new IdentityStorage(new IdentitiesDataSource(db), new ProfilesDataSource(db)),
    mt: new MerkleTreeLocalStorage(40),
    states: new EthStateStorage(conf),
  };
  return dataStorage;
}

async function initCircuitStorage() {
  const circuitStorage = new CircuitStorage(new InMemoryDataSource());

  const loader = new FSKeyLoader(join(__dirname, '../snark'));

  await circuitStorage.saveCircuitData(CircuitId.AuthV2, {
    circuitId: CircuitId.AuthV2,
    wasm: await loader.load(`${CircuitId.AuthV2.toString()}/circuit.wasm`),
    provingKey: await loader.load(`${CircuitId.AuthV2.toString()}/circuit_final.zkey`),
    verificationKey: await loader.load(`${CircuitId.AuthV2.toString()}/verification_key.json`),
  });

  await circuitStorage.saveCircuitData(CircuitId.AtomicQuerySigV2, {
    circuitId: CircuitId.AtomicQuerySigV2,
    wasm: await loader.load(`${CircuitId.AtomicQuerySigV2.toString()}/circuit.wasm`),
    provingKey: await loader.load(`${CircuitId.AtomicQuerySigV2.toString()}/circuit_final.zkey`),
    verificationKey: await loader.load(`${CircuitId.AtomicQuerySigV2.toString()}/verification_key.json`),
  });

  await circuitStorage.saveCircuitData(CircuitId.StateTransition, {
    circuitId: CircuitId.StateTransition,
    wasm: await loader.load(`${CircuitId.StateTransition.toString()}/circuit.wasm`),
    provingKey: await loader.load(`${CircuitId.StateTransition.toString()}/circuit_final.zkey`),
    verificationKey: await loader.load(`${CircuitId.StateTransition.toString()}/verification_key.json`),
  });

  return circuitStorage;
}

async function scanQR(qrcodeFile) {
  var buffer = fs.readFileSync(qrcodeFile);
  const image = await Jimp.read(buffer);
  const result = jsQR(new Uint8ClampedArray(image.bitmap.data), image.bitmap.width, image.bitmap.height);
  if (!result) {
    throw new Error('Failed to parse qr_code');
  }
  return JSON.parse(result.data);
}

async function initPackageManager(identityWallet, credentialWallet, stateStorage) {
  const circuitStorage = await initCircuitStorage();
  const circuitData = await circuitStorage.loadCircuitData(CircuitId.AuthV2);
  const proofService = new ProofService(identityWallet, credentialWallet, circuitStorage, stateStorage);
  const prepareFn = proofService.generateAuthV2Inputs.bind(proofService);
  const stateVerificationFn = proofService.verifyState.bind(proofService);
  const authInputsHandler = new DataPrepareHandlerFunc(prepareFn);
  const verificationFn = new VerificationHandlerFunc(stateVerificationFn);
  const mapKey = proving.provingMethodGroth16AuthV2Instance.methodAlg.toString();
  const verificationParamMap = new Map([
    [
      mapKey,
      {
        key: circuitData.verificationKey,
        verificationFn,
      },
    ],
  ]);

  const provingParamMap = new Map();
  provingParamMap.set(mapKey, {
    dataPreparer: authInputsHandler,
    provingKey: circuitData.provingKey,
    wasm: circuitData.wasm,
  });

  const packageManager = new PackageManager();
  const packer = new ZKPPacker(provingParamMap, verificationParamMap);
  const plainPacker = new PlainPacker();
  packageManager.registerPackers([packer, plainPacker]);

  return { packageManager, proofService };
}

module.exports = {
  initDataStorage,
  initCircuitStorage,
  initPackageManager,
  scanQR,
};
