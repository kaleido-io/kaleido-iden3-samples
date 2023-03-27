const { BjjProvider, core, IdentityWallet, CredentialWallet, KMS, KmsKeyType, ProofService } = require('@0xpolygonid/js-sdk');
const { DID } = require('@iden3/js-iden3-core');
const abi = require('@0xpolygonid/js-sdk/dist/cjs/storage/blockchain/state-abi.json');
const { Contract } = require('@ethersproject/contracts');
const { JsonRpcProvider } = require('@ethersproject/providers');
const { Wallet } = require('@ethersproject/wallet');
const { initDataStorage, initCircuitStorage } = require('./util');
const { FSPrivateKeyStore } = require('./extensions/keystore');
const config = require('./config');

class IdentityManager {
  constructor(db, network = 'kaleido') {
    this.db = db;
    this.config = config[network];
    this.provider = new JsonRpcProvider(this.config.url);
    this.stateContract = new Contract(this.config.contractAddress, abi, this.provider);
  }

  async init() {
    const keyStore = new FSPrivateKeyStore();
    const bjjProvider = new BjjProvider(KmsKeyType.BabyJubJub, keyStore);
    const kms = new KMS();
    kms.registerKeyProvider(KmsKeyType.BabyJubJub, bjjProvider);

    this.dataStorage = await initDataStorage(this.db);
    this.credentialWallet = new CredentialWallet(this.dataStorage);
    this.wallet = new IdentityWallet(kms, this.dataStorage, this.credentialWallet);

    const circuitStorage = await initCircuitStorage();
    this.proofService = new ProofService(this.wallet, this.credentialWallet, circuitStorage, this.dataStorage.states);
  }

  async createIdentity() {
    const rhsUrl = 'https://rhs-staging.polygonid.me';
    const { did: userDID, credential: authCredential } = await this.wallet.createIdentity(
      'http://mytestwallet.com/', // this is url that will be a part of auth bjj credential identifier
      {
        method: core.DidMethod.Iden3,
        rhsUrl,
      }
    );

    console.log('=============== user did ===============');
    console.log(userDID.toString());
    return { did: userDID, authCredential };
  }

  async getAllIdentities() {
    return await this.wallet._storage.identity.getAllIdentities();
  }

  async queryGISTProof() {
    const identities = await this.getAllIdentities();
    console.log(`=> Existing identities:\n${JSON.stringify(identities, null, 2)}`);
    const myIdentity = identities[0];
    const myDID = DID.parse(myIdentity.identifier);
    const result = await this.stateContract.getGISTProof(myDID.id.bigInt());
    return result;
  }

  async publishState(credential, did) {
    const res = await this.wallet.addCredentialsToMerkleTree([credential], did);
    const signer = new Wallet(this.config.privateKey, this.provider);
    const txId = await this.proofService.transitState(did, res.oldTreeState, true, this.dataStorage.states, signer);
    console.log(`Transaction ID: ${txId}`);
  }
}

module.exports = {
  IdentityManager,
};
