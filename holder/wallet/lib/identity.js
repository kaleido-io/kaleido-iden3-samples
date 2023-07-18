const { BjjProvider, core, IdentityWallet, CredentialWallet, KMS, KmsKeyType, ProofService, CredentialStatusResolverRegistry, CredentialStatusType, RHSResolver, IssuerResolver } = require('@0xpolygonid/js-sdk');
const { DID } = require('@iden3/js-iden3-core');
const abi = require('@0xpolygonid/js-sdk/dist/cjs/storage/blockchain/state-abi.json');
const { Contract } = require('@ethersproject/contracts');
const { JsonRpcProvider } = require('@ethersproject/providers');
const { Wallet } = require('@ethersproject/wallet');
const { initDataStorage, initCircuitStorage } = require('./util');
const { FSPrivateKeyStore } = require('./extensions/keystore');
const config = require('./config');

class IdentityManager {
  constructor(db, network) {
    this.db = db;
    this.network = network;
    this.config = config[network];
    // TODO: can get provider and state contract from this.dataStorage.states
    this.provider = new JsonRpcProvider(this.config.url);
    this.stateContract = new Contract(this.config.contractAddress, abi, this.provider);
  }

  async init() {
    const keyStore = new FSPrivateKeyStore();
    const bjjProvider = new BjjProvider(KmsKeyType.BabyJubJub, keyStore);
    const kms = new KMS();
    kms.registerKeyProvider(KmsKeyType.BabyJubJub, bjjProvider);

    this.dataStorage = await initDataStorage(this.db, this.network);
    this.credentialWallet = await this.initCredentialWallet();
    this.wallet = new IdentityWallet(kms, this.dataStorage, this.credentialWallet);

    const circuitStorage = await initCircuitStorage();
    this.proofService = new ProofService(this.wallet, this.credentialWallet, circuitStorage, this.dataStorage.states);
  }

  async createIdentity() {
    const { did: userDID, credential: authCredential } = await this.wallet.createIdentity({
      method: core.DidMethod.Iden3,
      blockchain: core.Blockchain.NoChain,
      networkId: core.NetworkId.NoNetwork,
      revocationOpts: {
        id: 'https://rhs-staging.polygonid.me',
        type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof
      }
    });
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

  async initCredentialWallet() {
    const resolvers = new CredentialStatusResolverRegistry();
    resolvers.register(
      CredentialStatusType.SparseMerkleTreeProof,
      new IssuerResolver()
    );
    resolvers.register(
      CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
      new RHSResolver(this.dataStorage.states)
    );
    return new CredentialWallet(this.dataStorage, resolvers);
  }
}

module.exports = {
  IdentityManager,
};
