const { TextEncoder } = require('util');
const { DID } = require('@iden3/js-iden3-core');
const { PROTOCOL_CONSTANTS, FetchHandler } = require('@0xpolygonid/js-sdk');
const { IdentityManager } = require('./identity');
const { scanQR, initPackageManager } = require('./util');

class CredentialManager {
  constructor(db) {
    this.db = db;
    this.idmgr = new IdentityManager(db);
  }

  async init() {
    await this.idmgr.init();
    this.identityWallet = this.idmgr.wallet;
    this.wallet = this.idmgr.credentialWallet;
    this.dataStorage = this.idmgr.dataStorage;
  }

  async downloadCredential(qrcodeFile) {
    const myIdentities = await this.idmgr.getAllIdentities();
    if (!myIdentities || myIdentities.length <= 0) {
      const msg = `Must generate at least one identity before downloading a credential`;
      console.error(msg);
      throw new Error(msg);
    }

    console.log(`Existing identities: ${JSON.stringify(myIdentities, null, 2)}`);

    const { MediaType, PROTOCOL_MESSAGE_TYPE } = PROTOCOL_CONSTANTS;
    const credentialOffer = await scanQR(qrcodeFile);
    let myDID;
    if (credentialOffer.typ != MediaType.PlainMessage) {
      const msg = `QR code does not have the right media type, expecting ${MediaType.PlainMessage} but got ${credentialOffer.typ}`;
      console.error(msg);
      throw new Error(msg);
    } else if (credentialOffer.type != PROTOCOL_MESSAGE_TYPE.CREDENTIAL_OFFER_MESSAGE_TYPE) {
      const msg = `QR code does not have the right message type, expecting ${PROTOCOL_MESSAGE_TYPE.CREDENTIAL_OFFER_MESSAGE_TYPE} but got ${credentialOffer.type}`;
      console.error(msg);
      throw new Error(msg);
    } else {
      let myIdentity;
      for (let id of myIdentities) {
        if (credentialOffer.to == id.identifier) {
          myIdentity = id;
          break;
        }
      }
      if (!myIdentity) {
        const msg = `QR code represents an offer to a subject we don't have: ${credentialOffer.to}`;
        console.error(msg);
        throw new Error(msg);
      }
      myDID = DID.parse(myIdentity.identifier);
    }

    const msgBytes = new TextEncoder().encode(JSON.stringify(credentialOffer));

    const { packageManager } = await initPackageManager(this.identityWallet, this.wallet, this.dataStorage.states);
    const fetchHandler = new FetchHandler(packageManager);
    const result = await fetchHandler.handleCredentialOffer(myDID, msgBytes);
    console.log(result);
    await this.wallet.save(result[0]);
  }
}

module.exports = {
  CredentialManager,
};
