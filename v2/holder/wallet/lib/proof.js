const { PROTOCOL_CONSTANTS, AuthHandler } = require('@0xpolygonid/js-sdk');
const { DID } = require('@iden3/js-iden3-core');
const { TextEncoder } = require('util');
const axios = require('axios');
const { CredentialManager } = require('./credential');
const { scanQR } = require('./util');
const { initPackageManager } = require('./util');

class ProofManager {
  constructor(db) {
    this.db = db;
    this.credmgr = new CredentialManager(db);
  }

  async init() {
    await this.credmgr.init();
  }

  async respondToChallenge(qrcodeFile, identityIndex = 0) {
    const challenge = await scanQR(qrcodeFile);
    console.log(JSON.stringify(challenge, null, 2));
    const { MediaType, PROTOCOL_MESSAGE_TYPE } = PROTOCOL_CONSTANTS;
    if (challenge.typ != MediaType.PlainMessage) {
      const msg = `QR code does not have the right media type, expecting ${MediaType.PlainMessage} but got ${challenge.typ}`;
      console.error(msg);
      throw new Error(msg);
    } else if (challenge.type != PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE) {
      const msg = `QR code does not have the right message type, expecting ${PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE} but got ${challenge.type}`;
      console.error(msg);
      throw new Error(msg);
    }

    const myIdentities = await this.credmgr.idmgr.getAllIdentities();
    if (!myIdentities || myIdentities.length <= 0) {
      const msg = `Must generate at least one identity before downloading a credential`;
      console.error(msg);
      throw new Error(msg);
    } else if (myIdentities.length < identityIndex + 1) {
      const msg = `Invalid identity index: ${identityIndex}. Must be between 0 and ${myIdentities.length - 1}`;
      console.error(msg);
      throw new Error(msg);
    }

    console.log(`Existing identities: ${JSON.stringify(myIdentities, null, 2)}`);
    console.log(`Using identity at index: ${identityIndex}`);

    const myDID = DID.parse(myIdentities[identityIndex].identifier);

    var authRawRequest = new TextEncoder().encode(JSON.stringify(challenge));
    const { packageManager, proofService } = await initPackageManager(this.credmgr.identityWallet, this.credmgr.wallet, this.credmgr.dataStorage.states);

    const authHandler = new AuthHandler(packageManager, proofService, this.credmgr.wallet);
    const { token, authResponse } = await authHandler.handleAuthorizationRequestForGenesisDID(myDID, authRawRequest);
    console.log(token);
    console.log(authResponse);
    const url = challenge.body.callbackUrl;
    console.log(`Sending the challenge response to callback URL: ${url}`);
    try {
      const result = await axios({
        method: 'post',
        url,
        data: token,
        headers: {
          'Content-Type': 'text/plain',
        },
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
        console.log('error data', error.response.data);
        console.log('error status', error.response.status);
        console.log('error headers', error.response.headers);
      } else if (error.request) {
        // The request was made but no response was received
        // `error.request` is an instance of XMLHttpRequest in the browser and an instance of
        // http.ClientRequest in node.js
        console.log(error.request);
      }
      console.log(`Callback to ${url} failed: ${error.message}. Please check the verifier server logs for more details.`);
      throw error;
    }
  }
}

module.exports = {
  ProofManager,
};
