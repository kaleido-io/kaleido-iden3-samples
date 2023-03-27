const { AbstractPrivateKeyStore } = require('@0xpolygonid/js-sdk');
const { readFile, writeFile } = require('fs-extra');
const os = require('os');
const { join } = require('path');

class FSPrivateKeyStore extends AbstractPrivateKeyStore {
  constructor() {
    super();
    this._keydir = join(os.homedir(), 'iden3/wallet');
  }
  async get(args) {
    const keyfile = join(this._keydir, `${args.alias}.key`);
    const privateKey = await readFile(keyfile);
    if (!privateKey) {
      throw new Error('no key under given alias');
    }
    return privateKey.toString();
  }

  async import(args) {
    const keyfile = join(this._keydir, `${args.alias}.key`);
    await writeFile(keyfile, args.key);
  }
}

module.exports = {
  FSPrivateKeyStore,
};
