const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const argv = yargs(hideBin(process.argv)).argv;

class SQliteDataSource {
  constructor(db, tableName) {
    this.db = db;
    this.tableName = tableName;
  }

  async save(key, value, keyName = 'id') {
    if (isDebug()) {
      console.log(JSON.stringify(value, null, 2));
    }
    const result = await this.db.get(`SELECT * FROM ${this.tableName} WHERE ${keyName} = ?`, key);
    if (!result) {
      console.log(`Inserting new entry to table ${this.tableName}`);
      await this._save(key, value);
    } else {
      console.log(`Existing record in table ${this.tableName} for key ${key}`);
    }
  }

  async get(key, keyName = 'id') {
    const result = await this.db.get(`SELECT * FROM ${this.tableName} WHERE ${keyName} = ?`, key);
    return result;
  }

  async load() {
    const result = await this.db.all(`SELECT * FROM ${this.tableName}`);
    return result;
  }

  async delete(key, keyName = 'id') {
    await this.db.run(`DELETE FROM ${this.tableName} WHERE ${keyName} = ?`, key);
  }
}

class IdentitiesDataSource extends SQliteDataSource {
  constructor(db) {
    super(db, 'Identities');
  }

  async _save(key, value) {
    const { state, published, genesis } = value;
    await this.db.run(`INSERT INTO ${this.tableName} (identifier, state, published, genesis) VALUES (?, ?, ?, ?)`, key, state.hex(), published, genesis);
  }
}

class ProfilesDataSource extends SQliteDataSource {
  constructor(db) {
    super(db, 'Profiles');
  }

  async _save(key, value) {
    const { nonce, genesisIdentifier, verifier } = value;
    await this.db.run(`INSERT INTO ${this.tableName} (id, nonce, genesisIdentifier, verifier) VALUES (?, ?, ?, ?)`, key, nonce, genesisIdentifier, verifier);
  }
}

class CredentialsDataSource extends SQliteDataSource {
  constructor(db) {
    super(db, 'Credentials');
  }

  async _save(key, value) {
    const { type, expirationDate, issuanceDate, credentialSubject, credentialStatus, issuer, credentialSchema, proof } = value;
    await this.db.run(
      `INSERT INTO ${this.tableName} (id, context, credentialType, expirationDate, issuanceDate, credentialSchema, credentialSubject, credentialStatus, issuer, proof) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      key,
      JSON.stringify(value['@context']),
      JSON.stringify(type),
      expirationDate,
      issuanceDate,
      JSON.stringify(credentialSchema),
      JSON.stringify(credentialSubject),
      JSON.stringify(credentialStatus),
      issuer,
      JSON.stringify(proof)
    );
  }

  async load() {
    const result = await super.load();
    for (let cred of result) {
      cred['@context'] = JSON.parse(cred.context);
      cred.type = JSON.parse(cred.credentialType);
      cred.credentialSubject = JSON.parse(cred.credentialSubject);
      cred.credentialStatus = JSON.parse(cred.credentialStatus);
      cred.credentialSchema = JSON.parse(cred.credentialSchema);
      cred.proof = JSON.parse(cred.proof);
      delete cred.context;
      delete cred.credentialType;
    }
    return result;
  }
}

function isDebug() {
  return argv.debug;
}

module.exports = {
  IdentitiesDataSource,
  ProfilesDataSource,
  CredentialsDataSource,
};
