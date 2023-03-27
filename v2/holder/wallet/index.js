const { join } = require('path');
const os = require('os');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const argv = yargs(hideBin(process.argv)).argv;
const { IdentityManager } = require('./lib/identity');
const { CredentialManager } = require('./lib/credential');
const { initializeStateContract } = require('./lib/init-contract');
const { ProofManager } = require('./lib/proof');

async function initDB() {
  const homedir = os.homedir();
  const dbpath = join(homedir, 'iden3/wallet/db.sqlite');

  const db = await open({
    filename: dbpath,
    driver: sqlite3.Database,
  });
  await db.migrate({
    migrationsPath: join(__dirname, './lib/migrations'),
  });

  return db;
}

async function exec() {
  console.log('Initialing SQLite DB');
  const db = await initDB();

  if (argv.command == 'init-contract') {
    console.log('Initializing state contract');
    await initializeStateContract(db);
  } else if (argv.command == 'list-ids') {
    console.log('Listing existing identities');
    const idmgr = new IdentityManager(db);
    await idmgr.init();
    const result = await idmgr.getAllIdentities();
    console.log(JSON.stringify(result, null, 2));
  } else if (argv.command == 'create-id') {
    console.log('Creating identity');
    const idmgr = new IdentityManager(db);
    await idmgr.init();
    await idmgr.createIdentity();
  } else if (argv.command == 'get-gist-proof') {
    console.log('Loading my identity');
    const idmgr = new IdentityManager(db, argv.network);
    await idmgr.init();
    const result = await idmgr.queryGISTProof();
    console.log(`GIST proof for my identity: ${JSON.stringify(result, null, 2)}`);
  } else if (argv.command == 'fetch-credential') {
    console.log('Downloading offered verifiable credentials');
    const cvmgr = new CredentialManager(db);
    await cvmgr.init();
    await cvmgr.downloadCredential(argv.qrcode);
  } else if (argv.command == 'respond-to-challenge') {
    console.log('Respond to challenge');
    const proofmgr = new ProofManager(db);
    await proofmgr.init();
    await proofmgr.respondToChallenge(argv.qrcode, argv['id-index']);
  }
}

exec().then(() => {
  console.log('Done!');
});
