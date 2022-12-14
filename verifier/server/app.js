const express = require('express');
const { join } = require('path');
const { auth, resolver, loaders } = require('@iden3/js-iden3-auth');
const getRawBody = require('raw-body');
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const argv = yargs(hideBin(process.argv)).option('state-contract', { string: true }).argv;

let publicHost = argv['public-host'];
if (!publicHost) {
  console.log("No publicly accessible hostname provided with '--public-host', using localhost:8080");
  publicHost = 'http://localhost:8080';
} else {
  publicHost = publicHost.replace(/\/+$/, '');
}

let jsonrpcUrl = argv['jsonrpc-url'];
if (!jsonrpcUrl) {
  console.error('Must provide the URL of the JSON-RPC endpoint for the blockchain that hosts the State contract, with the --jsonrpc-url parameter');
  process.exit(1);
}

let stateContract = argv['state-contract'];
if (!stateContract) {
  console.error('Must provide the address of the State contract, with the --state-contract parameter');
  process.exit(1);
}

const app = express();
const port = 8080;

app.use(express.static('static'));

app.get('/api/sign-in', (req, res) => {
  console.log('get QR');
  getQR(req, res);
});

app.post('/api/callback', (req, res) => {
  console.log('callback');
  callback(req, res);
});

app.listen(port, () => {
  console.log('server running on port 8080');
});

// Create a map to store the auth requests and their session IDs
const requestMap = new Map();

// GetQR returns auth request
async function getQR(req, res) {
  // Audience is verifier id
  const sessionId = 1;
  const callbackURL = '/api/callback';
  const audience = '1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ';
  const schemaUrl = 'https://schema.polygonid.com/jsonld/kyc.json-ld';
  const schemaType = 'AgeCredential';
  const circuitId = 'credentialAtomicQuerySig';

  const uri = `${publicHost}${callbackURL}?sessionId=${sessionId}`;

  // Generate request for basic authentication
  const challenge = '12345'; // supposed to be unique for every interaction
  const request = auth.createAuthorizationRequestWithMessage('test flow', challenge, audience, uri);

  request.id = '7f38a193-0918-4a48-9fac-36adfdb8b542';
  request.thid = '7f38a193-0918-4a48-9fac-36adfdb8b542';

  // Add request for a specific proof
  const proofRequest = {
    id: challenge,
    circuit_id: circuitId,
    rules: {
      query: {
        allowedIssuers: ['*'],
        schema: {
          type: schemaType,
          url: schemaUrl,
        },
        req: {
          birthDay: {
            $lt: 20000101, // bithDay field less then 2000/01/01
          },
        },
      },
    },
  };

  const scope = request.body.scope ?? [];
  request.body.scope = [...scope, proofRequest];

  // Store auth request in map associated with session ID
  requestMap.set(`${sessionId}`, request);

  return res.status(200).set('Content-Type', 'application/json').send(request);
}

// Callback verifies the proof after sign-in callbacks
async function callback(req, res) {
  // Get session ID from request
  const sessionId = req.query.sessionId;

  // get JWZ token params from the post request
  const raw = await getRawBody(req);
  const authResponse = JSON.parse(raw);

  // fetch authRequest from sessionID
  const authRequest = requestMap.get(`${sessionId}`);

  console.log(authRequest);

  // Locate the directory that contains circuit's verification keys
  const verificationKeyloader = new loaders.FSKeyLoader(join(__dirname, './keys'));
  const sLoader = new loaders.UniversalSchemaLoader('ipfs.io');

  // Add Polygon RPC node endpoint - needed to read on-chain state and identity state contract address
  const ethStateResolver = new resolver.EthStateResolver(jsonrpcUrl, stateContract);

  // EXECUTE VERIFICATION
  const verifier = new auth.Verifier(verificationKeyloader, sLoader, ethStateResolver);

  try {
    await verifier.verifyAuthResponse(authResponse, authRequest);
  } catch (error) {
    return res.status(500).send(error);
  }
  return res
    .status(200)
    .set('Content-Type', 'application/json')
    .send('user with ID: ' + authResponse.from + ' Succesfully authenticated');
}
