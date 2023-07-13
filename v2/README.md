# kaleido-iden3-samples

Sample code for using the [Iden3 protocol](https://docs.iden3.io/protocol/spec/) to issue verifiable claims and verify them.

This is the v2 version of the iden3 protocol. It adds support for the [w3c verifiable credentials](https://www.w3.org/TR/vc-data-model/) standard, plus the [Profiles](https://docs.iden3.io/protocol/spec/#identity-profiles-new) support.

# Getting Started

The setup includes 4 components:

- state contract on Kaleido: registers the trust root of the iden3 protocol
- issuer service: manages the issuer identities and verifiable credentials
- verifier service: manages the interactions with the holder wallet to present a verification challenge, and verifies the proof
- holder wallet: mimics the behavior of the holder's identity wallet. Such wallets are typically implemented as a mobile application. This sample uses node.js based command line programs to illustrate the interactions a mobile wallet performs with the issuer and the verifier services

## Deploy the state contract

Checkout the `v1.0.0-beta.0` tag of the contracts repository [https://github.com/iden3/contracts](https://github.com/iden3/contracts)

Add a `kaleido` network spec to the hardhat configuration file `hardhat.config.ts`:

```
    kaleido: {
      chainId: [chain ID of your Kaleido environment],
      url: "https://<appcreds name>:<appcreds password>@<environment ID>-<node ID>-rpc.us0-aws.kaleido.io",
      accounts: ["<private key hex of an Ethereum account>"]
    },
```

Deploy using hardhat:

```console
$ npx hardhat run scripts/deploy.ts --network kaleido
[ '======== StateV2: deploy started ========' ]
[ 'deploying verifier...' ]
[
  'Verifier contract deployed to address 0x5CDe7A583404bDdaF0Fda534Ab187d7dAb9d88F8 from 0xF1D44Cfc2400c9fC429E32861bd4439050c51623'
]
[ 'deploying poseidons...' ]
Poseidon1Elements deployed to: 0x824Bea121ef10aD3998Ef142B34D281F97Fb0618
Poseidon2Elements deployed to: 0x38D62962B27cfb561B125efcb55a63C29458e4EC
Poseidon3Elements deployed to: 0xdd46c0A974C994877B7fa93c00657480DDb42931
[ 'deploying SMT...' ]
[ 'Smt deployed to:  0x2DCd56940146B547C0C201B9BC8f68a29AC41D65' ]
[ 'deploying stateV2...' ]
Warning: Potentially unsafe deployment of StateV2

    You are using the `unsafeAllow.external-library-linking` flag to include external libraries.
    Make sure you have manually checked that the linked libraries are upgrade safe.

[
  'StateV2 contract deployed to address 0x4473e316be68B9Dc365c08d64880D0af6451120B from 0xF1D44Cfc2400c9fC429E32861bd4439050c51623'
]
[ '======== StateV2: deploy completed ========' ]
```

Take note of the state contract address from the above output, in this case `0x4473e316be68B9Dc365c08d64880D0af6451120B`.

## Issuer Server

The issuer server is made up of a number of microservices:

- issuer server: API server for managing identities and verifiable credentials
- pending state publisher: when there are new states in the issuer's merkle trees, that requires the global state to be updated on the blockchain, this service is responsible for checking and sending transactions to update the onchain state
- postgres DB: persistence for identities, credentials, merkle trees, etc
- redis: persistent cache for loading schemas
- Hashicorp vault: managing private keys for each identity

### Building the issuer server

Checkout the `v2.2.0` tag of the issuer server implementation from [https://github.com/0xPolygonID/issuer-node](https://github.com/0xPolygonID/issuer-node).

To build the docker image on an `arm` architecture machine, such as MacBook m1, modify the `Makefile` to use the `Dockerfile-arm` for the docker build:

```
build/docker: ## Build the docker image.
	DOCKER_BUILDKIT=1 \
	docker build \
		-f ./Dockerfile-arm \
```

On `amd64` architecture machines, leave the `Makefile` as is.

Build the docker images for the server:

```console
$ VERSION=latest make build/docker
```

### Launching vault

You must launch the vault container first before launching the issuer server container, because the vault container will generate a new access token, to be configured on the issuer server in order to gain access to the vault API.

Go to the [issuer](/v2/issuer) folder.

```console
$ docker compose up -d vault postgres redis
[+] Running 4/4
 ⠿ Network issuer_default       Created                                                                                                                                                                                                         0.0s
 ⠿ Container issuer-redis-1     Started                                                                                                                                                                                                         0.6s
 ⠿ Container issuer-vault-1     Started                                                                                                                                                                                                         0.7s
 ⠿ Container issuer-postgres-1  Started                                                                                                                                                                                                         0.7s
```

Get the access token from the vault container's logs:

```console
$ docker logs issuer-vault-1
...
===== ENABLED IDEN3 =====
token:hvs.nlF96QkyMKmozv6aDLjINonq
```

Take note of the token string above, in this case `token:hvs.nlF96QkyMKmozv6aDLjINonq`.

### Create an issuer identity

We should first launch the `platform` service to create an issuer identity.
First copy the env variable files that our issuer node needs to use.

```
cp .env-api.sample .env-api
cp .env-issuer.sample .env-issuer
cp .env-ui.sample .env-ui
```

Change the following in `.env-issuer`:
```
ISSUER_ETHEREUM_URL=<full URL to a Kaleido node RPC endpoint, including app creds>
ISSUER_ETHEREUM_CONTRACT_ADDRESS=<state contract address from the deploy task above>
ISSUER_REDIS_URL=redis://@redis:6380/1
ISSUER_KEY_STORE_TOKEN=<key store vault token that was obtained from the vault logs above>
```

Now we can launch the `platform` service
```
docker compose up -d platform
```

Finally, we send the following HTTP request to the `platform` service to create an identity in the issuer service (with basic auth using `user-issuer:password-issuer`):

```
curl 'localhost:3001/v1/identities' -H 'Authorization: Basic dXNlci1pc3N1ZXI6cGFzc3dvcmQtaXNzdWVy' -H 'Content-Type: application/json' \
--data-raw '{
    "didMetadata": {
        "method": "iden3"
    }
}'

{"identifier":"did:iden3:tVE7RF655rj8Ws4rYCF2E32d46q575Gq2GHi2aKYf","state":{"claimsTreeRoot":"c607cd9942b823b248ee67f5a8bed05b9009d4a052a2a1e895057955a07efa10","createdAt":"2023-07-13T15:26:01.547306Z","modifiedAt":"2023-07-13T15:26:01.547306Z","state":"134a098074f43b5490eeb87f175e7f6563759d3531d1c42ca14e94ee203de910","status":"confirmed"}}
```

Take note of the identifier, which is the DID for the issuer to be used in subsequent steps. In this case, it is `did:iden3:tVE7RF655rj8Ws4rYCF2E32d46q575Gq2GHi2aKYf`.

### Launching the publisher

To finalize launching our issuer service, we must have our pending state publisher running.

We first change the following contents in `.env-api`:

```
ISSUER_API_UI_ISSUER_DID=<Issuer DID that we obtained from the previous step>
```

We then launch the publisher service:

```
docker compose up -d pending_publisher
```

## Verifier server

A sample verifier server is provided in the [verifier](/v2/verifier) folder.

Build the server binary:

```console
$ make build
```

Create a configuration file with the following content. Be sure to fill out the
information in the brackets (`<>`) and fill out `ethContractAddress` and `self`
with information obtained from previous sections.

```yaml
api:
  address: 0.0.0.0
  publicURL: http://localhost:8000
iden3:
  verificationKeysDir: <your path to parent folder>/kaleido-iden3-samples/v2/verifier/pkg/circuits
  ethUrl: <full URL to a Kaleido node RPC endpoint, including app creds>
  ethContractAddress: <contract address obtained from previous section>
  publicHost: http://localhost:8000
  self: <issuer did obtained from previous section>
```

Launch the server:

```console
$ ./verifier -f /tmp/config.yaml
```

> If you are on an amd64 system, you can build the docker image and launch with Docker. Unfortunately docker build doesn't work on an arm64 architecture system.

## Holder wallet

The holder wallet uses the [js-sdk](https://github.com/0xPolygonID/js-sdk) to mimic the behaviors of a holder's wallet.

It uses the following persistence layer:

- sqlite: an extension for the data source interface is provided based on sqlite. The database file is created at `$HOME/iden3/wallet/db.sqlite`
- local storage: for the merkle tree storage, the local storage based implementation is used. Due to the usage of local storage, which is a browser-only construct, a polyfill must be specified with each command using the `-r node-localstorage/register` parameter. This creates a `scratch` folder in the current directory.

Go to the [holder/wallet](/v2/holder/wallet) folder.

### Pre-reqs

```console
$ npm i
```

### Configure the wallet

Update the wallet config file `v2/holder/wallet/lib/config.js` to match the values for the target blockchain node and the state contract address.

### Initialize the state contract

Due to a current limitation, the state contract won't function properly, until it has been primed with at least one identity state.

Use the following command to prime the new state contract with a temporary issuer identity and a credential. They are thrown away after the state is uploaded to the state contract, and are not involved with the functioning of the protocol.

```console
$ node -r node-localstorage/register index.js --command init-contract
Using network: kaleido
Initializing SQLite DB
Initializing state contract
=> Creating temporary issuer identity
=> Creating temporary holder identity
=> Issuing a credential

=> Saving the new credential to the credential wallet
=> Adding the new credential to the merkle tree
=> Publishing the new state to the revocation service
=> Uploading the new state to blockchain
        Transaction ID: 0x9aecb034dc9bf812c759f7262d3cf970e6077f16ba73b56c6e781c9c6c5b4496
Done!
```

### Creating the wallet identity

```console
$ node -r node-localstorage/register index.js --command create-id
Using network: kaleido
Initializing SQLite DB
Creating identity
{
  identifier: 'did:iden3:tNdgTFxGLkPXhXtppLZzsX7YJmE88aMbkPZusa3zH',
  state: Hash {
    bytes: Uint8Array(32) [
      140, 151, 234,  43, 149,  98, 252, 244,
       69, 132, 169, 229,  23, 173,  44,  20,
       37,  25, 245,  51, 225, 188,  94,  91,
        2,  51,  92,  67,   4,  59,  34,  47
    ]
  },
  published: false,
  genesis: true
}
Inserting new entry to table Identities
W3CCredential {
  id: 'http://mytestwallet.com/aca8aa92-47ac-488b-bf56-7ffe34c2d31d',
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    'https://schema.iden3.io/core/jsonld/iden3proofs.jsonld',
    'https://schema.iden3.io/core/jsonld/auth.jsonld'
  ],
  type: [ 'VerifiableCredential', 'AuthBJJCredential' ],
  expirationDate: undefined,
  issuanceDate: '2023-07-13T15:49:37.824Z',
  credentialSubject: {
    x: '20551443941541039856779724878316235181494180027949146387804488665078182933995',
    y: '6940650171259878655194725047865445476240722585292155442891301287291079301320',
    type: 'AuthBJJCredential'
  },
  issuer: 'did:iden3:tNdgTFxGLkPXhXtppLZzsX7YJmE88aMbkPZusa3zH',
  credentialSchema: {
    id: 'https://schema.iden3.io/core/json/auth.json',
    type: 'JsonSchemaValidator2018'
  },
  credentialStatus: {
    id: 'https://rhs-staging.polygonid.me',
    revocationNonce: 0,
    type: 'Iden3ReverseSparseMerkleTreeProof'
  },
  proof: [
    Iden3SparseMerkleTreeProof {
      type: 'Iden3SparseMerkleTreeProof',
      mtp: [Proof],
      issuerData: [IssuerData],
      coreClaim: 'cca3371a6cb1b715004407e325bd993c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000eb752b8b10d6aff25f995381aa5538933607aa39a14c50aa257516bc7eb46f2dc8186b3cf5fe973c9c84be168e7dc500233ee12be3881e5e7449d10ccf44580f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    }
  ]
}
Inserting new entry to table Credentials
=============== user did ===============
did:iden3:tNdgTFxGLkPXhXtppLZzsX7YJmE88aMbkPZusa3zH
Done!
```

Take note of the user DID string above, which is used as the holder DID in subsequent steps.

### Issue a credential

Call the following issuer service API to issue a verifiable credential for the holder identity. For this call we are using the following identities:

- issuer: `did:iden3:tVE7RF655rj8Ws4rYCF2E32d46q575Gq2GHi2aKYf`
- holder: `did:iden3:tNdgTFxGLkPXhXtppLZzsX7YJmE88aMbkPZusa3zH`

```
curl 'localhost:3001/v1/did:iden3:tVE7RF655rj8Ws4rYCF2E32d46q575Gq2GHi2aKYf/claims' -H 'Authorization: Basic dXNlci1pc3N1ZXI6cGFzc3dvcmQtaXNzdWVy' --data-raw '{
  "credentialSchema": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v3.json",
  "type": "KYCAgeCredential",
  "credentialSubject": {
    "id": "did:iden3:tNdgTFxGLkPXhXtppLZzsX7YJmE88aMbkPZusa3zH",
    "birthday": 19960424,
    "documentType": 2
  },
  "expiration": 1910106487
}'

{"id":"797c21b7-2197-11ee-9ce7-0242ac120005"}
```

### Download the credential to the wallet

To download the credential to the wallet, first generate a QR code for the **credential offer** object that the issuer service uses to interact with the wallet. The QR code encodes the object that contains the ID of the credential. The wallet must authenticate itself with the issuer service, by demonstrating its possession of the private key corresponding to the holder DID, in order to obtain the credential itself.

First call the issuer API to obtain the credential offer object:

```
curl 'localhost:3001/v1/did:iden3:tVE7RF655rj8Ws4rYCF2E32d46q575Gq2GHi2aKYf/claims/797c21b7-2197-11ee-9ce7-0242ac120005/qrcode' -H 'Authorization: Basic dXNlci1pc3N1ZXI6cGFzc3dvcmQtaXNzdWVy'

{"body":{"credentials":[{"description":"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld#KYCAgeCredential","id":"528d0276-2196-11ee-9ce7-0242ac120005"}],"url":"http://localhost:3001/v1/agent"},"from":"did:iden3:tVE7RF655rj8Ws4rYCF2E32d46q575Gq2GHi2aKYf","id":"a240c33d-2362-4772-8171-c4035cc7fb69","thid":"a240c33d-2362-4772-8171-c4035cc7fb69","to":"did:iden3:tJNHfqXTe2UriBsU6MHXd3GJjfG1ZXw5FsDRNBaGa","typ":"application/iden3comm-plain-json","type":"https://iden3-communication.io/credentials/1.0/offer"}
```

Copy the JSON output of the request, plug it into a QR code encoder, such as [https://goqr.me/](https://goqr.me/) to encode it into a QR code image. Make sure to use a large enough (such as 800 x 800) image to provide the resolution needed for the dense information. Download the QR code image.

Use the `fetch-credential` command to download the credential from the issuer service. The wallet sample code will generate an authentication proof (for the `authV2` circuit) and send it to the endpoint contained in the credential offer object above (`http://localhost:3001/v1/agent` in this case). The issuer service verifies the proof to authenticate the wallet, and returns the promised credential identified by the `body.credentials[0].id` value.

```console
$ node -r node-localstorage/register index.js --command fetch-credential --qrcode /Users/jimzhang/Downloads/qrcode.png

Using network: kaleido
Initializing SQLite DB
Downloading offered verifiable credentials
Existing identities: [
  {
    "identifier": "did:iden3:tNdgTFxGLkPXhXtppLZzsX7YJmE88aMbkPZusa3zH",
    "state": "8c97ea2b9562fcf44584a9e517ad2c142519f533e1bc5e5b02335c43043b222f",
    "published": 0,
    "genesis": 1
  }
]
[
  {
    id: 'http://localhost:3001/v1/did:iden3:tVE7RF655rj8Ws4rYCF2E32d46q575Gq2GHi2aKYf/claims/797c21b7-2197-11ee-9ce7-0242ac120005',
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      'https://schema.iden3.io/core/jsonld/iden3proofs.jsonld',
      'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld'
    ],
    type: [ 'VerifiableCredential', 'KYCAgeCredential' ],
    expirationDate: '2030-07-12T17:08:07Z',
    issuanceDate: '2023-07-13T16:08:15.702137458Z',
    credentialSubject: {
      birthday: 19960424,
      documentType: 2,
      id: 'did:iden3:tNdgTFxGLkPXhXtppLZzsX7YJmE88aMbkPZusa3zH',
      type: 'KYCAgeCredential'
    },
    credentialStatus: {
      id: 'http://localhost:3001/v1/did%3Aiden3%3AtVE7RF655rj8Ws4rYCF2E32d46q575Gq2GHi2aKYf/claims/revocation/status/3835285175',
      revocationNonce: 3835285175,
      type: 'SparseMerkleTreeProof'
    },
    issuer: 'did:iden3:tVE7RF655rj8Ws4rYCF2E32d46q575Gq2GHi2aKYf',
    credentialSchema: {
      id: 'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v3.json',
      type: 'JsonSchema2023'
    },
    proof: [ [Object] ]
  }
]
{
  id: 'http://localhost:3001/v1/did:iden3:tVE7RF655rj8Ws4rYCF2E32d46q575Gq2GHi2aKYf/claims/797c21b7-2197-11ee-9ce7-0242ac120005',
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    'https://schema.iden3.io/core/jsonld/iden3proofs.jsonld',
    'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld'
  ],
  type: [ 'VerifiableCredential', 'KYCAgeCredential' ],
  expirationDate: '2030-07-12T17:08:07Z',
  issuanceDate: '2023-07-13T16:08:15.702137458Z',
  credentialSubject: {
    birthday: 19960424,
    documentType: 2,
    id: 'did:iden3:tNdgTFxGLkPXhXtppLZzsX7YJmE88aMbkPZusa3zH',
    type: 'KYCAgeCredential'
  },
  credentialStatus: {
    id: 'http://localhost:3001/v1/did%3Aiden3%3AtVE7RF655rj8Ws4rYCF2E32d46q575Gq2GHi2aKYf/claims/revocation/status/3835285175',
    revocationNonce: 3835285175,
    type: 'SparseMerkleTreeProof'
  },
  issuer: 'did:iden3:tVE7RF655rj8Ws4rYCF2E32d46q575Gq2GHi2aKYf',
  credentialSchema: {
    id: 'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v3.json',
    type: 'JsonSchema2023'
  },
  proof: [
    {
      type: 'BJJSignature2021',
      issuerData: [Object],
      coreClaim: 'c9b2370371b7fa8b3dab2a5ba81b68382a000000000000000000000000000000010062fcf44584a9e517ad2c142519f533e1bc5e5b02335c43043b222fce0a00912170a9dcf64b58333fba5582097287445b126903b0dc90614831fcb1b59a040000000000000000000000000000000000000000000000000000000000000000b7ce99e40000000077e9d9710000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
      signature: '1d6cc275f7c9c1b937fb48d6476cc216a22cc981af640d2515fcb63471525f9d3a4ea667391dc2fa6f9faf45b5ceccef13a8c4166cd4d2db40b3166023472501'
    }
  ]
}
Inserting new entry to table Credentials
Done!
```

### Create a challenge object

Now we can use the verifiable credential obtained above, to create verifiable presentations for verifiers.

A verifier first presents a challenge. Call the following endpoint on the verifier service to obtain the challenge object:

```
curl 'http://localhost:8000/api/v1/challenges' -H 'Content-Type: application/json' \
--data-raw '{
    "credentialSubject": {
        "birthday": {
            "$lt": 20021010
        }
    },
    "context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
    "type": "KYCAgeCredential"
}'

{"id":"2a5b1926-b1c3-4c6a-b732-a01e6796474b","typ":"application/iden3comm-plain-json","type":"https://iden3-communication.io/authorization/1.0/request","thid":"2a5b1926-b1c3-4c6a-b732-a01e6796474b","body":{"callbackUrl":"http://localhost:8000/api/v1/verify?threadId=2a5b1926-b1c3-4c6a-b732-a01e6796474b","reason":"challenge","message":"482110307","scope":[{"id":482110307,"circuitId":"credentialAtomicQuerySigV2","optional":true,"query":{"allowedIssuers":["*"],"context":"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld","credentialSubject":{"birthday":{"$lt":20021010}},"type":"KYCAgeCredential"}}]},"from":"did:iden3:tVE7RF655rj8Ws4rYCF2E32d46q575Gq2GHi2aKYf"}
```

Copy the response object above and use the QR encoder service to generate the QR code image.

Now you can use the `respond-to-challenge` command to generate a proof based on the verifiable credential downloaded previously, and respond to the verifier's endpoint encoded in the challenge object, in this case `http://localhost:8000/api/v1/verify?threadId=2a5b1926-b1c3-4c6a-b732-a01e6796474b`.

```console
$ node -r node-localstorage/register index.js --command respond-to-challenge --qrcode /Users/jimzhang/Downloads/qrcode.png
Using network: kaleido
Initializing SQLite DB
Respond to challenge
{
  "id": "2a5b1926-b1c3-4c6a-b732-a01e6796474b",
  "typ": "application/iden3comm-plain-json",
  "type": "https://iden3-communication.io/authorization/1.0/request",
  "thid": "2a5b1926-b1c3-4c6a-b732-a01e6796474b",
  "body": {
    "callbackUrl": "http://localhost:8000/api/v1/verify?threadId=2a5b1926-b1c3-4c6a-b732-a01e6796474b",
    "reason": "challenge",
    "message": "482110307",
    "scope": [
      {
        "id": 482110307,
        "circuitId": "credentialAtomicQuerySigV2",
        "optional": true,
        "query": {
          "allowedIssuers": [
            "*"
          ],
          "context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
          "credentialSubject": {
            "birthday": {
              "$lt": 20021010
            }
          },
          "type": "KYCAgeCredential"
        }
      }
    ]
  },
  "from": "did:iden3:tVE7RF655rj8Ws4rYCF2E32d46q575Gq2GHi2aKYf"
}
Existing identities: [
  {
    "identifier": "did:iden3:tNdgTFxGLkPXhXtppLZzsX7YJmE88aMbkPZusa3zH",
    "state": "8c97ea2b9562fcf44584a9e517ad2c142519f533e1bc5e5b02335c43043b222f",
    "published": 0,
    "genesis": 1
  }
]
Using identity at index: 0
eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6ImY5YzZmMDBlLTM0YzItNGY0My04MmQ5LWQ3MDIwMThlNThhNCIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zLXprcC1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiIyYTViMTkyNi1iMWMzLTRjNmEtYjczMi1hMDFlNjc5NjQ3NGIiLCJib2R5Ijp7Im1lc3NhZ2UiOiI0ODIxMTAzMDciLCJzY29wZSI6W3siaWQiOjQ4MjExMDMwNywiY2lyY3VpdElkIjoiY3JlZGVudGlhbEF0b21pY1F1ZXJ5U2lnVjIiLCJwcm9vZiI6eyJwaV9hIjpbIjE0NDg3NTAzOTk5Nzc2NjY1MTY1NTYzODU1NDk2MDY5NzYyOTI1OTEwOTg1NTUyNDg2NTcxNjE3Mzk4NjE4ODA3Nzc0NjI3NDEzMDE3IiwiMTczOTQ1NzY5NDUzOTYzNjM3MTM4MDc2NTc4MzcwMzk2MjU0MzMxMTU0MTQwNTA2MTMyMDY0NTQwMDI5MTM5OTY3MTg0Nzc2NTk2NzciLCIxIl0sInBpX2IiOltbIjM1MjUxNjM3NzY5NjY5MTkyMTEzODQ1NTM4NDQzODE0NjA5NDkxMzQwOTQzNjYyMTg0OTYxNzU4NDg4MTk5MTk3MDM0OTg3Mjg4NzkiLCIxMTkzNjU3NzkwMzc3NjI3NjY5Njg4MTYyOTQyMDg4NTQ4MjYzMTAzMDI0MTA4Mzc1NDExNzgwMzQ3NTg1NTgyMDExOTg1OTI2MjA4NSJdLFsiMTMxODMyMzExMjI3MTkzMzk0NDMxOTkzNDA3MDQ2NzU3MTU2NzIzNDAxNzcxMTc2NDI2ODAxNjUzMDExNjgzNzAwMjI0NDgyOTczOTciLCIxOTg5MzIwOTkxNjk5MjU3NTA0MjE0NzkyMjc1Mzg0ODk4MDkyOTE2MDU1OTIyMDc4MDcxNjk2NzU3Mjg4NTk1OTQ2Mjk3MDY4NzE3NyJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMTk3OTcwNzQ4NjY1NDEzNjc5MjE0MzE2Mzg4NDEzNjcwNTMwMjkzMDEzMzEwNTIwMDY4NzM0Njc4ODQwODI4MjAwNjc0NDYyNTY3NTMiLCI4NzA2MTcwOTkxNDkyNDQ5NTkzMjM4MTM2NjEyOTgzNTE0MTI2MDc1NjAwNjM5NzA2NjMwMzg0NDUwNTU5MDY4OTQ5ODk4NTgwNjgyIiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjEiLCIxOTA5MTUwMTExNzYxMjAxNTA0NjI1OTQ3NTMwMTkyMjQ0NTEzMTE1Mjk0ODU0MjI0NDg3OTYxMDE1MTI0MTA2NzQ0ODYzMTI5NyIsIjc2NDkxMDI4Mzc3OTY0MDg3NzQ1OTM2NTY2ODU1Nzc5NjA0Njc3MjQ3NDI1OTI4NjIzNDk3OTI4MzMzNDE1Mjk0NzAzMzUwMTEzNDciLCI0ODIxMTAzMDciLCIyMjg5MzU0ODU1NDM2MTc5NzM3MDI0MDY2MTU1NzM0Njc4MzE3OTYyNjcxODk5MDcxNDcwNTc4MTI2MTU0MTgxMzM2MDI2MzE2OSIsIjEiLCI3NjQ5MTAyODM3Nzk2NDA4Nzc0NTkzNjU2Njg1NTc3OTYwNDY3NzI0NzQyNTkyODYyMzQ5NzkyODMzMzQxNTI5NDcwMzM1MDExMzQ3IiwiMTY4OTI2NTQ0MyIsIjc0OTc3MzI3NjAwODQ4MjMxMzg1NjYzMjgwMTgxNDc2MzA3NjU3IiwiMCIsIjIwMzc2MDMzODMyMzcxMTA5MTc3NjgzMDQ4NDU2MDE0NTI1OTA1MTE5MTczNjc0OTg1ODQzOTE1NDQ1NjM0NzI2MTY3NDUwOTg5NjMwIiwiMiIsIjIiLCIyMDAyMTAxMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCJdfV19LCJmcm9tIjoiZGlkOmlkZW4zOnROZGdURnhHTGtQWGhYdHBwTFp6c1g3WUptRTg4YU1ia1BadXNhM3pIIiwidG8iOiJkaWQ6aWRlbjM6dFZFN1JGNjU1cmo4V3M0cllDRjJFMzJkNDZxNTc1R3EyR0hpMmFLWWYifQ.eyJwcm9vZiI6eyJwaV9hIjpbIjEwMTU4ODAxMTc3OTg1OTIwMzcxNTU1ODQyNjQ5NzkxNDAxMDE5ODMwODk4MDIyNjQ2Nzk4NzQ1MTUyMTIwMzAzNzY5NjQxNTg4MjMyIiwiMzI0NzQ0NzQ3NjU5MDI5Njc4NjgyMTU2NTExOTgyMzM0ODU4NzIzODA2NjA5MjE3ODM1NDk1MDQyMTQ4NTQ5MzI1NTQ1NTgxODgyMCIsIjEiXSwicGlfYiI6W1siMTcxMDcwOTc2MzA1NDc5MjUyNjk3MjUzNDgzMjYzMTczNjE4MzYyMTMwMTc1NjkyOTA0OTQwMjYxMjE0OTY5MjM1MDE4NjE3MjA4OTgiLCIxMDIxNzY5NDAzNTEyNDUwMzU3NTU4ODc0MTk4MjcwMzc5Mzg2NTgyNjY5MjkxNjA3Mzk1NjEzOTU3NTcxNDk4OTM3Mjc0NDUzNTIxMiJdLFsiMzI2NzY2NDE0MjQ4NjM5MjYwNjgxODcxMjc5NTg3MTkwMTE4NDg5MzAxNTUwMzE0ODA5OTg1NDkyNDE4NDc2MTQxMjY4NDAzMDMyMSIsIjEzNTQ5NDMzMTc5Nzc2NTIzNTE2NjU3MDA4MDA2MzM3NjUxNTM0MzYwMDUwODEzNjA4OTkzNTE5Mjg2ODU1MjU5MjkzODY0NzcyMjcwIl0sWyIxIiwiMCJdXSwicGlfYyI6WyIxNzI1MjQ0NjM2MzA0MjEzMDM4Nzk5OTc4MzY3MzA3MTU2NjgyNTIzNzIxMTM1ODA0MzQ0MDM5NzYyMjk3Njc1NjI0NTYyNjI2ODI4NiIsIjE2MjQ1NjM3NzM1MjQ3ODkwMzc2OTI4MjAzNjU4MDA5NDE1MTAyMDc1NzcxODU0MDE0MTk2NzAzMTkwOTIxMjE3MjQ1MDA5NzI1MzM3IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjE5MDkxNTAxMTE3NjEyMDE1MDQ2MjU5NDc1MzAxOTIyNDQ1MTMxMTUyOTQ4NTQyMjQ0ODc5NjEwMTUxMjQxMDY3NDQ4NjMxMjk3IiwiOTY3OTYxMTQwOTQ1ODc4NjgwNjgyMTYzMjg1MzQ2MDg0ODA5ODQ1Mjc2MzY4ODQxODQyMjMwMTAwNTE1NTMyMDg0MzIzMTAzODc1NyIsIjEwNjgwMjcxMDQ0Nzc4NDk0MTEyOTU4MzQ0NDE3MDE4NzUxNjMyMTg5ODg4MDAwNDk3Njc5NzUxNDQ1NDYzNzQ1MTUxMDg2Mzg2NTgiXX0
{
  id: 'f9c6f00e-34c2-4f43-82d9-d702018e58a4',
  typ: 'application/iden3-zkp-json',
  type: 'https://iden3-communication.io/authorization/1.0/response',
  thid: '2a5b1926-b1c3-4c6a-b732-a01e6796474b',
  body: { did_doc: undefined, message: '482110307', scope: [ [Object] ] },
  from: 'did:iden3:tNdgTFxGLkPXhXtppLZzsX7YJmE88aMbkPZusa3zH',
  to: 'did:iden3:tVE7RF655rj8Ws4rYCF2E32d46q575Gq2GHi2aKYf'
}
Sending the challenge response to callback URL: http://localhost:8000/api/v1/verify?threadId=2a5b1926-b1c3-4c6a-b732-a01e6796474b
Success response from the verifier server: {"status":200,"message":true}
Done!
```

Congratulations! Now you have completed the end to end flow of a Decentralized Identity use case.

For further reading:

- Polygon ID: [https://0xpolygonid.github.io/tutorials/](https://0xpolygonid.github.io/tutorials/)
- iden3 protocol: [https://docs.iden3.io/protocol/spec/](https://docs.iden3.io/protocol/spec/)
