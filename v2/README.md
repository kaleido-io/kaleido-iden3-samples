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
  'Verifier contract deployed to address 0x8e5B9441176c9267877c5be097b703084c9A7a40 from 0x58a95936ABbF7dAb6A4a48e6ae8e8BD0D0f87A88'
]
[ 'deploying poseidons...' ]
Poseidon1Elements deployed to: 0xffABf502ABeC4bd826d787D2115D94621AEceF73
Poseidon2Elements deployed to: 0x5AdE200728D5FCfaFb08958374B7E1CCbF0F8a71
Poseidon3Elements deployed to: 0x2d838327e75CF43A82B61Ca55266074F1c03B24e
[ 'deploying SMT...' ]
[ 'Smt deployed to:  0xdc7D27f232F7786c9d6305df46Ff5EFBd7B1692e' ]
[ 'deploying stateV2...' ]
Warning: Potentially unsafe deployment of StateV2

    You are using the `unsafeAllow.external-library-linking` flag to include external libraries.
    Make sure you have manually checked that the linked libraries are upgrade safe.

[
  'StateV2 contract deployed to address 0xd94Dae61E4A337C526527a79BB222f67C2fB6B81 from 0x58a95936ABbF7dAb6A4a48e6ae8e8BD0D0f87A88'
]
[ '======== StateV2: deploy completed ========' ]
```

Take note of the state contract address from the above output, in this case `0xd94Dae61E4A337C526527a79BB222f67C2fB6B81`.

## Issuer Server

The issuer server is made up of a number of microservices:

- issuer server: API server for managing identities and verifiable credentials
- pending state publisher: when there are new states in the issuer's merkle trees, that requires the global state to be updated on the blockchain, this service is responsible for checking and sending transactions to update the onchain state
- postgres DB: persistence for identities, credentials, merkle trees, etc
- redis: persistent cache for loading schemas
- Hashicorp vault: managing private keys for each identity

### Building the issuer server

Checkout the `v1.0.1` tag of the issuer server implementation from [https://github.com/0xPolygonID/sh-id-platform](https://github.com/0xPolygonID/sh-id-platform).

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

### Launch the issuer service

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
token:hvs.1pzenz8dba3ogukEijLYuc60
```

Take note of the token string above, in this case `hvs.1pzenz8dba3ogukEijLYuc60`.

Now we are ready to launch the rest of the issuer service containers:

```console
$ export KEY_STORE_TOKEN=hvs.1pzenz8dba3ogukEijLYuc60
$ export KALEIDO_NODE_URL=<full URL to a Kaleido node RPC endpoint, including app creds>
$ export STATE_CONTRACT=<state contract address from the deploy task above>
$ docker compose up -d
```

### Create an issuer identity

Use the following HTTP request to create an identity in the issuer service (with basic auth using `user:password`):

```
curl 'localhost:3001/v1/identities' -H 'Authorization: Basic dXNlcjpwYXNzd29yZA==' -H 'Content-Type: application/json' \
--data-raw '{
    "didMetadata": {
        "method": "iden3"
    }
}'

{
    "identifier": "did:iden3:tPEsstk9vxvKHt6jY1sHgRjPvDHG4hY9WykfXJxdY",
    "state": {
        "claimsTreeRoot": "bc833e0c9fcf90647b57447736c8241a9cf9d6cf13caba415c0a3cb487ac3d01",
        "createdAt": "2023-03-25T19:23:59.482966Z",
        "modifiedAt": "2023-03-25T19:23:59.482966Z",
        "state": "218c4f6fd1705b0892df5c4a7a1b0e8c930687a5acb98e3311d46aab852c4e29",
        "status": "confirmed"
    }
}
```

Take note of the `identifier`, which is the DID for the issuer to be used in subsequent steps.

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
  ethContractAddress: '0xd94Dae61E4A337C526527a79BB222f67C2fB6B81'
  publicHost: http://localhost:8000
  self: did:iden3:tPEsstk9vxvKHt6jY1sHgRjPvDHG4hY9WykfXJxdY
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
Initialing SQLite DB
Initializing state contract
=> Creating temporary issuer identity
=> Creating temporary holder identity
=> Issuing a credential
=> Saving the new credential to the credential wallet
=> Adding the new credential to the merkle tree
=> Publishing the new state to the revocation service
=> Uploading the new state to blockchain
	Transaction ID: 0x4a7b049e49dc5f6747e0cb2b07a449221b7c132ac6ba7f7b7d90b3e9b8cf0d20
Done!
```

### Creating the wallet identity

```console
$ node -r node-localstorage/register index.js --command create-id
Initialing SQLite DB
Creating identity
{
  identifier: 'did:iden3:tJNHfqXTe2UriBsU6MHXd3GJjfG1ZXw5FsDRNBaGa',
  state: Hash {
    bytes: Uint8Array(32) [
       58, 164, 180, 186, 121,   5,   7, 208,
      143, 242, 143,  72, 230, 199,  49,   2,
       16,  12,  29, 183, 145, 137, 105, 181,
      169,  45, 184,  61, 217, 120,  15,  34
    ]
  },
  published: false,
  genesis: true
}
Inserting new entry to table Identities
W3CCredential {
  id: 'http://mytestwallet.com/73439e98-d2c8-4f95-9b6e-4a04c3a35cb1',
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    'https://schema.iden3.io/core/jsonld/iden3proofs.jsonld',
    'https://schema.iden3.io/core/jsonld/auth.jsonld'
  ],
  type: [ 'VerifiableCredential', 'AuthBJJCredential' ],
  expirationDate: undefined,
  issuanceDate: '2023-03-25T21:15:24.697Z',
  credentialSubject: {
    x: '13968967984666922088410190353462299620605959288164538184809184441187219881010',
    y: '6378993877653513474069166764522801044874345334148347940207106278412088343769',
    type: 'AuthBJJCredential'
  },
  issuer: 'did:iden3:tJNHfqXTe2UriBsU6MHXd3GJjfG1ZXw5FsDRNBaGa',
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
      coreClaim: 'cca3371a6cb1b715004407e325bd993c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000323c354e737f2179eaf43910a3db1352fc4d920f2ba30790e225c1acdb27e21ed97c2dc081f1531a2b980b158c8f64351cfe0306ee18400d18c20b43f1611a0e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    }
  ]
}
Inserting new entry to table Credentials
=============== user did ===============
did:iden3:tJNHfqXTe2UriBsU6MHXd3GJjfG1ZXw5FsDRNBaGa
Done!
```

Take note of the user DID string above, which is used as the holder DID in subsequent steps.

### Issue a credential

Call the following issuer service API to issue a verifiable credential for the holder identity. For this call we are using the following identities:

- issuer: `did:iden3:tPEsstk9vxvKHt6jY1sHgRjPvDHG4hY9WykfXJxdY`
- holder: `did:iden3:tJNHfqXTe2UriBsU6MHXd3GJjfG1ZXw5FsDRNBaGa`

```
curl 'localhost:3001/v1/did:iden3:tPEsstk9vxvKHt6jY1sHgRjPvDHG4hY9WykfXJxdY/claims' -H 'Authorization: Basic dXNlcjpwYXNzd29yZA==' -H 'Content-Type: application/json' \
--data-raw '{
  "credentialSchema": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v3.json",
  "type": "KYCAgeCredential",
  "credentialSubject": {
    "id": "did:iden3:tJNHfqXTe2UriBsU6MHXd3GJjfG1ZXw5FsDRNBaGa",
    "birthday": 19960424,
    "documentType": 2
  },
  "expiration": 1910106487
}'

{
    "id": "8f760167-cb52-11ed-878c-0242ac190006"
}
```

### Download the credential to the wallet

To download the credential to the wallet, first generate a QR code for the **credential offer** object that the issuer service uses to interact with the wallet. The QR code encodes the object that contains the ID of the credential. The wallet must authenticate itself with the issuer service, by demonstrating its possession of the private key corresponding to the holder DID, in order to obtain the credential itself.

First call the issuer API to obtain the credential offer object:

```
curl 'localhost:3001/v1/did:iden3:tPEsstk9vxvKHt6jY1sHgRjPvDHG4hY9WykfXJxdY/claims/8f760167-cb52-11ed-878c-0242ac190006/qrcode' -H 'Authorization: Basic dXNlcjpwYXNzd29yZA=='

{
    "body": {
        "credentials": [
            {
                "description": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld#KYCAgeCredential",
                "id": "8f760167-cb52-11ed-878c-0242ac190006"
            }
        ],
        "url": "http://localhost:3001/v1/agent"
    },
    "from": "did:iden3:tPEsstk9vxvKHt6jY1sHgRjPvDHG4hY9WykfXJxdY",
    "id": "f2066d69-7f11-42c2-b0b9-70448e400649",
    "thid": "f2066d69-7f11-42c2-b0b9-70448e400649",
    "to": "did:iden3:tJNHfqXTe2UriBsU6MHXd3GJjfG1ZXw5FsDRNBaGa",
    "typ": "application/iden3comm-plain-json",
    "type": "https://iden3-communication.io/credentials/1.0/offer"
}
```

Copy the JSON output of the request, plug it into a QR code encoder, such as [https://goqr.me/](https://goqr.me/) to encode it into a QR code image. Make sure to use a large enough (such as 800 x 800) image to provide the resolution needed for the dense information. Download the QR code image.

Use the `fetch-credential` command to download the credential from the issuer service. The wallet sample code will generate an authentication proof (for the `authV2` circuit) and send it to the endpoint contained in the credential offer object above (`http://localhost:3001/v1/agent` in this case). The issuer service verifies the proof to authenticate the wallet, and returns the promised credential identified by the `body.credentials[0].id` value.

```console
$ node -r node-localstorage/register index.js --command fetch-credential --qrcode /Users/jimzhang/Downloads/qrcode.png
Initialing SQLite DB
Downloading offered verifiable credentials
Existing identities: [
  {
    "identifier": "did:iden3:tJNHfqXTe2UriBsU6MHXd3GJjfG1ZXw5FsDRNBaGa",
    "state": "3aa4b4ba790507d08ff28f48e6c73102100c1db7918969b5a92db83dd9780f22",
    "published": 0,
    "genesis": 1
  }
]
{
  id: 'http://localhost:3001/v1/did:iden3:tPEsstk9vxvKHt6jY1sHgRjPvDHG4hY9WykfXJxdY/claims/8f760167-cb52-11ed-878c-0242ac190006',
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    'https://schema.iden3.io/core/jsonld/iden3proofs.jsonld',
    'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld'
  ],
  type: [ 'VerifiableCredential', 'KYCAgeCredential' ],
  expirationDate: '2023-03-29T11:01:49Z',
  issuanceDate: '2023-03-25T21:18:17.298604262Z',
  credentialSubject: {
    birthday: 19960424,
    documentType: 2,
    id: 'did:iden3:tJNHfqXTe2UriBsU6MHXd3GJjfG1ZXw5FsDRNBaGa',
    type: 'KYCAgeCredential'
  },
  credentialStatus: {
    id: 'http://localhost:3001/v1/did%3Aiden3%3AtPEsstk9vxvKHt6jY1sHgRjPvDHG4hY9WykfXJxdY/claims/revocation/status/1230256121',
    revocationNonce: 1230256121,
    type: 'SparseMerkleTreeProof'
  },
  issuer: 'did:iden3:tPEsstk9vxvKHt6jY1sHgRjPvDHG4hY9WykfXJxdY',
  credentialSchema: {
    id: 'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v3.json',
    type: 'JsonSchemaValidator2018'
  },
  proof: [
    {
      type: 'BJJSignature2021',
      issuerData: [Object],
      coreClaim: 'c9b2370371b7fa8b3dab2a5ba81b68382a00000000000000000000000000000001000507d08ff28f48e6c73102100c1db7918969b5a92db83dd9780f228a0b00818aaca70fe8036010d218aaa887eeed97bb2e1ccc89763371592e7ff993b70d0000000000000000000000000000000000000000000000000000000000000000f9375449000000009d1a24640000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
      signature: 'ca78d0f67328072775236007549685346eae8287094918dda15bdb77063db582074d3d417174ce1c64a0032846218feff1700d6b382da4d1feec1313eaceac00'
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

{
    "id": "3f0e0882-60da-4eda-baf3-79476402d6f5",
    "typ": "application/iden3comm-plain-json",
    "type": "https://iden3-communication.io/authorization/1.0/request",
    "thid": "3f0e0882-60da-4eda-baf3-79476402d6f5",
    "body": {
        "callbackUrl": "http://localhost:8000/api/v1/verify?threadId=3f0e0882-60da-4eda-baf3-79476402d6f5",
        "reason": "challenge",
        "message": "3206975992",
        "scope": [
            {
                "id": 3206975992,
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
    "from": "did:iden3:tTjhYsRM2B6fbbsuQhubfPkQiUrGwYY6QEznBQxn6"
}
```

Copy the response object above and use the QR encoder service to generate the QR code image.

Now you can use the `respond-to-challenge` command to generate a proof based on the verifiable credential downloaded previously, and respond to the verifier's endpoint encoded in the challenge object, in this case `http://localhost:8000/api/v1/verify?threadId=3f0e0882-60da-4eda-baf3-79476402d6f5`.

```console
$ node -r node-localstorage/register index.js --command respond-to-challenge --qrcode /Users/jimzhang/Downloads/qrcode.png
Initialing SQLite DB
Respond to challenge
{
  "id": "3f0e0882-60da-4eda-baf3-79476402d6f5",
  "typ": "application/iden3comm-plain-json",
  "type": "https://iden3-communication.io/authorization/1.0/request",
  "thid": "3f0e0882-60da-4eda-baf3-79476402d6f5",
  "body": {
    "callbackUrl": "http://localhost:8000/api/v1/verify?threadId=3f0e0882-60da-4eda-baf3-79476402d6f5",
    "reason": "challenge",
    "message": "3206975992",
    "scope": [
      {
        "id": 3206975992,
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
  "from": "did:iden3:tTjhYsRM2B6fbbsuQhubfPkQiUrGwYY6QEznBQxn6"
}
Existing identities: [
  {
    "identifier": "did:iden3:tUGcefebfyaMiWY12yCKAJ3nxSncA8LBHnamP8TS5",
    "state": "4370790035df27a5a5868af6e39336dc392db88d15662840eae6a9e7c602b52e",
    "published": 0,
    "genesis": 1
  }
]
Using identity at index: 0
eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6ImQ2ODNiODFmLWIzZDMtNGQ3Ny1iNTBiLWI5Zjc1ODM2YTA5MSIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zLXprcC1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI2M2Y5ZDZkNi01YzdlLTRmYWQtYmRiNi0zYThmNWE0ZGZhZGYiLCJib2R5Ijp7Im1lc3NhZ2UiOiIzMTkyMzM1NjQzIiwic2NvcGUiOlt7ImlkIjozMTkyMzM1NjQzLCJjaXJjdWl0SWQiOiJjcmVkZW50aWFsQXRvbWljUXVlcnlTaWdWMiIsInByb29mIjp7InBpX2EiOlsiNTcwMTU5NjQzMzc1MjU1MTQ0MjU0MTQ5Nzk1OTkxMTIyNzc2OTgyNjU4OTI4NTgwODY2ODgyODk4NjIyMjgxODMyNDcxMTE5NTcxMiIsIjExODM1NTk5MzMwODc0NjQwNzE3NjkzMTgxMTIzNzQwOTY4NDA5NTI5MjAyNDEwOTkxMTI5NTUzMDMwODQ1ODAzMDE5NzA5MzI2NTM5IiwiMSJdLCJwaV9iIjpbWyI4NjE3MDA5NTkxMjg0MzYzOTcxMjI1NjkyMDk0NTcyMTExNjU4MzA2MjQ5NjA4Mzk5MjA2NjcyNzQxMzYyMDE5MzY5MDkwMzkyMTk0IiwiNTAxMTQxMzE5MDIyMzA5MzkwODcyNjIxODEyNTA4MDMwMjM2NzMwMDc5NzY4MDc4MTgwODUyMjc5OTI0NTM3MzA5NDIwMjc2NzI1MyJdLFsiMTg1MTA4MzgwMTI0MjE4OTA4Njg0MTI2Mjk5NjE0NTUyMDE0NjYyMzY4OTA5ODIzMTI3NzIzNDcwNzk1NzgzNTc5NDEzNzExMzk0MDkiLCIzMTIxNDc2MjM5NTUyMTc1MzMzMDEzMDU1NTcyNzgxNDk5MTI4NzQzOTYzMTE0NDI4MDM3OTExOTM3Mjc3NjY4MzYyMjU5NDU3NzI1Il0sWyIxIiwiMCJdXSwicGlfYyI6WyIyMDMzNzYxNzg3MDQ0NzE5ODkzODEyNjAzODMyNTY5NTYyNzQzODk1MTQ0NzMzOTAyNzQxOTcxMzU5NDQyNzAwMTMwMzg3MTkxNzQyNyIsIjIwNjU1NjQ5MzAyNTExNDA2NTAyODUzOTE3OTkxODA4MjAwMTc5MDA2NTE2MzAzNTAxNTU3Mjc0NDEzMjkwODU2ODIwNjg4MDQ2MjYzIiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjEiLCIyNTU2NTMyNzY4ODcyNjEwOTM5NDg0OTY0OTYwMDc1NjYyNDQyODA2MjM1NTA1NjgzNTgxMTEyMDc1MTI0ODEwOTEwMDUzMTcxMyIsIjE4NjgyOTQ4MTQzNTMxMTQ5OTQxNzg4MTE3NjE0MTEyMjE0NzgyNjkyOTg1ODE4MDIyODUzMTg0NDY3Njk5NDk3ODg2NTk5MzE4NTYxIiwiMzE5MjMzNTY0MyIsIjE5NzA1NTk5NDEwNTc0NTExODMxMDU5Mjc0MDk2MzM1MDU4NzU2ODIwNDcwMDQ3MzY3OTIwNDY5MzkzNDgzOTk4ODk5OTk0NjI1IiwiMSIsIjE4NjgyOTQ4MTQzNTMxMTQ5OTQxNzg4MTE3NjE0MTEyMjE0NzgyNjkyOTg1ODE4MDIyODUzMTg0NDY3Njk5NDk3ODg2NTk5MzE4NTYxIiwiMTY3OTg4MTk4NCIsIjc0OTc3MzI3NjAwODQ4MjMxMzg1NjYzMjgwMTgxNDc2MzA3NjU3IiwiMCIsIjIwMzc2MDMzODMyMzcxMTA5MTc3NjgzMDQ4NDU2MDE0NTI1OTA1MTE5MTczNjc0OTg1ODQzOTE1NDQ1NjM0NzI2MTY3NDUwOTg5NjMwIiwiMiIsIjIiLCIyMDAyMTAxMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCJdfV19LCJmcm9tIjoiZGlkOmlkZW4zOnRVR2NlZmViZnlhTWlXWTEyeUNLQUozbnhTbmNBOExCSG5hbVA4VFM1IiwidG8iOiJkaWQ6aWRlbjM6dFRqaFlzUk0yQjZmYmJzdVFodWJmUGtRaVVyR3dZWTZRRXpuQlF4bjYifQ.eyJwcm9vZiI6eyJwaV9hIjpbIjc0MjY4MTY2MDkyMzU4OTQzNDY5OTIxMDk4MDMxMjMyMDcyMTYyODU4MTM4NjEzNDMyNzk2MDE1MjU4ODI1NzMwMDI5NTQ5MDAwODUiLCIxODc0MzcwODQ0MTQyOTM4MjY2NzQ2MjYwNjU5MTk3MjI0NDc3NDUzMjQ1OTUxNjEwMTYyMTA5Mjc1NjE2OTg1Nzk0ODQ2Nzk1MjY2MSIsIjEiXSwicGlfYiI6W1siMjA2MzQ5MzMyNTEzNDk4Njk5MDM5MDA4ODczODYzMjkzNjU3NjMwMjE5OTU1ODQzMzQ4MzI0MTE2MDc2MTI1NTAwODkzMzgwNjA3MDYiLCIxNDkyNDI3OTA5ODQxNzEzNzAyNTk3MTQ4ODIzNTk1Njk3NjU1NTE5MDk0Mjg0MzQ1Mjg1NTEwMzgyNzc1MTY5NTI3NDAzMTg0NzYwOCJdLFsiMTIzODc4ODM1ODk5MzI0ODYyODA2MjI4MDEwMDgyNDMwOTczNTk3NDA5MjgyNjI2NDUzMjY5Nzk4NTgwNTI3NDYxNjI4NDYwMzIxNjgiLCIxOTU3Nzk1MzExMjYzMDQ1Njc2MTcwODI5MTE0NjU5OTIzOTM3NjA0NzE0NTQwMDgxMjYxNTcxODQ2MTQ2NzgzMzMyMzU3NTU4MTgxNSJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMTIyNDg3NDcwNTk4MTI0Njg1MTQyNjMyMjk3NTM4MzM3MTI3NzkzODYzMTI3ODEyMDk4OTc3NDIxNzEzODIyMzk5MjgxNzA2OTg3MjciLCIxOTcwMDQ5ODk5ODkxNDU5NzI0MjI4MzY2MjYzNjIyMTI1NzI5NzI5NTI2ODk1MTYxNDM5OTE5NzY5NDU0Nzk2NTYzNjg0NDU2ODE2NCIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2IiwiY3VydmUiOiJibjEyOCJ9LCJwdWJfc2lnbmFscyI6WyIyNTU2NTMyNzY4ODcyNjEwOTM5NDg0OTY0OTYwMDc1NjYyNDQyODA2MjM1NTA1NjgzNTgxMTEyMDc1MTI0ODEwOTEwMDUzMTcxMyIsIjgwNDcxMjk1NzE5MjcwMjkxNjc4NTE0OTIwOTYzNTMxNjI0MjkyNjQzNzk3Mjc2Mjk0MDk4Mzc5OTczNjIyOTQ2NDYxMTU0OTEzNjUiLCIxODUwNzA0NzM1MTczMjU2MDQyNzU0Mjg2OTc5NTU4MzUyMjEwMjMzMzAwOTU0MDMwMzAyNTkzMDc2MDkwNjA3ODE3NzY1NzY3NTI0MSJdfQ
{
  id: 'd683b81f-b3d3-4d77-b50b-b9f75836a091',
  typ: 'application/iden3-zkp-json',
  type: 'https://iden3-communication.io/authorization/1.0/response',
  thid: '63f9d6d6-5c7e-4fad-bdb6-3a8f5a4dfadf',
  body: { did_doc: undefined, message: '3192335643', scope: [ [Object] ] },
  from: 'did:iden3:tUGcefebfyaMiWY12yCKAJ3nxSncA8LBHnamP8TS5',
  to: 'did:iden3:tTjhYsRM2B6fbbsuQhubfPkQiUrGwYY6QEznBQxn6'
}
Sending the challenge response to callback URL: http://localhost:8000/api/v1/verify?threadId=3f0e0882-60da-4eda-baf3-79476402d6f5
Success response from the verifier server: {"status":200,"message":true}
Done!
```

Congratulations! Now you have completed the end to end flow of a Decentralized Identity use case.

For further reading:

- Polygon ID: [https://0xpolygonid.github.io/tutorials/](https://0xpolygonid.github.io/tutorials/)
- iden3 protocol: [https://docs.iden3.io/protocol/spec/](https://docs.iden3.io/protocol/spec/)
