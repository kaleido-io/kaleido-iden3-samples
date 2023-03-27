# kaleido-iden3-samples

Sample code for using the [Iden3 protocol](https://docs.iden3.io/protocol/spec/) to issue verifiable claims and verify them.

This is the v1 version of the iden3 protocol. It doesn't have support for the [w3c verifiable credentials](https://www.w3.org/TR/vc-data-model/) standard. That support is introduced in the [v2](/v2) version of the protocol.

# Getting Started

The sample covers the 3 roles involved in a typical Self Sovereign Identity use case:

- **Issuer**: to create their own identity and issue claims to a target holder
- **Holder**: to create their own identity, receive a claim issued by the issuer, and generate a proof for the claim when challenged by the verifier
- **Verifier**: to challenge the holder for the proof of their possession of a claim, by using a zero knowledge query

The iden3 protocol relies on zkSNARK for generating zero knowledge proofs at various stages of the end to end user flow:

- state transition: [this circuit](https://github.com/iden3/circuits/blob/master/circuits/lib/stateTransition.circom) is used for publishing the state transition of the identity state to the State contract.
  - The file `issuer/upload-claims/scripts/snark/circuit_final.zkey` is the output of the trusted setup ceremony for this circuit based on the power of tau parameters `powersOfTau28_hez_final_16.ptau` described here: https://github.com/iden3/snarkjs/blob/master/README.md#7-prepare-phase-2
  - The file `issuer/upload-claims/scripts/snark/circuit.wasm` is the output of the circuit compiler from the state transition circuit
- claim proof: [this circuit](https://github.com/iden3/circuits/blob/master/circuits/lib/query/credentialAtomicQuerySig.circom) is used for verifying the claim query proof
  - The file `holder/snark/circuit_final.key` is the output of the trusted setup ceremony for this circuit based on the power of tau parameters `powersOfTau28_hez_final_16.ptau` described here: https://github.com/iden3/snarkjs/blob/master/README.md#7-prepare-phase-2
  - The file `holder/snark/circuit.wasm` are the output of the circuit compiler

> The zkp generation code in this sample uses the `groth16` library under the cover, which requires circuit-specific trusted setup. That's why we have different proving keys (the `.zkey` files) and verification keys (the `verification_keys.json` files) for each of the circuits described above

## Before you start

All of the files generated while following this tutorial will be stored in a single directory. You can specify the directory to use using the following command, the directory will be created if it doesn't exist:

```bash
export IDEN3_WORKDIR=~/gitrepos/kaleido-iden3-samples/iden3
```

**NB: don't forget to run this command in new terminal windows, you can add it to your bash/zsh profile to avoid repeating**

`IDEN3_WORKDIR` is default to `~/iden3` if it's not set manually.

## Create an Identity

The issuer and the holder must first create their identities. This is accomplished with the Golang program in the `identity` folder, with the subcommand `init`.

```
$ go run main.go init --name JohnDoe
```

Example output:

```
Generating new signing key from the "babyjubjub" curve
-> Private key written to file: $IDEN3_WORKDIR/JohnDoe/private/keys/defaultKey.key
Generating genesis state for the identity
-> Create the empty claims merkle tree
-> Create the empty revocations merkle tree
-> Create the empty roots merkle tree
-> Issue an authentication claim for the identity
   -> Add the new auth claim to the claims tree
   -> Persisting claim to $IDEN3_WORKDIR/JohnDoe/private/claims/authClaim-ca938857241db9451ea329256b9c06e5-defaultKey.json
-> ID of the generated identity: 112Hiyq6QNpGvf6fDrSZSp21ijniWvCtfqMjkQrijq
-> Identity's genesis state written to file: $IDEN3_WORKDIR/JohnDoe/private/states/genesis_state.json
Generating state transition inputs
-> State transition inputs written to file: $IDEN3_WORKDIR/JohnDoe/private/states/stateTransition_inputs.json
-> Old and new tree states written to file: $IDEN3_WORKDIR/JohnDoe/private/states/treeStates.json
```

For each identity, the program creates the following resources under the `$IDEN3_WORKDIR` folder:

- identity name (e.g. `JohnDoe/`): this folder holds the resources specific to the identity, including:
  - `private`: this folder stores private resource of the identity
    - `keys`: this folder stores all private keys owned by the identity (on the [Baby Jubjub](https://docs.iden3.io/getting-started/babyjubjub/) curve). Keys are strictly private data and must only be accessed by the owning identity.
    - `claims`: this folder stores all claims that are issued by the identity when acting as an **Issuer**. Copies of claims will be distributed to different identities upon requests.
    - `received-claims` this folder stores all claims that are issued to the identity when acting as a **Holder**.
    - `states` this folder contains all the identity states information.
      - `genesis_state.json ` genesis state of the identity, including its public user ID, a base58 encoded string, and the issuer identity's own authentication claim ([schema](https://github.com/iden3/claim-schema-vocab/blob/main/schemas/json-ld/auth.json-ld) here)
      - `treeStates.json` if present, this indicate the latest identity state needs to be updated in the registry (a state smart contract is used for this tutorial as the registry). It stores the old and new identity states.
      - `stateTransition_inputs.json` the inputs to generate a zero knowledge proof for the state transition method on the smart contract that maintains the public registry of issuer identities. Input file for [Proof Generation and Update OnChain State](#proof-generation-and-update-onchain-state).
    - `claims.db`: sqlite DB files that store the Claims tree of the identity.
  - `public` this folder stores public resource of the identity that needs to be shared in a public storage for real time verification
    - `revocations.db`: sqlite DB files that store the Revocation tree of the identity.
    - `roots.db`: sqlite DB files that store the Roots tree of the identity.
- `identities.json`: this file contains a lookup table of identity name and IDs. It gets updated whenever a new identify is created.

Use the `init` subcommand to generate at least two identities, one as the issuer, and one as the holder. The sections below use JohnDoe as the issuer and AliceWonder as the holder, so create an identity for AliceWonder and take note of the ID:

```
$ go run main.go init --name AliceWonder
```

## Issuer Publishes Identity State to a Registry

The identity state of the issuer should be published to a registry so that verifiers can use it to validate claims. A smart contract based registry has been provided and can be deployed using the Hardhat script.

The Iden3 `State.sol` contract, and its dependencies, implements an identity registry. An issuer should register its identity state with the contract, by calling the `transitState()` function, which requires a zero knowledge proof of the addition of the auth claim of the issuer to the Merkle tree.

### Publish the Iden3 State contract

To publish the State contract, use the `deploy.js` script in the Hardhat project in the folder `issuer/upload-claims`.

Set the environment variable `KALEIDO_NODE_URL` to the full RPC URL of a Kaleido node, including the basic auth credentials. For example:

```
export KALEIDO_NODE_URL=https://username:password@u0nc4noce4-u0c5qcrhgs-rpc.us0-aws.kaleido.io
```

> You can also use the Polygon Mumbai test network as the target, with `--network mumbai`. Set the environment variables `MUMBAI_NODE_URL` and `MUMBAI_PRIV_KEY` accordingly. If you use this option, there's no need to deploy the smart contract. You can use the contract that's already been deployed to Mumbai.

```shell
$ npx hardhat run scripts/deploy.js --network kaleido
```

Example output:

```
deploying verifier
deploying state
Verifier contract deployed to 0x874AEd7b9949E70F2542da6A85A0bCa0360293d0 from 0xe78A015f45C5B7e056AD09981689B5DE3d21892B
State contract deployed to 0xDE1E08008873DFF0536D0C0Feec7e62f76EB92ED from 0xe78A015f45C5B7e056AD09981689B5DE3d21892B
```

The result, in particular the State contract address, is persisted in a file (`$IDEN3_WORKDIR/deploy_output.json`) that will be read by the next program.

### Generate proof and update on-chain state

Next we want to publish the transition from the nil state to the genesis state, including the issuer's auth claim in the Merkle tree, to the [State smart contract](./issuer/upload-claims/contracts/State.sol). The smart contract function `transitState()` takes the public inputs (issuer ID, old state and new state) and the proof, verifies the proof and then updates the state for the issuer ID to the new state.

We use the snarkjs library to generate the state transition proof, from the nil state to the genesis state, and upload the states with the proof to the smart contract in order to update the onchain state for the identity.

This step uses the output of the Golang program as the input to the proof generation. It's based on a [pre-compiled circuit](https://github.com/iden3/circuits/blob/master/circuits/lib/stateTransition.circom) for the state transition.

For successful runs, the program may create new resources in the identify folder. Using JohnDoe as example:

- `$IDEN3_WORKDIR/iden3/JohnDoe`: this folder holds the resources specific to the identity:
  - `stateTransition_inputs_previous.json`: if a state transition is successfully applied, the input file `stateTransition_inputs.json` will be renamed to `stateTransition_inputs_previous.json`
  - `treeStates_previous.json`: if a state transition is successfully applied, the tree state record file `treeStates.json` will be renamed to `treeStates_previous.json`
  - `archived_transitions/` folder: when more than 2 state transitions have been executed, all historical transition input and tree states files will be archived into this folder with a timestamp prefix for record purpose.

With the `IDEN3_NAME` env var set to `JohnDoe`, we run the script to publish the state of JohnDoe on-chain. This identity will act as the issuer in later steps. In the `issuer/upload-claims` folder, run:

```
$ export IDEN3_NAME=JohnDoe
$ npx hardhat run scripts/upload-state-transition.js --network kaleido
```

Example output:

```
State before transaction:  0
{
  userID: '424127325476085530097027527790464006105059863140416092718486616524642320384',
  authClaim: [
    '304427537360709784173770334266246861770',
    '0',
    '7189210981809528877958741905387398770059833311092570463419735512875392060409',
    '8267109733201710561201549683759683736598648617480088118330896000807232010458',
    '5577006791947779410',
    '0',
    '0',
    '0'
  ],
  authClaimMtp: [
    '0', '0', '0', '0', '0', '0',
    '0', '0', '0', '0', '0', '0',
    '0', '0', '0', '0', '0', '0',
    '0', '0', '0', '0', '0', '0',
    '0', '0', '0', '0', '0', '0',
    '0', '0'
  ],
  authClaimNonRevMtp: [
    '0', '0', '0', '0', '0', '0',
    '0', '0', '0', '0', '0', '0',
    '0', '0', '0', '0', '0', '0',
    '0', '0', '0', '0', '0', '0',
    '0', '0', '0', '0', '0', '0',
    '0', '0'
  ],
  authClaimNonRevMtpAuxHi: '0',
  authClaimNonRevMtpAuxHv: '0',
  authClaimNonRevMtpNoAux: '1',
  newUserState: '20391223377548563843999554468270160170074387945389495727108408344433313723989',
  oldUserState: '20283203034931743047620932728057250760919164255176061329706088816149584979158',
  isOldStateGenesis: '1',
  claimsTreeRoot: '14348862092439901333875808663235006784593549561426356368822130600079254047494',
  revTreeRoot: '0',
  rootsTreeRoot: '0',
  signatureR8x: '5411014774652694612750517612049598053860196585568082902147216922321717675827',
  signatureR8y: '6819594267086286854454179927590467584271982427527056051219584512827205575675',
  signatureS: '1852796375311873305389450973150514943588140488907350945842333228638331101625'
}
Calculating witness...
Calculated witness successfully written to file $IDEN3_WORKDIR/JohnDoe/private/witness-3f004235ce3789125eb5.wtns
Successfully generated proof!
Invoking state transaction on chain ...
State after transaction:  20391223377548563843999554468270160170074387945389495727108408344433313723989
```

## Issuer Issues a Claim Via Signature

To issue a claim, go back to the `identity` folder and run the Golang program with the subcommand `claim`.

```
$ go run main.go claim --issuer JohnDoe --holder AliceWonder --indexDataA 19950704
```

Here,

- `--issuer JohnDoe` indicates to use the private key for `JohnDoe` as the issuer of the claim.
- `--holder AliceWonder` the name of the holder to issue the claim to.
- `--indexDataA 19950704` indicates to store number 19950704 into the indexDataSlot A of a claim structure.

Example output:

```
Using:
  issuer identity name: JohnDoe
  holder identity name: AliceWonder
  schema file: ./schemas/kyc.json-ld
  schema type: AgeCredential
  index data: [19950704 <nil>]
  value data: [<nil> <nil>]
  expiry date: <nil>
Loading issuer identity
Load the claims merkle tree
Load the revocations merkle tree
Load the roots merkle tree
Load holder identity in read only mode to figure out the ID
Load the claims merkle tree
Load the revocations merkle tree
Load the roots merkle tree
Creating the new claim
-> Schema hash for schema file './schemas/kyc.json-ld' and type 'AgeCredential': 681758df5afc8632bbf2e88995c26adb
Generating the non-membership proof of revocation tree
   -> Persisting claim to $IDEN3_WORKDIR/JohnDoe/private/claims/genericClaim-681758df5afc8632bbf2e88995c26adb-JohnDoe-defaultKey-AliceWonder.json
Generating the auth Proof of key: defaultKey and storing claim inputs for Signature Circuit
Claim issued by "JohnDoe" using key "defaultKey" is received by holder "AliceWonder" under path: $IDEN3_WORKDIR/AliceWonder/private/received-claims/genericClaim-681758df5afc8632bbf2e88995c26adb-JohnDoe-defaultKey-AliceWonder-via-signature.json
```

The issued claim is persisted in the folder `iden3/JohnDoe/private/claims`. The file name is `genericClaim-[schemaHash]-[issuer name]-[issuer key name]-[holder name].json`.

Note: since we are using signature-based proofs for claims, rather than MTP (Merkle Tree Proof)-based, there is no need to update the on-chain state for the newly issued claim.
With this approach, we only need to store the issuer's identity genesis state on-chain.

## Holder "Downloads" the Claim to their "Wallet"

A real holder's wallet is typically a mobile app. In this sample, we use the Golang program to manage the resources in the identity's dedicated folder, mimicking the holder's wallet.

Therefore, the Claim has already been downloaded into holder's private folders in the previous step.

The received claim is persisted in the folder `iden3/AliceWonder/private/received-claims`. The file name is `genericClaim-[schemaHash]-[issuer name]-[issuer key name]-[holder name]-via-signature.json`.

## Verifier Presents a Claim Challenge

The verifier wants to request the holder to present a proof for a condition that the verifier is interested in. The current communication between the verifier and the holder is conducted via QR code.

The verifier expresses the condition using the [Iden3 proof query language](https://docs.iden3.io/protocol/querylanguage/), wraps it in a request object, and encodes this in a QR code.

The QR code is presented in the verifier's web site, which the holder can scan to obtain the proof request. Based on the query request decoded from the QR code, the holder can then generate the proof accordingly.

Using a Kaleido blockchain as example, to launch the sample verifier's web site, go to the `verifier/server` folder and run:

```
$ npm i
$ node app.js --jsonrpc-url $KALEIDO_NODE_URL --state-contract 0xDE1E08008873DFF0536D0C0Feec7e62f76EB92ED
server running on port 8080
```

Here,

- `--jsonrpc-url` indicates the blockchain node for the state resolver to contact in order to get the latest state to verify the proof responses against
- `--state-contract` indicates the `State.sol` contract address that captures the issuer's latest state. (you can find the value of it in the `state` field in `~/iden3/deploy_output.json` file)

Point your browser at the URL `http://localhost:8080`, then click the "Sign In" button to display the QR code which encodes the proof request.

**Make sure you keep this server running so that the holder can respond to this login session in the last step**

Here's the sample proof request:

```json
{
  "id": "7f38a193-0918-4a48-9fac-36adfdb8b542",
  "thid": "7f38a193-0918-4a48-9fac-36adfdb8b542",
  "from": "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ",
  "typ": "application/iden3comm-plain-json",
  "type": "https://iden3-communication.io/authorization/1.0/request",
  "body": {
    "reason": "test flow",
    "message": "12345",
    "callbackUrl": "http://5c8e-208-1-60-238.ngrok.io/api/callback?sessionId=1",
    "scope": [
      {
        "id": 1,
        "circuit_id": "credentialAtomicQuerySig",
        "rules": {
          "query": {
            "allowedIssuers": ["*"],
            "schema": {
              "type": "KYCAgeCredential",
              "url": "https://github.com/kaleido-io/kaleido-iden3-samples/blob/main/identity/schemas/test.json-ld"
            },
            "req": {
              "birthdate": {
                "$lt": 20000101
              }
            }
          }
        }
      }
    ]
  }
}
```

## Holder Responds to the Claim Challenge

Now, acting as the holder, we can use the Golang program's `respond-to-challenge` subcommand to generate the necessary inputs for the zero knowledge proof, responding to the challenge by the verifier. In the sample code, the challenge was for a proof that the age claim has a `birthdate` attribute with a value less than `20000101`.

Before running the command, save the QR code image from the web site to a **PNG or JPEG file** (in the real world, the holder would use the wallet app to scan the QR code).

```
$ go run main.go respond-to-challenge --holder AliceWonder --qrcode /Users/alice/Downloads/challenge-qr.png
```

Here,

- `--holder AliceWonder` indicates to use the private key and the Merkle tree of the identity `AliceWonder`,
- `--qrcode <file>` indicates to decode the proof request from the QR code image file, and
- `--challenge 12345` indicates to sign the unique challenge nonce `12345`, which is an alternative to using the QR code

Example output:

```
Using the challenge &{Message:12345 Scope:{CircuitID:credentialAtomicQuerySig Queries:[{Property:birthDay Operator:2 Value:2.0000101e+07}]}} decoded from the QR Code
Loading holder identity
Load the claims merkle tree
Load the revocations merkle tree
Load the roots merkle tree
Challenge response inputs written to the file: $IDEN3_WORKDIR/AliceWonder/challenge.json
```

## Generate the Zero Knowledge Proof for the Claim Challenge

We use snark.js again to generate the proof, using the inputs that have been generated in the above step and callback to the verifier server for verification.

```
$ cd holder/wallet
$ npm i
$ node index.js --holder AliceWonder --qrcode /Users/alice/Downloads/challenge-qr.png
```

Example verification success output:

```
Successfully generated proof!
holderId: 49569550112309810311684076244797631987219037202776082502010719096263737344
Sending callback to the verifier server:  http://localhost:8080/api/callback?sessionId=1
Success response from the verifier server: {"status":200,"message":{"message":"user with ID: 116MeDP87togwHVXFJC78sUA9Vdwbtj25NKjHzZ8Tm successfully authenticated"}}
Done!
```
