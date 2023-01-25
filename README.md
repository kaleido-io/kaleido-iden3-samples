# kaleido-iden3-samples

Sample code for using the [Iden3 protocol](https://docs.iden3.io/protocol/spec/) to issue verifiable claims and verify them.

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

## Create an Identity

The issuer and the holder must first create their identity. This is accomplished with the Golang program in the `identity` folder, with the subcommand `init`.

```
$ cd identity
$ go run main.go init --name JohnDoe
```

Example output:

```
Generating new signing key from the "babyjubjub" curve
-> Public key: dc743d5a062212f859c818c694bd1ee8bd5697d8cd9600da33b52c65a240cc82

Generating genesis state for the identity
-> Create the empty claims merkle tree
-> Create the empty revocations merkle tree
-> Create the empty roots merkle tree
-> Issue the authentication claim for the identity
   -> Issued auth claim: encoded=["304427537360709784173770334266246861770","0","18017859934107271763951455900250501959551723233962067023583930178913551929368","1265508588313811044386092944925023464726920457950722282048202448327822636252","1","0","0","0"]
   -> Add the new auth claim to the claims tree
-> Genesis State: 21425710663792543860638097878176930092881222457766735304651100508091636401546
-> ID of the generated identity: 117Lsj1jXRhts4C1ADyKwEAYfhTRr4ymrA3UpwdU32

Construct the state snapshot (later as input to the ZK proof generation)
-> Generate a merkle proof of the inclusion of the auth claim in the claims tree
-> Generate a merkle proof of the exclusion of the revocation nonce in the revocation tree

-> Input bytes for the identity's genesis state written to the file: /Users/jimzhang/iden3/JohnDoe/genesis_state.json
Add the current claim tree root to the roots tree
Calculate the new state
-> state transition from old to new
-> State transition input bytes written to the file: /Users/jimzhang/iden3/JohnDoe/stateTransition_inputs.json
```

For each identity, the program creates the following resources under the `$HOMEDIR/iden3/` folder:

- identity name (e.g. `JohnDoe/`): this folder holds the resources specific to the identity, including:
  - `private.key`: the private key for the identity (on the [Baby Jubjub](https://docs.iden3.io/getting-started/babyjubjub/) curve)
  - `genesis_state.json`: the genesis state of the identity, including its public user ID, a base58 encoded string, and the issuer identity's own authentication claim ([schema](https://github.com/iden3/claim-schema-vocab/blob/main/schemas/json-ld/auth.json-ld) here)
  - `claims/revocations/roots.db`: sqlite DB files that store the Claims, Revocation and Roots Merkle trees of the identity.
  - `stateTransition_inputs.json`: the inputs to generate a zero knowledge proof for the state transition method on the smart contract that maintains the public registry of issuer identities. Input file for [Proof Generation and Update OnChain State](#proof-generation-and-update-onchain-state)
  - `treeStates.json`: this json file contains an old state (genesis state OR the state recorded on chain) and a new state (the current state calculated locally to be recorded on chain)
- `identities.json`: this file contains a lookup table of identity name and IDs. It gets updated whenever a new identify is created.

Use the `init` subcommand to generate at least two identities, one as the issuer, and one as the holder. The sections below use JohnDoe as the issuer and AliceWonder as the holder, so create an identity for AliceWonder and take note of the ID:

```
$ go run main.go init --name AliceWonder
```

Example output:

```
...
-> ID of the generated identity: 11C3BYGvF9QaTBGCYfV3tiKQ5tQh1Fpu7YtnazFczS
...
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
npx hardhat run scripts/deploy.js --network kaleido
```

Example output:

```
deploying verifier
deploying state
Verifier contract deployed to 0x2442dD31Bb4c5df7AEA41dC1AE98B8f806CE4375 from 0x6b2807d1074ae6E1ab022E1bdb7C0C8C1Eff1BDF
State contract deployed to 0xe4BAd4a8636d79E918fFA9Db72502fCf56a77D2D from 0x6b2807d1074ae6E1ab022E1bdb7C0C8C1Eff1BDF
```

The result, in particular the State contract address, is persisted in a file (`$HOME_DIR/iden3/deploy_output.json`) that will be read by the next program.

### Generate proof and update on-chain state

Next we want to publish the transition from the nil state to the genesis state, including the issuer's auth claim in the Merkle tree, to the [State smart contract](./issuer/upload-claims/contracts/State.sol). The smart contract function `transitState()` takes the public inputs (issuer ID, old state and new state) and the proof, verifies the proof and then updates the state for the issuer ID to the new state.

We use the snarkjs library to generate the state transition proof, from the nil state to the genesis state, and upload the states with the proof to the smart contract in order to update the onchain state for the identity.

This step uses the output of the Golang program as the input to the proof generation. It's based on a [pre-compiled circuit](https://github.com/iden3/circuits/blob/master/circuits/lib/stateTransition.circom) for the state transition.

For successful runs, the program may create new resources in the identify folder. Using JohnDoe as example:

- `$HOMEDIR/iden3/JohnDoe`: this folder holds the resources specific to the identity:
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
{
  authClaim: [
    '304427537360709784173770334266246861770',
    '0',
    '16182024339410368346878413058713696476688824744274081349004534968207168734196',
    '12841111665807436890802721781149912292363767375600649957739168310055570656034',
    '1',
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
  userID: '409998607882138324879147799124165933611201359746019080539065965042743050240',
  newUserState: '4415121770339690351530166661455105854178222280927373194615248123084196097920',
  claimsTreeRoot: '6558733581564106007744827686666841045660069343837367883412654471356912161735',
  revTreeRoot: '0',
  rootsTreeRoot: '0',
  oldUserState: '6142995168629238402157389637522013281792890289547561328355780470257846623025',
  isOldStateGenesis: '1',
  signatureR8x: '21126463187838547760619835419984459466018433355967260339237983728776669928396',
  signatureR8y: '12271130677221335597573147809728317393586613092791779637238186615149949086007',
  signatureS: '2674232694038697703767340830255401681196777672498953355857692309695719736210'
}
Calculated witness successfully written to file /Users/jimzhang/iden3/JohnDoe/witness-303bf4db24b455170660.wtns
Successfully generated proof!
State before transaction:  BigNumber { value: "0" }
Invoking state transaction on chain ...
State after transaction:  BigNumber { value: "4415121770339690351530166661455105854178222280927373194615248123084196097920" }
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
-> Calculated state hash: 17344721974390121998109186055953020091232501576591384662216306133407895435304
Generating the non-membership proof of revocation tree
-> Calculated state hash: 17344721974390121998109186055953020091232501576591384662216306133407895435304
Persisting claim to iden3/JohnDoe/private/claims/genericClaim-681758df5afc8632bbf2e88995c26adb-JohnDoe-private-AliceWonder.json
Generating the auth Proof of key: private and storing claim inputs for Signature Circuit
-> Calculated state hash: 17344721974390121998109186055953020091232501576591384662216306133407895435304
Claim issued by "JohnDoe" using key "private" is received by holder "AliceWonder" under path: iden3/AliceWonder/private/received-claims/genericClaim-681758df5afc8632bbf2e88995c26adb-JohnDoe-private-AliceWonder-via-signature.json
```

The issued claim is persisted in the folder `iden3/JohnDoe/private/claims`. The file name is `genericClaim-[schemaHash]-[issuer name]-[issuer key name]-[holder name].json`.

Note: since we are using signature-based proofs for claims, rather than MTP (Merkle Tree Proof)-based, there is no need to update the on-chain state for the newly issued claim. 
With this approach, we only need to store the issuer's identity genesis state on-chain.

## Holder "Downloads" the Claim to their "Wallet"

A real holder's wallet is typically a mobile app. In this sample, we use the Golang program to manage the resources in the identity's dedicated folder, mimicking the holder's wallet.

Therefore, we have already the Claim has already been downloaded into holder's private folders in the previous step.

The received claim is persisted in the folder `iden3/AliceWonder/private/received-claims`. The file name is `genericClaim-[schemaHash]-[issuer name]-[issuer key name]-[holder name]-via-signature.json`.


## Verifier Presents a Claim Challenge

The verifier wants to request the holder to present a proof for a condition that the verifier is interested in. The current communication between the verifier and the holder is conducted via QR code.

The verifier expresses the condition using the [Iden3 proof query language](https://docs.iden3.io/protocol/querylanguage/), wraps it in a request object, and encodes this in a QR code.

The QR code is presented in the verifier's web site, which the holder can scan to obtain the proof request. Based on the query request decoded from the QR code, the holder can then generate the proof accordingly.

To launch the sample verifier's web site, go to the `verifier/server` folder and run:

```
$ npm i
$ node app.js --jsonrpc-url https://[appcred]:[password]@u0nc4abdk4-u0c5xarhgs-rpc.us0-aws.kaleido.io --state-contract 0xe4bad4a8636d79e918ffa9db72502fcf56a77d2d
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
Using the challenge &{Message:12345 Scope:{CircuitID:credentialAtomicQuerySig Queries:[{Property:birthdate Operator:2 Value:2.0000101e+07}]}} decoded from the QR Code
Loading holder state
Load the issuer claims merkle tree
Load the revocations merkle tree
Load the roots merkle tree
Loading holder private key
Loading holder ID
-> Issuer identity:  117Lsj1jXRhts4C1ADyKwEAYfhTRr4ymrA3UpwdU32
Challenge response inputs written to the file: /Users/jimzhang/iden3/AliceWonder/challenge.json
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
Sending callback to verifier server:  http://localhost:8080/api/callback?sessionId=1
Success response from verifier server: {"status":200,"message":"user with ID: 11C3BYGvF9QaTBGCYfV3tiKQ5tQh1Fpu7YtnazFczS Succesfully authenticated"}
Done!
```
