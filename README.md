# kaleido-iden3-samples

Sample code for using the iden3 protocol to issue verifiable claims and verify them.

# Getting Started

The sample covers the 3 roles involved in a typical Self Sovereign Identity use case:

- issuer: to create their own identity and issue claims to a target holder
- holder: to create their own identity, receive a claim issued by the issuer, and generate a proof for the claim when challenged by the verifier
- verifier: to challenge the holder for the proof of their possession of a claim, by using a zero knowledge query

## Create An Identity

The issuer and the holder must first create their identity. This is accomplished with the Golang program in the `identity` folder, with the subcommand `init`.

```
cd identity
go run main.go init --name JohnDoe
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

For each identity, the program creates the following resources:

- $HOMEDIR/iden3/JohnDoe: this folder holds the resources specific to the identity, including:
  - **private.key**: the private key for the identity (on the babyjubjub curve)
  - **genesis_state.json**: the genesis state of the identity, including its public user ID, a base58 encoded string, and the issuer identity's own authentication claim ([schema](https://github.com/iden3/claim-schema-vocab/blob/main/schemas/json-ld/auth.json-ld) here)
  - **stateTransition_inputs.json**: the inputs to generate a zero knowledge proof for the state transition method on the smart contract that maintains the public registry of issuer identities
  - **claims/revocations/roots.db**: sqlite DB files that store the Claims, Revocation and Roots Merkle trees of the identity.

Use the `init` subcommand to generate at least two identities, one as the issuer, and one as the holder.

## Publish Identity States to a registry

The identity state of the issuer should be published to a registry so that verifiers can use it to validate claims. A smart contract based registry has been provided and can be deployed using the Hardhat script.

The iden3 `State.sol` contract, and its dependencies, implements an identity registry. An issuer should register its identity state with the contract, by calling the `transitState()` function, which requires a zero knowledge proof of the addition of the auth claim of the issuer to the merkle tree.

### Publish the iden3 State Contract

To publish the State contract, use the `deploy.js` script in the Hardhat project in the folder `issuer/upload-claims`.

Set the environment variable `KALEIDO_NODE_URL` to the full RPC URL of a Kaleido node, including the basic auth credentials. For example:

```
export KALEIDO_NODE_URL=https://username:password@u0nc4noce4-u0c5qcrhgs-rpc.us0-aws.kaleido.io
```

> You can also use the Polygon Mumbai test network as the target, with `--network mumbai`. Set the environment variables `MUMBAI_NODE_URL` and `MUMBAI_PRIV_KEY` accordingly. If you use this option, there's no need to deploy the smart contract. You can use the contract that's already been deployed to Mumbai.

```
$ npx hardhat run scripts/deploy.js --network kaleido
deploying verifier
deploying state
Verifier contract deployed to 0x2442dD31Bb4c5df7AEA41dC1AE98B8f806CE4375 from 0x6b2807d1074ae6E1ab022E1bdb7C0C8C1Eff1BDF
State contract deployed to 0xe4BAd4a8636d79E918fFA9Db72502fCf56a77D2D from 0x6b2807d1074ae6E1ab022E1bdb7C0C8C1Eff1BDF
```

The result, in particular the State contract address, is persisted in a file ($HOME_DIR/iden3_deploy_output.json) that will be read by the next program.

### Proof Generation and Update OnChain State

Next we want to publish the transition from the nil state to the genesis state that includes the issuer's auth claim in the merkle tree, to the [iden3 smart contract](./issuer/upload-claims/contracts/State.sol). The smart contract function `transitState()` takes the public inputs (issuer ID, old state and new state) and the proof, verifies the proof and then update the state for the issuer ID to the new state.

> Note that the state published to the smart contract is the hash of the latest markle tries `hash(claims_root, revocation_root, roots_root)`. This means that care should be taken when designing the claim schemas. No PII _should_ be part of the claim because hashes of PII is still considered PII under some regulations such as GDPR ([details](https://legalconsortium.org/uncategorized/how-does-the-eus-gdpr-view-hashed-data-on-the-blockchain/#:~:text=The%20GDPR%20does%20not%20apply,linkability%E2%80%9D%20of%20an%20unreadable%20hash) available here).

We use snarkjs to generate the state transition proof, from the nil state to the genesis state, and upload the states with the proof to the smart contract in order to update the onchain state for the identity.

This step uses the output of the golang program as the input to the proof generation. It's based on a [pre-compiled circuit](https://github.com/iden3/circuits/blob/master/circuits/lib/stateTransition.circom) for the state transition.

With the `IDEN3_NAME` set to `JohnDoe`, we tell the program to publish the state of JohnDoe on chain, which will be act as the issuer in the later tutorial.

```
$ export IDEN3_NAME=JohnDoe
$ npx hardhat run scripts/upload-state-transition.js --network kaleido
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
Calculated witness successfully written to file /Users/jimzhang/iden3_witness.wtns
Generated proof written to file /Users/jimzhang/iden3_proof.json
Generated public signals written to file /Users/jimzhang/iden3_public.json
Successfully generated proof!
State before transaction:  BigNumber { value: "0" }
State after transaction:  BigNumber { value: "4415121770339690351530166661455105854178222280927373194615248123084196097920" }
```

## Issue Claims

To issue a claim, use the Golang program with the subcommand `claim`.

```
$ go run main.go claim --issuer JohnDoe --holder 117Lsj1jXRhts4C1ADyKwEAYfhTRr4ymrA3UpwdU32 --nonce 2
Using issuer identity with name:  JohnDoe
Using holder identity:  117Lsj1jXRhts4C1ADyKwEAYfhTRr4ymrA3UpwdU32
Using revocation nonce for the new claim:  2
Loading issuer identity
-> Issuer private key successfully loaded
Loading issuer ID
-> Issuer identity:  11AmRzsJt9cWVYCs8xNbBnHdLB14ubKLAvqsYsyD35
Loading issuer state
Load the issuer claims merkle tree
Load the revocations merkle tree
Load the roots merkle tree
Issue the KYC age claim
-> Schema hash for 'KYCAgeCredential': 295816c03b74e65ac34e5c6dda3c753b
-> Issued age claim: ["759597918575796644664644898807048722473","171461361565191151824690974871439449294142670051513093660327757037227933696","25","0","2","0","0","0"]
-> Add the age claim to the claims tree

-> Input bytes for issued user claim written to the file: /Users/jimzhang/iden3/JohnDoe/claims/2-117Lsj1jXRhts4C1ADyKwEAYfhTRr4ymrA3UpwdU32.json
```

With the `--issuer JohnDoe` parameter, we tell the program to use the private key inside the folder `JohnDoe` as the issuer of the claim.

With the `--holder 117Lsj1jXRhts4C1ADyKwEAYfhTRr4ymrA3UpwdU32` paramter, we tell the program that the holder to issue the claim to is `117Lsj1jXRhts4C1ADyKwEAYfhTRr4ymrA3UpwdU32`, which is the holder's public user ID. This string is printed in the output of the `init` command.

With the `--nonce 2` parameter, we tell the program to use the revocation nonce `2` for the claim. Every claim must have a nonce that is used to validate if the claim has been revoked or not.

The issued claim is persisted in the folder `iden3/JohnDoe/claims`. The file name is `[nonce]-[holder user ID].json`.

## Copy The Claim to the Holder's "Wallet"

A real holder's wallet is typically a mobile app. In this sample, we use the Golang program to manage the resources in the identity's dedicated folder, minicing the holder's wallet.

To mimic the transfer of the claim from the issuer's server to the holder's wallet, simply copy the claim file created in the previous step, to a `received-claims` folder of the holder.

For instance, if the issuer's name is `JohnDoe`, and the holder's name is `AliceWonder`:

```
mkdir ~/iden3/AliceWonder/received-claims
cp ~/iden3/JohnDoe/claims/2-117Lsj1jXRhts4C1ADyKwEAYfhTRr4ymrA3UpwdU32.json ~/iden3/AliceWonder/received-claims/
```

## Verifier To Launch the Claim Challenge Site

The verifier wants to request the holder to present a proof for a condition that the verifier is interested in. The current communication between the verifier and the holder is conducted via QR code.

The verifier expresses the condition using the [iden3 proof query language](https://docs.iden3.io/protocol/querylanguage/), and then wrap it inside a request object which then gets encoded into a QR code.

The QR code is presented in the verifier's web site, which the holder can scan to obtain the proof request. Based on the query request decoded from the QR code, the holder can then generate the proof accordingly.

To launch the sample verifier's web site, go to the `verifier/server` folder:

```
$ npm i
$ node app.js
server running on port 8080
```

Point your browser at the URL `http://localhost:8080`, then click the "Sign In" button to display the QR code which encodes the proof request.

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

## Holder To Respond To Challenge For A Claim

Now, acting as the holder, we can use the Golang program's `respond-to-challenge` subcommand to generate the necessary inputs for the zero knowledge proof, responding to the challenge by the verifier. In the sample code, the challenge was for a proof that the age claim has a `birthdate` attribute with a value less than `20000101`.

Before launching the command, save the QR code image from the web site to a **PNG or JPEG file** (In the real world, the holder would use the wallet app to scan the QR code.)

```
$ go run main.go respond-to-challenge --holder AliceWonder --qrcode /Users/alice/Downloads/challenge-qr.png
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

`--holder AliceWonder` tells the program to use the private key and the merkletree of the identity `AliceWonder`.
`--qrcode <file>` tells the program to decode the proof request from the QR code image file
`--challenge 12345` tells the program to sign the unique challenge nonce `12345`, which is an alternative to using the QR code

## Generate the Zero Knowledge Proof for the Claim Challenge

We use snark.js again to generate the proof, using the inputs that have been generated in the above step.

```
cd holder/wallet
npm i
node index.js --holder AliceWonder --qrcode /Users/alice/Downloads/challenge-qr.png
```
