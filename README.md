# kaleido-iden3-samples

Sample code for using the iden3 protocol to issue verifiable claims and verify them.

# Getting Started

Issuing claims is a two step process in our example:

- Creation: creating the issuer identity and author the claims
- Publishing: generate a ZK proof for the state transition and publish to the iden3 smart contract

## Issuer Creation and Claims Authoring

This part is accomplished in a golang program in the folder [issuer/issue-claims](./issuer/issue-claims/). Simply run the `main.go` program:

```
$ go run main.go
Generating new signing key from the "babyjubjub" curve
-> Public key: 0c818f2eb345aee28b40ef1c6b9bde8d230fec1d733391410389498dbf26dd9b

Generating genesis state for the issuer
-> Create the empty claims merkle tree
-> Create the empty revocations merkle tree
-> Create the empty roots merkle tree

-> Issue the authentication claim for the issuer's identity
   -> Issued auth claim: encoded=["304427537360709784173770334266246861770","0","19193078513091090569938980098530893130676186200521453179047524649910266768883","12603187543654490644502531250373959395204698526200642479217027199547846131980","1","0","0","0"]
   -> Add the new auth claim to the claims tree

-> Genesis State: 19306747691617191881741508742304484212112659069796039293152856903884093040265
-> ID of the issuer identity: 115xohB51QpGvf9eojCAwFXYcJiUw9bmrJzuSa2FmH

Construct the state snapshot (later as input to the ZK proof generation)
-> Generate a merkle proof of the inclusion of the auth claim in the claims tree
-> Generate a merkle proof of the exclusion of the revocation nonce in the revocation tree


Add the current claim tree root to the roots tree

Issue the KYC age claim
-> Schema hash for 'KYCAgeCredential': 295816c03b74e65ac34e5c6dda3c753b
-> Issued age claim: ["79033184733919717737895683943512299561","0","25","0","0","0","0","0"]
-> Add the age claim to the claims tree


Issue the KYC country claim
-> Schema hash for 'KYCCountryOfResidenceCredential': 1fb3b6e8f0f177c56e78731dbaf5f1d8
-> Issued country claim: ["288369574568354504799542423489921594143","0","21333","2387954847937209828280248043093287993223726259666336443989","0","0","0","0"]
-> Add the country claim to the claims tree


Issue the KYC creds claim
-> Schema hash for 'KYCCredential': 260ccec2e476e60ded1c8ec06857fafe
-> Issued full KYC claim: ["338923758012959683754742625582170639398","0","31691307728223429882979181890","16409611496416179189386577045636576920385","0","0","21333","367285800500154616598425773395044450553314396878965345179264319476807986"]
-> Add the KYC creds claim to the claims tree


Calculate the new state

-> state transition from old to new
-> Input bytes written to the file: /Users/jimzhang/iden3_input.json
```

The end result of this program is that, an issuer identity was created from a new private key of the babyjubjub curve, with a genesis state that contains the issuer identity's own authentication claim ([schema](https://github.com/iden3/claim-schema-vocab/blob/main/schemas/json-ld/auth.json-ld) here), then a number of claims intended for the holder are authored that result in a new state. Finally the program generates the inputs needed to generate a zero knowledger proof for the state transition. The proof generation is accomplished in the next step with a node.js based program, based on [snarkjs](https://github.com/iden3/snarkjs).

## Proof Generation and State Transition

Next we want to publish the transition from the genesis state and the new state, which contains the claims we issued, to the [iden3 smart contract](./issuer/upload-claims/contracts/State.sol). The smart contract function `transitState()` takes the public inputs (issuer ID, old state and new state) and the proof, verifies the proof and then update the state for the issuer ID to the new state.

Note that the state published to the smart contract is the hash of the latest markle tries `hash(claims_root, revocation_root, roots_root)`. This means that care should be taken when designing the claim schemas. No PII _should_ be part of the claim because hashes of PII is still considered PII under some regulations such as GDPR ([details](https://legalconsortium.org/uncategorized/how-does-the-eus-gdpr-view-hashed-data-on-the-blockchain/#:~:text=The%20GDPR%20does%20not%20apply,linkability%E2%80%9D%20of%20an%20unreadable%20hash) available here).

### Deploy the State Smart Contract

The iden3 State contract is deployed using hardhat. It depends on a Verifier contract as library.

Go to the [issuer/upload-claims](./issuer/upload-claims/) folder.

Set the environment variable `KALEIDO_NODE_URL` to the full RPC URL of a Kaleido node, including the basic auth credentials. For example:

```
export KALEIDO_NODE_URL=https://username:password@u0nc4noce4-u0c5qcrhgs-rpc.us0-aws.kaleido.io
```

> You can also use the Polygon Mumbai test network as the target, with `--network mumbai`. Set the environment variables `MUMBAI_NODE_URL` and `MUMBAI_PRIV_KEY` accordingly. If you use this option, there's no need to deploy the smart contract. You can use the contract that's already been deployed to Mumbai.

```
$ npx hardhat run scripts/deploy.js --network kaleido
deploying verifier
deploying state
Verifier contract deployed to 0xf7933EdC82Face032402dBC197280045B327F4ee from 0x6b2807d1074ae6E1ab022E1bdb7C0C8C1Eff1BDF
State contract deployed to 0x4d94963B43212D03fDc5f0523512d30430e83041 from 0x6b2807d1074ae6E1ab022E1bdb7C0C8C1Eff1BDF
```

The result, in particular the State contract address, is persisted in a file ($HOME_DIR/iden3_deploy_output.json) that will be read by the next program.

### Generate State Transition Proof and Update OnChain State

Next we use snarkjs to generate the state transition, from the genesis state to the new state, and upload the states with the proof to the smart contract in order to update the onchain state to the new state that contains the new claims.

This step uses the output of the golang program as the input to the proof generation. It's based on a [pre-compiled circuit](https://github.com/iden3/circuits/blob/master/circuits/lib/stateTransition.circom) for the state transition.

```
$ npx hardhat run scripts/upload-state-transition.js --network kaleido
Calculated witness successfully written to file /Users/jimzhang/iden3_witness.wtns
Generated proof written to file /Users/jimzhang/iden3_proof.json
Generated public signals written to file /Users/jimzhang/iden3_public.json
Successfully generated proof!
State before transaction:  BigNumber { value: "0" }
State after transaction:  BigNumber { value: "11664970887009708975084603155656094025162508207603246286644937792890894779539" }
```

## Claim Verification

To be continued...
