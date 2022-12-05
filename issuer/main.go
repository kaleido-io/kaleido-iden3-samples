package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/iden3/go-circuits"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/keccak256"
	"github.com/iden3/go-iden3-crypto/poseidon"
	merkletree "github.com/iden3/go-merkletree-sql"
	"github.com/iden3/go-merkletree-sql/db/memory"
)

func main() {
	privKey := babyjub.NewRandPrivKey()
	pubKey := privKey.Public()
	fmt.Printf("Public key: %s\n", pubKey)

	ctx := context.Background()

	// Create the Genesis State:
	// - issue an auth claim based on the public key and revocation nounce, this will determine the identity's ID
	// - add the auth claim to the claim tree
	// - add the claim tree root at this point in time to the roots tree
	claimTree, _ := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 32)
	revocationTree, _ := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 32)
	rootsTree, _ := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 32)

	authSchemaHash, _ := core.NewSchemaHashFromHex("ca938857241db9451ea329256b9c06e5")
	revNonce := uint64(1)
	authClaim, _ := core.NewClaim(authSchemaHash, core.WithIndexDataInts(pubKey.X, pubKey.Y), core.WithRevocationNonce(revNonce))
	encodedAuthClaim, _ := json.Marshal(authClaim)
	fmt.Printf("Issued auth claim: encoded=%s\n", encodedAuthClaim)

	hIndex, hValue, _ := authClaim.HiHv()
	claimTree.Add(ctx, hIndex, hValue)

	// print the genesis state
	state, _ := merkletree.HashElems(claimTree.Root().BigInt(), revocationTree.Root().BigInt(), rootsTree.Root().BigInt())
	fmt.Printf("Genesis State: %s\n", state.BigInt())

	// print the ID
	id, _ := core.IdGenesisFromIdenState(core.TypeDefault, state.BigInt())
	fmt.Printf("ID of the identity: %s\n", id)

	// construct the genesis state snapshot, to be used as input to the ZKP for the state transition
	authMTProof, _, _ := claimTree.GenerateProof(ctx, hIndex, claimTree.Root())
	authNonRevMTProof, _, _ := revocationTree.GenerateProof(ctx, new(big.Int).SetInt64(int64(revNonce)), revocationTree.Root())
	genesisTreeState := circuits.TreeState{
		State:          state,
		ClaimsRoot:     claimTree.Root(),
		RevocationRoot: revocationTree.Root(),
		RootOfRoots:    rootsTree.Root(),
	}

	// before updating the claims tree, add the claims tree root at this point to the roots tree
	rootsTree.Add(ctx, claimTree.Root().BigInt(), big.NewInt(0))

	// Load the schema for the KYC claims
	schemaBytes, _ := os.ReadFile("./schemas/test.json-ld")
	var sHash core.SchemaHash

	// issue the age claim
	h := keccak256.Hash(schemaBytes, []byte("KYCAgeCredential"))
	copy(sHash[:], h[len(h)-16:])
	sHashText, _ := sHash.MarshalText()
	ageSchemaHash := string(sHashText)
	fmt.Println("Schema hash for 'KYCAgeCredential':", ageSchemaHash)

	kycAgeSchema, _ := core.NewSchemaHashFromHex(ageSchemaHash)
	age := big.NewInt(25)
	ageClaim, _ := core.NewClaim(kycAgeSchema, core.WithIndexDataInts(age, nil))
	encoded, _ := json.Marshal(ageClaim)
	fmt.Printf("Issued age claim: %s\n", encoded)

	// add the age claim to the claim tree
	ageHashIndex, ageHashValue, _ := ageClaim.HiHv()
	claimTree.Add(ctx, ageHashIndex, ageHashValue)

	// issue the country claim
	h = keccak256.Hash(schemaBytes, []byte("KYCCountryOfResidenceCredential"))
	copy(sHash[:], h[len(h)-16:])
	sHashText, _ = sHash.MarshalText()
	countrySchemaHash := string(sHashText)
	fmt.Println("Schema hash for 'KYCCountryOfResidenceCredential':", countrySchemaHash)

	kycCountrySchema, _ := core.NewSchemaHashFromHex(countrySchemaHash)
	countryClaim, _ := core.NewClaim(kycCountrySchema, core.WithIndexDataBytes([]byte("US"), []byte("United States of America")))
	encoded, _ = json.Marshal(countryClaim)
	fmt.Printf("Issued country claim: %s\n", encoded)

	countryHashIndex, countryHashValue, _ := countryClaim.HiHv()
	claimTree.Add(ctx, countryHashIndex, countryHashValue)

	// issue the full KYC claim
	h = keccak256.Hash(schemaBytes, []byte("KYCCredential"))
	copy(sHash[:], h[len(h)-16:])
	sHashText, _ = sHash.MarshalText()
	kycSchemaHash := string(sHashText)
	fmt.Println("Schema hash for 'KYCCountryOfResidenceCredential':", kycSchemaHash)

	kycSchema, _ := core.NewSchemaHashFromHex(kycSchemaHash)
	kycClaim, err := core.NewClaim(kycSchema, core.WithIndexDataBytes([]byte("Ben Chodroff"), []byte("ACCOUNT1234567890")), core.WithValueDataBytes([]byte("US"), []byte("295816c03b74e65ac34e5c6dda3c753b")))
	if err != nil {
		fmt.Println("Failed to create claim", err)
		return
	}
	encoded, _ = json.Marshal(kycClaim)
	fmt.Printf("Issued full KYC claim: %s\n", encoded)

	kycHashIndex, kycHashValue, _ := kycClaim.HiHv()
	claimTree.Add(ctx, kycHashIndex, kycHashValue)

	// construct the new identity state
	newState, _ := merkletree.HashElems(claimTree.Root().BigInt(), revocationTree.Root().BigInt(), rootsTree.Root().BigInt())

	// hash the [genesis state + new state] to be signed later
	hashOldAndNewState, _ := poseidon.Hash([]*big.Int{state.BigInt(), newState.BigInt()})
	// sign using the identity key
	signature := privKey.SignPoseidon(hashOldAndNewState)

	// construct the inputs to feed to the proof generation for the state transition
	stateTransitionInputs := circuits.StateTransitionInputs{
		ID:                id,
		OldTreeState:      genesisTreeState,
		NewState:          newState,
		IsOldStateGenesis: true,
		AuthClaim: circuits.Claim{
			Claim: authClaim,
			Proof: authMTProof,
			NonRevProof: &circuits.ClaimNonRevStatus{
				Proof: authNonRevMTProof,
			},
		},
		Signature: signature,
	}

	inputBytes, _ := stateTransitionInputs.InputsMarshal()
	fmt.Printf("Input bytes to feed to the proof generator: %s\n", string(inputBytes))
}
