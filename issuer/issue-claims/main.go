package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/iden3/go-circuits"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/keccak256"
	"github.com/iden3/go-iden3-crypto/poseidon"
	merkletree "github.com/iden3/go-merkletree-sql"
	"github.com/iden3/go-merkletree-sql/db/memory"
)

func main() {
	fmt.Println("Generating new signing key from the \"babyjubjub\" curve")
	privKey := babyjub.NewRandPrivKey()
	pubKey := privKey.Public()
	fmt.Printf("-> Public key: %s\n\n", pubKey)

	ctx := context.Background()

	// An iden3 state is made up of 3 parts:
	// - a claims tree. This is a sparse merkle tree where each claim is uniquely identified with a key
	// - a revocation tree. This captures whether a claim, identified by its revocation nonce, has been revoked
	// - a roots tree. This captures the historical progression of the merkle tree root of the claims tree
	//
	// To create a genesis state:
	// - issue an auth claim based on the public key and revocation nounce, this will determine the identity's ID
	// - add the auth claim to the claim tree
	// - add the claim tree root at this point in time to the roots tree
	fmt.Println("Generating genesis state for the issuer")
	fmt.Println("-> Create the empty claims merkle tree")
	claimTree, _ := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 32)
	fmt.Println("-> Create the empty revocations merkle tree")
	revocationTree, _ := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 32)
	fmt.Println("-> Create the empty roots merkle tree\n")
	rootsTree, _ := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 32)

	// A schema is registered using its hash. The hash is used to coordinate the validation by offline processes.
	// There is no schema validation by the protocol.
	fmt.Println("-> Issue the authentication claim for the issuer's identity")
	authSchemaHash, _ := core.NewSchemaHashFromHex("ca938857241db9451ea329256b9c06e5")
	revNonce := uint64(1)
	// An auth claim includes the X and Y curve coordinates of the public key, along with the revocation nonce
	authClaim, _ := core.NewClaim(authSchemaHash, core.WithIndexDataInts(pubKey.X, pubKey.Y), core.WithRevocationNonce(revNonce))
	encodedAuthClaim, _ := json.Marshal(authClaim)
	fmt.Printf("   -> Issued auth claim: encoded=%s\n", encodedAuthClaim)

	fmt.Println("   -> Add the new auth claim to the claims tree\n")
	hIndex, hValue, _ := authClaim.HiHv()
	claimTree.Add(ctx, hIndex, hValue)

	// print the genesis state
	state, _ := merkletree.HashElems(claimTree.Root().BigInt(), revocationTree.Root().BigInt(), rootsTree.Root().BigInt())
	fmt.Printf("-> Genesis State: %s\n", state.BigInt())

	// print the ID
	id, _ := core.IdGenesisFromIdenState(core.TypeDefault, state.BigInt())
	fmt.Printf("-> ID of the issuer identity: %s\n\n", id)

	// construct the genesis state snapshot, to be used as input to the ZKP for the state transition
	fmt.Println("Construct the state snapshot (later as input to the ZK proof generation)")
	fmt.Println("-> Generate a merkle proof of the inclusion of the auth claim in the claims tree")
	authMTProof, _, _ := claimTree.GenerateProof(ctx, hIndex, claimTree.Root())
	fmt.Println("-> Generate a merkle proof of the exclusion of the revocation nonce in the revocation tree\n\n")
	authNonRevMTProof, _, _ := revocationTree.GenerateProof(ctx, new(big.Int).SetInt64(int64(revNonce)), revocationTree.Root())
	genesisTreeState := circuits.TreeState{
		State:          state,
		ClaimsRoot:     claimTree.Root(),
		RevocationRoot: revocationTree.Root(),
		RootOfRoots:    rootsTree.Root(),
	}

	// before updating the claims tree, add the claims tree root at this point to the roots tree
	fmt.Println("Add the current claim tree root to the roots tree\n")
	rootsTree.Add(ctx, claimTree.Root().BigInt(), big.NewInt(0))

	fmt.Println("Issue the KYC age claim")
	// Load the schema for the KYC claims
	schemaBytes, _ := os.ReadFile("./schemas/test.json-ld")
	var sHash core.SchemaHash

	// issue the age claim
	h := keccak256.Hash(schemaBytes, []byte("KYCAgeCredential"))
	copy(sHash[:], h[len(h)-16:])
	sHashText, _ := sHash.MarshalText()
	ageSchemaHash := string(sHashText)
	fmt.Println("-> Schema hash for 'KYCAgeCredential':", ageSchemaHash)

	kycAgeSchema, _ := core.NewSchemaHashFromHex(ageSchemaHash)
	age := big.NewInt(25)
	ageClaim, _ := core.NewClaim(kycAgeSchema, core.WithIndexDataInts(age, nil))
	encoded, _ := json.Marshal(ageClaim)
	fmt.Printf("-> Issued age claim: %s\n", encoded)

	// add the age claim to the claim tree
	fmt.Println("-> Add the age claim to the claims tree\n\n")
	ageHashIndex, ageHashValue, _ := ageClaim.HiHv()
	claimTree.Add(ctx, ageHashIndex, ageHashValue)

	// issue the country claim
	fmt.Println("Issue the KYC country claim")
	h = keccak256.Hash(schemaBytes, []byte("KYCCountryOfResidenceCredential"))
	copy(sHash[:], h[len(h)-16:])
	sHashText, _ = sHash.MarshalText()
	countrySchemaHash := string(sHashText)
	fmt.Println("-> Schema hash for 'KYCCountryOfResidenceCredential':", countrySchemaHash)

	kycCountrySchema, _ := core.NewSchemaHashFromHex(countrySchemaHash)
	countryClaim, _ := core.NewClaim(kycCountrySchema, core.WithIndexDataBytes([]byte("US"), []byte("United States of America")))
	encoded, _ = json.Marshal(countryClaim)
	fmt.Printf("-> Issued country claim: %s\n", encoded)

	fmt.Println("-> Add the country claim to the claims tree\n\n")
	countryHashIndex, countryHashValue, _ := countryClaim.HiHv()
	claimTree.Add(ctx, countryHashIndex, countryHashValue)

	// issue the full KYC claim
	fmt.Println("Issue the KYC creds claim")
	h = keccak256.Hash(schemaBytes, []byte("KYCCredential"))
	copy(sHash[:], h[len(h)-16:])
	sHashText, _ = sHash.MarshalText()
	kycSchemaHash := string(sHashText)
	fmt.Println("-> Schema hash for 'KYCCredential':", kycSchemaHash)

	kycSchema, _ := core.NewSchemaHashFromHex(kycSchemaHash)
	kycClaim, err := core.NewClaim(kycSchema, core.WithIndexDataBytes([]byte("Ben Chodroff"), []byte("ACCOUNT1234567890")), core.WithValueDataBytes([]byte("US"), []byte("295816c03b74e65ac34e5c6dda3c75")))
	if err != nil {
		fmt.Println("Failed to create claim", err)
		return
	}
	encoded, _ = json.Marshal(kycClaim)
	fmt.Printf("-> Issued full KYC claim: %s\n", encoded)

	fmt.Println("-> Add the KYC creds claim to the claims tree\n\n")
	kycHashIndex, kycHashValue, _ := kycClaim.HiHv()
	claimTree.Add(ctx, kycHashIndex, kycHashValue)

	// construct the new identity state
	fmt.Println("Calculate the new state\n")
	newState, _ := merkletree.HashElems(claimTree.Root().BigInt(), revocationTree.Root().BigInt(), rootsTree.Root().BigInt())

	// hash the [genesis state + new state] to be signed later
	hashOldAndNewState, _ := poseidon.Hash([]*big.Int{state.BigInt(), newState.BigInt()})
	// sign using the identity key
	signature := privKey.SignPoseidon(hashOldAndNewState)

	// construct the inputs to feed to the proof generation for the state transition
	fmt.Println("-> state transition from old to new")
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
	homedir, _ := os.UserHomeDir()
	outputFile := filepath.Join(homedir, "iden3_input.json")
	os.WriteFile(outputFile, inputBytes, 0644)
	fmt.Printf("-> Input bytes written to the file: %s\n", outputFile)
}
