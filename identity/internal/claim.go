// Copyright © 2022 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package internal

import (
	"context"
	"encoding/json"
	"flag"
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
)

func IssueClaim() {

	issueCmd := flag.NewFlagSet("claim", flag.ExitOnError)
	issuerNameStr := issueCmd.String("issuer", "", "name of the issuer identity")
	holderIdStr := issueCmd.String("holder", "", "base58-encoded ID of the holder")
	revNonce := issueCmd.Uint64("nonce", 2, "Revocation nonce for the new claim")
	issueCmd.Parse(os.Args[2:])
	if *issuerNameStr == "" {
		fmt.Println("Must specify the name of the issuer with a --issuer parameter")
		os.Exit(1)
	}
	if *holderIdStr == "" {
		fmt.Println("Must specify a base58-encoded ID for the holder with a --holder parameter")
		os.Exit(1)
	}
	if *revNonce <= uint64(1) {
		fmt.Println("Must specify a revocation nonce greater than 1 for the new claim with a --nonce parameter")
		os.Exit(1)
	}
	holderId, err := core.IDFromString(*holderIdStr)
	if err != nil {
		fmt.Println("Failed to use the provided Id: ", err)
		os.Exit(1)
	}
	fmt.Println("Using issuer identity with name: ", *issuerNameStr)
	fmt.Println("Using holder identity: ", *holderIdStr)
	fmt.Println("Using revocation nonce for the new claim: ", *revNonce)

	//
	// Before issuing any claims, we need to first load the ID of the holder
	//
	fmt.Println("Loading issuer identity")
	privKey, err := loadPrivateKey(*issuerNameStr)
	assertNoError(err)
	fmt.Println("-> Issuer private key successfully loaded")

	fmt.Println("Loading issuer ID")
	issuerId, err := loadUserId(*issuerNameStr)
	assertNoError(err)

	ctx := context.Background()
	fmt.Println("Loading issuer state")
	claimsTree, revocationsTree, rootsTree, err := loadState(ctx, issuerNameStr)
	assertNoError(err)

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
	ageClaim, _ := core.NewClaim(kycAgeSchema, core.WithIndexID(holderId), core.WithIndexDataInts(age, nil), core.WithRevocationNonce(*revNonce))
	// kycClaim, err := core.NewClaim(kycSchema, core.WithIndexDataBytes([]byte("Lionel Messi"), []byte("ACCOUNT1234567890")), core.WithValueDataBytes([]byte("US"), []byte("295816c03b74e65ac34e5c6dda3c75")))
	encoded, _ := json.Marshal(ageClaim)
	fmt.Printf("-> Issued age claim: %s\n", encoded)

	// add the age claim to the claim tree
	fmt.Printf("-> Add the age claim to the claims tree\n\n")
	ageHashIndex, ageHashValue, _ := ageClaim.HiHv()
	claimsTree.Add(ctx, ageHashIndex, ageHashValue)

	// from the recovered private key, we can derive the public key and the auth claim
	pubKey := privKey.Public()
	authClaimRevNonce := uint64(1)
	authSchemaHash, _ := getAuthClaimSchemaHash()
	// An auth claim includes the X and Y curve coordinates of the public key, along with the revocation nonce
	authClaim, _ := core.NewClaim(authSchemaHash, core.WithIndexDataInts(pubKey.X, pubKey.Y), core.WithRevocationNonce(authClaimRevNonce))
	hIndex, _ := authClaim.HIndex()
	// generate a merkle proof that the issuer's auth claim is not revoked, based on the latest claims and revocations trees
	authMTProof, _, _ := claimsTree.GenerateProof(ctx, hIndex, claimsTree.Root())
	authNonRevMTProof, _, _ := revocationsTree.GenerateProof(ctx, new(big.Int).SetInt64(int64(authClaimRevNonce)), revocationsTree.Root())

	issuerState, _ := merkletree.HashElems(claimsTree.Root().BigInt(), revocationsTree.Root().BigInt(), rootsTree.Root().BigInt())
	issuerTreeState := circuits.TreeState{
		State:          issuerState,
		ClaimsRoot:     claimsTree.Root(),
		RevocationRoot: revocationsTree.Root(),
		RootOfRoots:    rootsTree.Root(),
	}

	persistClaim(ctx, *issuerNameStr, *holderIdStr, &holderId, ageClaim, *revNonce, claimsTree, revocationsTree, rootsTree, privKey, issuerId, issuerTreeState, authClaim, authMTProof, authNonRevMTProof)
}

func persistClaim(ctx context.Context, issuer, holderIdStr string, holderId *core.ID, ageClaim *core.Claim, ageNonce uint64, claimsTree, revocationsTree, rootsTree *merkletree.MerkleTree, privKey *babyjub.PrivateKey, issuerId *core.ID, genesisTreeState circuits.TreeState, issuerAuthClaim *core.Claim, issuerAuthMTProof *merkletree.Proof, issuerAuthNonRevMTProof *merkletree.Proof) {
	// persists the input for the validity of the issuer identity against the latest state tree
	state, _ := merkletree.HashElems(claimsTree.Root().BigInt(), revocationsTree.Root().BigInt(), rootsTree.Root().BigInt())
	key, value, noAux := getNodeAuxValue(issuerAuthNonRevMTProof.NodeAux)
	a := circuits.AtomicQuerySigInputs{}
	iState := issuerState{
		AuthClaim:               *issuerAuthClaim,
		AuthClaimMtp:            circuits.PrepareSiblingsStr(issuerAuthMTProof.AllSiblings(), a.GetMTLevel()),
		AuthClaimNonRevMtp:      circuits.PrepareSiblingsStr(issuerAuthNonRevMTProof.AllSiblings(), a.GetMTLevel()),
		AuthClaimMtpBytes:       issuerAuthMTProof.Bytes(),
		AuthClaimNonRevMtpBytes: issuerAuthNonRevMTProof.Bytes(),
		AuthClaimNonRevMtpAuxHi: key,
		AuthClaimNonRevMtpAuxHv: value,
		AuthClaimNonRevMtpNoAux: noAux,
		UserID:                  issuerId.BigInt().String(),
		IDState:                 state,
		ClaimsTreeRoot:          claimsTree.Root(),
		RevTreeRoot:             revocationsTree.Root(),
		RootsTreeRoot:           rootsTree.Root(),
	}

	// persists additional inputs used for generating zk proofs by the holder
	// these are candidates for sending to the holder wallet
	ageHashIndex, _, _ := ageClaim.HiHv()
	ageClaimMTProof, _, _ := claimsTree.GenerateProof(ctx, ageHashIndex, claimsTree.Root())
	stateAfterAddingAgeClaim, _ := merkletree.HashElems(claimsTree.Root().BigInt(), revocationsTree.Root().BigInt(), rootsTree.Root().BigInt())
	issuerStateAfterClaimAdd := circuits.TreeState{
		State:          stateAfterAddingAgeClaim,
		ClaimsRoot:     claimsTree.Root(),
		RevocationRoot: revocationsTree.Root(),
		RootOfRoots:    rootsTree.Root(),
	}
	proofNotRevoke, _, _ := revocationsTree.GenerateProof(ctx, big.NewInt(int64(ageNonce)), revocationsTree.Root())
	hashIndex, hashValue, err := claimsIndexValueHashes(*ageClaim)
	if err != nil {
		fmt.Printf("Failed to calculate claim hashes: %s\n", err)
		os.Exit(1)
	}
	commonHash, _ := merkletree.HashElems(hashIndex, hashValue)
	claimSignature := privKey.SignPoseidon(commonHash.BigInt())
	claimIssuerSignature := circuits.BJJSignatureProof{
		IssuerID:           issuerId,
		IssuerTreeState:    genesisTreeState,
		IssuerAuthClaimMTP: issuerAuthMTProof,
		Signature:          claimSignature,
		IssuerAuthClaim:    issuerAuthClaim,
		IssuerAuthNonRevProof: circuits.ClaimNonRevStatus{
			TreeState: genesisTreeState,
			Proof:     issuerAuthNonRevMTProof,
		},
	}
	inputsUserClaim := circuits.Claim{
		Claim:     ageClaim,
		Proof:     ageClaimMTProof,
		TreeState: issuerStateAfterClaimAdd,
		NonRevProof: &circuits.ClaimNonRevStatus{
			TreeState: issuerStateAfterClaimAdd,
			Proof:     proofNotRevoke,
		},
		IssuerID:       issuerId,
		SignatureProof: claimIssuerSignature,
	}
	key, value, noAux = getNodeAuxValue(proofNotRevoke.NodeAux)
	inputs := ClaimInputs{
		IssuerAuthState:            &iState,
		IssuerClaim:                inputsUserClaim.Claim,
		IssuerClaimMtp:             circuits.PrepareSiblingsStr(ageClaimMTProof.AllSiblings(), a.GetMTLevel()),
		IssuerClaimMtpBytes:        ageClaimMTProof.Bytes(),
		IssuerState_State:          issuerStateAfterClaimAdd.State,
		IssuerState_ClaimsTreeRoot: issuerStateAfterClaimAdd.ClaimsRoot,
		IssuerState_RevTreeRoot:    issuerStateAfterClaimAdd.RevocationRoot,
		IssuerState_RootsTreeRoot:  issuerStateAfterClaimAdd.RootOfRoots,
		IssuerClaimNonRevMtp:       circuits.PrepareSiblingsStr(proofNotRevoke.AllSiblings(), a.GetMTLevel()),
		IssuerClaimNonRevMtpBytes:  proofNotRevoke.Bytes(),
		IssuerClaimNonRevMtpAuxHi:  key,
		IssuerClaimNonRevMtpAuxHv:  value,
		IssuerClaimNonRevMtpNoAux:  noAux,
		ClaimSchema:                inputsUserClaim.Claim.GetSchemaHash().BigInt().String(),
		IssuerClaimSignatureR8X:    claimSignature.R8.X.String(),
		IssuerClaimSignatureR8Y:    claimSignature.R8.Y.String(),
		IssuerClaimSignatureS:      claimSignature.S.String(),
	}
	homedir, _ := os.UserHomeDir()
	inputBytes, _ := json.Marshal(inputs)
	outputFile := filepath.Join(homedir, fmt.Sprintf("iden3/%s/claims/%d-%s.json", issuer, ageNonce, holderId))
	_ = os.MkdirAll(filepath.Dir(outputFile), os.ModePerm)
	os.WriteFile(outputFile, inputBytes, 0644)
	fmt.Printf("-> Input bytes for issued user claim written to the file: %s\n", outputFile)
}

func getNodeAuxValue(a *merkletree.NodeAux) (*merkletree.Hash, *merkletree.Hash, string) {

	key := &merkletree.HashZero
	value := &merkletree.HashZero
	noAux := "1"

	if a != nil && a.Value != nil && a.Key != nil {
		key = a.Key
		value = a.Value
		noAux = "0"
	}

	return key, value, noAux
}

func claimsIndexValueHashes(c core.Claim) (*big.Int, *big.Int, error) {
	index, value := c.RawSlots()
	indexHash, err := poseidon.Hash(core.ElemBytesToInts(index[:]))
	if err != nil {
		return nil, nil, err
	}
	valueHash, err := poseidon.Hash(core.ElemBytesToInts(value[:]))
	return indexHash, valueHash, err
}
