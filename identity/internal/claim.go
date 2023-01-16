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
		fmt.Println("Failed to parse the provided holder ID: ", err)
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

	fmt.Println("Issue the claim")

	// create the basic claim, independent of issuer and prev state
	basicClaim := createBasicClaim(holderId, *revNonce)

	// issue the claim relative to prev state and persist it
	issueClaim(basicClaim, issuerNameStr, *issuerId, holderId, privKey, *revNonce)
}

func createBasicClaim(holderId core.ID, revNonce uint64) *core.Claim {
	// Load the schema for the claim
	schemaBytes, _ := os.ReadFile("./schemas/kyc.json-ld")
	var sHash core.SchemaHash

	h := keccak256.Hash(schemaBytes, []byte("AgeCredential"))
	copy(sHash[:], h[len(h)-16:])
	schemaHashHex, _ := sHash.MarshalText()
	fmt.Println("-> Schema hash for 'AgeCredential':", string(schemaHashHex))

	kycAgeSchema, _ := core.NewSchemaHashFromHex(string(schemaHashHex))
	birthDay := big.NewInt(19950704)
	claim, _ := core.NewClaim(kycAgeSchema, core.WithIndexID(holderId), core.WithIndexDataInts(birthDay, nil), core.WithRevocationNonce(revNonce))

	return claim
}

func issueClaim(basicClaim *core.Claim, issuerNameStr *string, issuerId core.ID, holderId core.ID, privKey *babyjub.PrivateKey, revNonce uint64) {
	ctx := context.Background()

	fmt.Println("Loading issuer state")
	claimsTree, revocationsTree, rootsTree, err := loadState(ctx, issuerNameStr)
	assertNoError(err)

	// before adding any claims work out the old state
	var issuerRecordedTreeState circuits.TreeState
	// is there is already a pending state change, copy the old state from there
	// so that we can batch claim additions together
	pendingIssuerState, err := loadPendingState(*issuerNameStr)
	if err != nil {
		if os.IsNotExist(err) {
			// there is no pending state, it's fine to calculate the old state from the merkle tree roots
			issuerState, _ := merkletree.HashElems(claimsTree.Root().BigInt(), revocationsTree.Root().BigInt(), rootsTree.Root().BigInt())
			issuerRecordedTreeState = circuits.TreeState{
				State:          issuerState,
				ClaimsRoot:     claimsTree.Root(),
				RevocationRoot: revocationsTree.Root(),
				RootOfRoots:    rootsTree.Root(),
			}
		} else {
			assertNoError(err)
		}
	} else {
		issuerRecordedTreeState = circuits.TreeState{
			State:          pendingIssuerState.OldIdState,
			ClaimsRoot:     pendingIssuerState.ClaimsTreeRoot,
			RevocationRoot: pendingIssuerState.RevTreeRoot,
			RootOfRoots:    pendingIssuerState.RootsTreeRoot,
		}
	}

	// from the recovered private key, we can derive the public key and the auth claim
	pubKey := privKey.Public()
	authClaimRevNonce := uint64(1)
	authSchemaHash, _ := getAuthClaimSchemaHash()
	// An auth claim includes the X and Y curve coordinates of the public key, along with the revocation nonce
	authClaim, _ := core.NewClaim(authSchemaHash, core.WithIndexDataInts(pubKey.X, pubKey.Y), core.WithRevocationNonce(authClaimRevNonce))

	// Generate a merkle proof that the issuer's auth claim is not revoked
	// The merkle proof for the issuer auth claim used in generating the zkp is based on the state before the claims are added
	issuerPreviousState, err := loadGenesisState(*issuerNameStr)
	assertNoError(err)
	issuerPreviousState.ClaimsTreeRoot = issuerRecordedTreeState.ClaimsRoot
	issuerPreviousState.RevTreeRoot = issuerRecordedTreeState.RevocationRoot
	issuerPreviousState.RootsTreeRoot = issuerRecordedTreeState.RootOfRoots

	hIndex, _ := authClaim.HIndex()

	authMTProof, _, err := claimsTree.GenerateProof(ctx, hIndex, issuerPreviousState.ClaimsTreeRoot)
	if err != nil {
		fmt.Printf("Failed to generate issuer auth claim proof: %s\n", err)
		os.Exit(1)
	}
	authNonRevMTProof, _, _ := revocationsTree.GenerateProof(ctx, new(big.Int).SetInt64(int64(authClaim.GetRevocationNonce())), issuerPreviousState.RevTreeRoot)
	if err != nil {
		fmt.Printf("Failed to recover issuer auth claim non rev proof from saved bytes: %s\n", err)
		os.Exit(1)
	}

	issuerPreviousState.AuthClaimMtpBytes = authMTProof.Bytes()
	issuerPreviousState.AuthClaimNonRevMtpBytes = authNonRevMTProof.Bytes()

	claimJson, _ := json.MarshalIndent(basicClaim, "", "  ")
	fmt.Printf("-> Issued claim: %s\n", claimJson)

	persistClaim(ctx, *issuerNameStr, holderId, basicClaim, revNonce, claimsTree, revocationsTree, rootsTree, privKey, issuerId, issuerRecordedTreeState, issuerPreviousState, authClaim)
}

func persistClaim(ctx context.Context, issuer string, holderId core.ID, basicClaim *core.Claim, revNonce uint64, claimsTree, revocationsTree, rootsTree *merkletree.MerkleTree, privKey *babyjub.PrivateKey, issuerId core.ID, issuerRecordedTreeState circuits.TreeState, issuerPreviousState *issuerState, issuerAuthClaim *core.Claim) {

	issuerAuthMTProof, err := merkletree.NewProofFromBytes(issuerPreviousState.AuthClaimMtpBytes)
	assertNoError(err)

	issuerAuthNonRevMTProof, err := merkletree.NewProofFromBytes(issuerPreviousState.AuthClaimNonRevMtpBytes)
	assertNoError(err)

	// add the claim to the claim tree
	fmt.Printf("-> Add the claim to the claims tree\n\n")
	claimHashIndex, claimHashValue, _ := basicClaim.HiHv()
	claimsTree.Add(ctx, claimHashIndex, claimHashValue)

	fmt.Printf("-> Add the current claim tree root to the roots tree\n")
	err = rootsTree.Add(ctx, claimsTree.Root().BigInt(), big.NewInt(0))
	assertNoError(err)

	// persists the input for the validity of the issuer identity against the latest state tree
	a := circuits.AtomicQuerySigInputs{}

	// persists additional inputs used for generating zk proofs by the holder
	// these are candidates for sending to the holder wallet
	basicClaimMTProof, _, _ := claimsTree.GenerateProof(ctx, claimHashIndex, claimsTree.Root())
	stateAfterAddingClaim, _ := merkletree.HashElems(claimsTree.Root().BigInt(), revocationsTree.Root().BigInt(), rootsTree.Root().BigInt())
	issuerStateAfterClaimAdd := circuits.TreeState{
		State:          stateAfterAddingClaim,
		ClaimsRoot:     claimsTree.Root(),
		RevocationRoot: revocationsTree.Root(),
		RootOfRoots:    rootsTree.Root(),
	}
	proofNotRevoke, _, _ := revocationsTree.GenerateProof(ctx, big.NewInt(int64(revNonce)), revocationsTree.Root())
	hashIndex, hashValue, err := claimsIndexValueHashes(*basicClaim)
	if err != nil {
		fmt.Printf("Failed to calculate claim hashes: %s\n", err)
		os.Exit(1)
	}
	commonHash, _ := merkletree.HashElems(hashIndex, hashValue)
	claimSignature := privKey.SignPoseidon(commonHash.BigInt())

	claimIssuerSignature := circuits.BJJSignatureProof{
		IssuerID:           &issuerId,
		IssuerTreeState:    issuerRecordedTreeState,
		IssuerAuthClaimMTP: issuerAuthMTProof,
		Signature:          claimSignature,
		IssuerAuthClaim:    &issuerPreviousState.AuthClaim,
		IssuerAuthNonRevProof: circuits.ClaimNonRevStatus{
			TreeState: issuerRecordedTreeState,
			Proof:     issuerAuthNonRevMTProof,
		},
	}
	inputsUserClaim := circuits.Claim{
		Claim:     basicClaim,
		Proof:     basicClaimMTProof,
		TreeState: issuerStateAfterClaimAdd,
		NonRevProof: &circuits.ClaimNonRevStatus{
			TreeState: issuerStateAfterClaimAdd,
			Proof:     proofNotRevoke,
		},
		IssuerID:       &issuerId,
		SignatureProof: claimIssuerSignature,
	}
	key, value, noAux := getNodeAuxValue(proofNotRevoke.NodeAux)
	issuerPreviousState.AuthClaimMtp = circuits.PrepareSiblingsStr(issuerAuthMTProof.AllSiblings(), a.GetMTLevel())
	issuerPreviousState.AuthClaimNonRevMtp = circuits.PrepareSiblingsStr(issuerAuthNonRevMTProof.AllSiblings(), a.GetMTLevel())
	issuerPreviousState.AuthClaimNonRevMtpAuxHi = key
	issuerPreviousState.AuthClaimNonRevMtpAuxHv = value
	issuerPreviousState.AuthClaimNonRevMtpNoAux = noAux
	inputs := ClaimInputs{
		IssuerAuthState:            issuerPreviousState,
		IssuerClaim:                inputsUserClaim.Claim,
		IssuerClaimMtp:             circuits.PrepareSiblingsStr(basicClaimMTProof.AllSiblings(), a.GetMTLevel()),
		IssuerClaimMtpBytes:        basicClaimMTProof.Bytes(),
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
	inputBytes, _ := json.MarshalIndent(inputs, "", "  ")
	outputFile := filepath.Join(homedir, fmt.Sprintf("iden3/%s/claims/%d-%s.json", issuer, revNonce, &holderId))
	_ = os.MkdirAll(filepath.Dir(outputFile), os.ModePerm)
	os.WriteFile(outputFile, inputBytes, 0644)
	fmt.Printf("-> Input bytes for issued user claim written to the file: %s\n", outputFile)

	err = persistNewState(issuer, claimsTree, revocationsTree, rootsTree, issuerRecordedTreeState, *privKey, &authClaimAndProofs{
		AuthClaim:               issuerPreviousState.AuthClaim,
		AuthClaimMtpBytes:       issuerPreviousState.AuthClaimMtpBytes,
		AuthClaimNonRevMtpBytes: issuerPreviousState.AuthClaimNonRevMtpBytes,
	}, false)
	assertNoError(err)
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
