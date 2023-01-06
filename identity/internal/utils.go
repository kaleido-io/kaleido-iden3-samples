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
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/iden3/go-circuits"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	merkletree "github.com/iden3/go-merkletree-sql"
	sqlstorage "github.com/iden3/go-merkletree-sql/db/sql"
)

// Captures the properties needed to prove the identity of the issuer
// and it hasn't been revoked
type issuerState struct {
	AuthClaimMtpBytes       []byte           `json:"authClaimMtpBytes,omitempty"`
	AuthClaimNonRevMtpBytes []byte           `json:"authClaimNonRevMtpBytes,omitempty"`
	AuthClaim               core.Claim       `json:"authClaim"`
	UserID                  string           `json:"userID"`
	IDState                 *merkletree.Hash `json:"newUserState"`
	ClaimsTreeRoot          *merkletree.Hash `json:"claimsTreeRoot"`
	RevTreeRoot             *merkletree.Hash `json:"revTreeRoot"`
	RootsTreeRoot           *merkletree.Hash `json:"rootsTreeRoot"`
}

type authClaimAndProofs struct {
	AuthClaim               core.Claim `json:"authClaim"`
	AuthClaimMtpBytes       []byte     `json:"authClaimMtpBytes,omitempty"`
	AuthClaimNonRevMtpBytes []byte     `json:"authClaimNonRevMtpBytes,omitempty"`
}

type stateTransitionInputs struct {
	AuthClaim               core.Claim       `json:"authClaim"`
	AuthClaimMtp            []string         `json:"authClaimMtp"`
	AuthClaimNonRevMtp      []string         `json:"authClaimNonRevMtp"`
	AuthClaimNonRevMtpAuxHi *merkletree.Hash `json:"authClaimNonRevMtpAuxHi"`
	AuthClaimNonRevMtpAuxHv *merkletree.Hash `json:"authClaimNonRevMtpAuxHv"`
	AuthClaimNonRevMtpNoAux string           `json:"authClaimNonRevMtpNoAux"`
	NewIdState              *merkletree.Hash `json:"newUserState"`
	OldIdState              *merkletree.Hash `json:"oldUserState"`
	IsOldStateGenesis       string           `json:"isOldStateGenesis"`
	ClaimsTreeRoot          *merkletree.Hash `json:"claimsTreeRoot"`
	RevTreeRoot             *merkletree.Hash `json:"revTreeRoot"`
	RootsTreeRoot           *merkletree.Hash `json:"rootsTreeRoot"`
	SignatureR8X            string           `json:"signatureR8x"`
	SignatureR8Y            string           `json:"signatureR8y"`
	SignatureS              string           `json:"signatureS"`
}

type ClaimInputs struct {
	IssuerAuthState            *issuerState     `json:"issuerAuthState"`
	IssuerClaim                *core.Claim      `json:"issuerClaim"`
	IssuerClaimMtp             []string         `json:"issuerClaimMtp"`
	IssuerClaimMtpBytes        []byte           `json:"issuerClaimMtpBytes"`
	IssuerState_ClaimsTreeRoot *merkletree.Hash `json:"issuerState_ClaimsTreeRoot"`
	IssuerState_RevTreeRoot    *merkletree.Hash `json:"issuerState_RevTreeRoot"`
	IssuerState_RootsTreeRoot  *merkletree.Hash `json:"issuerState_RootsTreeRoot"`
	IssuerState_State          *merkletree.Hash `json:"issuerState_State"`
	IssuerClaimNonRevMtp       []string         `json:"issuerClaimNonRevMtp"`
	IssuerClaimNonRevMtpBytes  []byte           `json:"issuerClaimNonRevMtpBytes"`
	IssuerClaimNonRevMtpAuxHi  *merkletree.Hash `json:"issuerClaimNonRevMtpAuxHi"`
	IssuerClaimNonRevMtpAuxHv  *merkletree.Hash `json:"issuerClaimNonRevMtpAuxHv"`
	IssuerClaimNonRevMtpNoAux  string           `json:"issuerClaimNonRevMtpNoAux"`
	ClaimSchema                string           `json:"claimSchema"`
	IssuerClaimSignatureR8X    string           `json:"issuerClaimSignatureR8x"`
	IssuerClaimSignatureR8Y    string           `json:"issuerClaimSignatureR8y"`
	IssuerClaimSignatureS      string           `json:"issuerClaimSignatureS"`
}

func getPrivateKeyPath(name string) string {
	homedir, _ := os.UserHomeDir()
	return filepath.Join(homedir, fmt.Sprintf("iden3/%s/private.key", name))
}

func loadPrivateKey(name string) (*babyjub.PrivateKey, error) {
	keyBytes, err := os.ReadFile(getPrivateKeyPath(name))
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %s", err)
	}
	var key32Bytes [32]byte
	copy(key32Bytes[:], keyBytes)
	privKey := babyjub.PrivateKey(key32Bytes)
	return &privKey, nil
}

func getAuthClaimSchemaHash() (core.SchemaHash, error) {
	return core.NewSchemaHashFromHex("ca938857241db9451ea329256b9c06e5")
}

type IdentityLookupMap map[string]string

func updateIdentifyLookupFile(identifyName string, identifyID string) {
	homedir, _ := os.UserHomeDir()
	lookupFilename := filepath.Join(homedir, "iden3/identities.json")
	mapToSave := map[string]string{}
	existingMapContent, err := os.ReadFile(lookupFilename)
	if os.IsNotExist(err) {
		_ = os.MkdirAll(filepath.Dir(lookupFilename), os.ModePerm)
	} else {
		err = json.Unmarshal(existingMapContent, &mapToSave)
		assertNoError(err)
	}
	mapToSave[identifyName] = identifyID
	inputBytes, _ := json.MarshalIndent(mapToSave, "", "  ")
	err = os.WriteFile(lookupFilename, inputBytes, 0644)
	assertNoError(err)
}

// the genesis state is used for proving an identity's auth claim when generating any proof
func persistGenesisState(name string, id *core.ID, claimsTreeRoot, revTreeRoot, rootsTreeRoot *merkletree.Hash, authClaim *core.Claim) error {
	state, _ := merkletree.HashElems(claimsTreeRoot.BigInt(), revTreeRoot.BigInt(), rootsTreeRoot.BigInt())
	genState := issuerState{
		AuthClaim:      *authClaim,
		UserID:         id.BigInt().String(),
		IDState:        state,
		ClaimsTreeRoot: claimsTreeRoot,
		RevTreeRoot:    revTreeRoot,
		RootsTreeRoot:  rootsTreeRoot,
	}
	inputBytes, _ := json.MarshalIndent(genState, "", "  ")
	homedir, _ := os.UserHomeDir()
	outputFile := filepath.Join(homedir, fmt.Sprintf("iden3/%s/genesis_state.json", name))
	_ = os.MkdirAll(filepath.Dir(outputFile), os.ModePerm)
	err := os.WriteFile(outputFile, inputBytes, 0644)
	if err != nil {
		return err
	}
	fmt.Printf("-> Input bytes for the identity's genesis state written to the file: %s\n", outputFile)
	return nil
}

func loadGenesisState(name string) (*issuerState, error) {
	homedir, _ := os.UserHomeDir()
	inputFile := filepath.Join(homedir, fmt.Sprintf("iden3/%s/genesis_state.json", name))
	content, err := os.ReadFile(inputFile)
	if err != nil {
		return nil, err
	}
	var genesisState issuerState
	err = json.Unmarshal(content, &genesisState)
	if err != nil {
		return nil, err
	}
	return &genesisState, nil
}

type TreeState struct {
	IdentityState  *merkletree.Hash `json:"identityState"`
	ClaimsTreeRoot *merkletree.Hash `json:"claimsTreeRoot"`
	RevTreeRoot    *merkletree.Hash `json:"revTreeRoot"`
	RootsTreeRoot  *merkletree.Hash `json:"rootsTreeRoot"`
}

type TreeStates struct {
	Old *TreeState `json:"old"`
	New *TreeState `json:"new"`
}

func persistNewState(name string, claimsTree, revocationsTree, rootsTree *merkletree.MerkleTree, oldTreeState circuits.TreeState, privKey babyjub.PrivateKey, authClaimProof *authClaimAndProofs, isGenesis bool) error {
	// construct the new identity state
	fmt.Println("Calculate the new state")
	newState, err := merkletree.HashElems(claimsTree.Root().BigInt(), revocationsTree.Root().BigInt(), rootsTree.Root().BigInt())
	if err != nil {
		return err
	}

	// hash the [old state + new state] to be signed later
	hashOldAndNewState, _ := poseidon.Hash([]*big.Int{oldTreeState.State.BigInt(), newState.BigInt()})
	// sign using the identity key
	signature := privKey.SignPoseidon(hashOldAndNewState)

	// construct the inputs to feed to the proof generation for the state transition
	fmt.Println("-> state transition from old to new")
	isOldStateGenesis := "0"
	if isGenesis {
		isOldStateGenesis = "1"
	}

	authMTProof, err := merkletree.NewProofFromBytes(authClaimProof.AuthClaimMtpBytes)
	assertNoError(err)

	authNonRevMTProof, err := merkletree.NewProofFromBytes(authClaimProof.AuthClaimNonRevMtpBytes)
	assertNoError(err)
	key, value, noAux := getNodeAuxValue(authNonRevMTProof.NodeAux)
	a := circuits.AtomicQuerySigInputs{}
	stateTransitionInputs := stateTransitionInputs{
		AuthClaim:               *&authClaimProof.AuthClaim,
		AuthClaimMtp:            circuits.PrepareSiblingsStr(authMTProof.AllSiblings(), a.GetMTLevel()),
		AuthClaimNonRevMtp:      circuits.PrepareSiblingsStr(authNonRevMTProof.AllSiblings(), a.GetMTLevel()),
		AuthClaimNonRevMtpAuxHi: key,
		AuthClaimNonRevMtpAuxHv: value,
		AuthClaimNonRevMtpNoAux: noAux,
		NewIdState:              newState,
		OldIdState:              oldTreeState.State,
		IsOldStateGenesis:       isOldStateGenesis,
		ClaimsTreeRoot:          oldTreeState.ClaimsRoot,
		RevTreeRoot:             oldTreeState.RevocationRoot,
		RootsTreeRoot:           oldTreeState.RootOfRoots,
		SignatureR8X:            signature.R8.X.String(),
		SignatureR8Y:            signature.R8.Y.String(),
		SignatureS:              signature.S.String(),
	}

	homedir, _ := os.UserHomeDir()
	inputBytes, err := json.MarshalIndent(stateTransitionInputs, "", "  ")
	if err != nil {
		return err
	}
	outputFile := filepath.Join(homedir, fmt.Sprintf("iden3/%s/stateTransition_inputs.json", name))
	err = os.WriteFile(outputFile, inputBytes, 0644)
	if err != nil {
		return err
	}
	fmt.Printf("-> State transition input bytes written to the file: %s\n", outputFile)

	treeStates := TreeStates{
		Old: &TreeState{
			IdentityState:  oldTreeState.State,
			ClaimsTreeRoot: oldTreeState.ClaimsRoot,
			RevTreeRoot:    oldTreeState.RevocationRoot,
			RootsTreeRoot:  oldTreeState.RootOfRoots,
		},
		New: &TreeState{
			IdentityState:  newState,
			ClaimsTreeRoot: claimsTree.Root(),
			RevTreeRoot:    revocationsTree.Root(),
			RootsTreeRoot:  rootsTree.Root(),
		},
	}
	inputBytes2, err := json.MarshalIndent(treeStates, "", "  ")
	if err != nil {
		return err
	}
	outputFile2 := filepath.Join(homedir, fmt.Sprintf("iden3/%s/treeStates.json", name))
	err = os.WriteFile(outputFile2, inputBytes2, 0644)
	if err != nil {
		return err
	}
	fmt.Printf("-> Tree states written into file: %s\n", outputFile2)
	return nil
}

func loadPendingState(name string) (*stateTransitionInputs, error) {
	homedir, _ := os.UserHomeDir()
	inputFile := filepath.Join(homedir, fmt.Sprintf("iden3/%s/stateTransition_inputs.json", name))
	content, err := os.ReadFile(inputFile)
	if err != nil {
		return nil, err
	}
	var sti stateTransitionInputs
	err = json.Unmarshal(content, &sti)
	if err != nil {
		return nil, err
	}
	return &sti, nil
}

func loadState(ctx context.Context, issuerNameStr *string) (*merkletree.MerkleTree, *merkletree.MerkleTree, *merkletree.MerkleTree, error) {
	claimsDB, revsDB, rootsDB, err := initMerkleTreeDBs(*issuerNameStr)
	if err != nil {
		fmt.Println(err)
		return nil, nil, nil, err
	}
	claimsStorage := sqlstorage.NewSqlStorage(&sqlDB{db: claimsDB}, 1)
	revsStorage := sqlstorage.NewSqlStorage(&sqlDB{db: revsDB}, 1)
	rootsStorage := sqlstorage.NewSqlStorage(&sqlDB{db: rootsDB}, 1)

	fmt.Println("Load the issuer claims merkle tree")
	claimsTree, err := merkletree.NewMerkleTree(ctx, claimsStorage, 32)
	if err != nil {
		fmt.Println(err)
		return nil, nil, nil, err
	}
	fmt.Println("Load the revocations merkle tree")
	revocationsTree, err := merkletree.NewMerkleTree(ctx, revsStorage, 32)
	if err != nil {
		fmt.Println(err)
		return nil, nil, nil, err
	}
	fmt.Printf("Load the roots merkle tree\n")
	rootsTree, err := merkletree.NewMerkleTree(ctx, rootsStorage, 32)
	if err != nil {
		fmt.Println(err)
		return nil, nil, nil, err
	}
	return claimsTree, revocationsTree, rootsTree, nil
}

func loadUserId(issuerNameStr string) (*core.ID, error) {
	homedir, _ := os.UserHomeDir()
	issuerIdBytes, _ := os.ReadFile(filepath.Join(homedir, fmt.Sprintf("iden3/%s/genesis_state.json", issuerNameStr)))
	var issuerIdInputs map[string]interface{}
	err := json.Unmarshal(issuerIdBytes, &issuerIdInputs)
	if err != nil {
		fmt.Printf("-> Failed to read identity '%s' ID file: %s\n", issuerNameStr, err)
		return nil, err
	}
	issuerIdStr := issuerIdInputs["userID"].(string)
	issuerIdBigInt := &big.Int{}
	issuerIdBigInt.SetString(issuerIdStr, 10)
	issuerId, err := core.IDFromInt(issuerIdBigInt)
	fmt.Println("-> Issuer identity: ", issuerId.String())
	if err != nil {
		fmt.Printf("-> Failed to load issuer ID from string: %s\n", err)
		os.Exit(1)
	}
	return &issuerId, nil
}

func assertNoError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
