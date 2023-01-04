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
	AuthClaim               core.Claim       `json:"authClaim"`
	AuthClaimMtp            []string         `json:"authClaimMtp"`
	AuthClaimNonRevMtp      []string         `json:"authClaimNonRevMtp"`
	AuthClaimMtpBytes       []byte           `json:"authClaimMtpBytes"`
	AuthClaimNonRevMtpBytes []byte           `json:"authClaimNonRevMtpBytes"`
	AuthClaimNonRevMtpAuxHi *merkletree.Hash `json:"authClaimNonRevMtpAuxHi"`
	AuthClaimNonRevMtpAuxHv *merkletree.Hash `json:"authClaimNonRevMtpAuxHv"`
	AuthClaimNonRevMtpNoAux string           `json:"authClaimNonRevMtpNoAux"`
	UserID                  string           `json:"userID"`
	IDState                 *merkletree.Hash `json:"newUserState"`
	ClaimsTreeRoot          *merkletree.Hash `json:"claimsTreeRoot"`
	RevTreeRoot             *merkletree.Hash `json:"revTreeRoot"`
	RootsTreeRoot           *merkletree.Hash `json:"rootsTreeRoot"`
}

type stateTransitionInputs struct {
	NewIdState        *merkletree.Hash `json:"newUserState"`
	OldIdState        *merkletree.Hash `json:"oldUserState"`
	IsOldStateGenesis string           `json:"isOldStateGenesis"`
	ClaimsTreeRoot    *merkletree.Hash `json:"claimsTreeRoot"`
	RevTreeRoot       *merkletree.Hash `json:"revTreeRoot"`
	RootsTreeRoot     *merkletree.Hash `json:"rootsTreeRoot"`
	SignatureR8X      string           `json:"signatureR8x"`
	SignatureR8Y      string           `json:"signatureR8y"`
	SignatureS        string           `json:"signatureS"`
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

// the genesis state is used for proving an identity's auth claim when generating any proof
func persistGenesisState(name string, id *core.ID, claimsTreeRoot, revTreeRoot, rootsTreeRoot *merkletree.Hash, authClaim *core.Claim, authMTProof, authNonRevMTProof *merkletree.Proof) error {
	state, _ := merkletree.HashElems(claimsTreeRoot.BigInt(), revTreeRoot.BigInt(), rootsTreeRoot.BigInt())
	key, value, noAux := getNodeAuxValue(authNonRevMTProof.NodeAux)
	a := circuits.AtomicQuerySigInputs{}
	genState := issuerState{
		AuthClaim:               *authClaim,
		AuthClaimMtp:            circuits.PrepareSiblingsStr(authMTProof.AllSiblings(), a.GetMTLevel()),
		AuthClaimMtpBytes:       authMTProof.Bytes(),
		AuthClaimNonRevMtp:      circuits.PrepareSiblingsStr(authNonRevMTProof.AllSiblings(), a.GetMTLevel()),
		AuthClaimNonRevMtpBytes: authNonRevMTProof.Bytes(),
		AuthClaimNonRevMtpAuxHi: key,
		AuthClaimNonRevMtpAuxHv: value,
		AuthClaimNonRevMtpNoAux: noAux,
		UserID:                  id.BigInt().String(),
		IDState:                 state,
		ClaimsTreeRoot:          claimsTreeRoot,
		RevTreeRoot:             revTreeRoot,
		RootsTreeRoot:           rootsTreeRoot,
	}
	inputBytes, _ := json.Marshal(genState)
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

func persistNewState(name string, claimsTree, revocationsTree, rootsTree *merkletree.MerkleTree, oldTreeState circuits.TreeState, privKey babyjub.PrivateKey) error {
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
	if oldTreeState.RevocationRoot.String() == "0" && oldTreeState.RootOfRoots.String() == "0" {
		isOldStateGenesis = "1"
	}
	stateTransitionInputs := stateTransitionInputs{
		NewIdState:        newState,
		OldIdState:        oldTreeState.State,
		IsOldStateGenesis: isOldStateGenesis,
		ClaimsTreeRoot:    oldTreeState.ClaimsRoot,
		RevTreeRoot:       oldTreeState.RevocationRoot,
		RootsTreeRoot:     oldTreeState.RootOfRoots,
		SignatureR8X:      signature.R8.X.String(),
		SignatureR8Y:      signature.R8.Y.String(),
		SignatureS:        signature.S.String(),
	}

	homedir, _ := os.UserHomeDir()
	inputBytes, err := json.Marshal(stateTransitionInputs)
	if err != nil {
		return err
	}
	outputFile := filepath.Join(homedir, fmt.Sprintf("iden3/%s/stateTransition_inputs.json", name))
	err = os.WriteFile(outputFile, inputBytes, 0644)
	if err != nil {
		return err
	}
	fmt.Printf("-> State transition input bytes written to the file: %s\n", outputFile)
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
