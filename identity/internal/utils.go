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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	core "github.com/iden3/go-iden3-core"
	merkletree "github.com/iden3/go-merkletree-sql"
)

// Captures the properties needed to prove the identity of the issuer
// and it hasn't been revoked
type AuthClaimWithProof struct {
	AuthClaim core.Claim `json:"authClaim"`

	// proof of the membership in claims tree for the auth claim
	AuthClaimMtp []string `json:"authClaimMtp,omitempty"`

	// proof of the non-membership in revocation tree for the auth claim
	AuthClaimNonRevMtp      []string         `json:"authClaimNonRevMtp,omitempty"`
	AuthClaimNonRevMtpAuxHi *merkletree.Hash `json:"authClaimNonRevMtpAuxHi,omitempty"`
	AuthClaimNonRevMtpAuxHv *merkletree.Hash `json:"authClaimNonRevMtpAuxHv,omitempty"`
	AuthClaimNonRevMtpNoAux string           `json:"authClaimNonRevMtpNoAux,omitempty"`

	// id of the owning identity
	UserID string `json:"userID"`

	// tree roots of when the proofs were generated
	ClaimsTreeRoot *merkletree.Hash `json:"claimsTreeRoot"`
	RevTreeRoot    *merkletree.Hash `json:"revTreeRoot"`
	RootsTreeRoot  *merkletree.Hash `json:"rootsTreeRoot"`

	// TODO: figure out whether the following attributes are necessary
	IDState                 *merkletree.Hash `json:"newUserState"`
	AuthClaimMtpBytes       []byte           `json:"authClaimMtpBytes,omitempty"`
	AuthClaimNonRevMtpBytes []byte           `json:"authClaimNonRevMtpBytes,omitempty"`
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

type ClaimInputsForSigCircuit struct {
	// inputs required to prove the auth claim (contains public key of a babyJubJub key pairs)
	// that is linked to the selected private key is still valid
	//   - it's in the claims tree of the issuer identity
	//   - it's not in the revocation tree of the issuer identity
	IssuerAuthClaimWithProof *AuthClaimWithProof `json:"issuerAuthState"`

	IssuerClaim *core.Claim `json:"issuerClaim"`
	ClaimSchema string      `json:"claimSchema"`

	// proof of the non-membership in revocation tree for the claim
	IssuerClaimNonRevMtp      []string         `json:"issuerClaimNonRevMtp"`
	IssuerClaimNonRevMtpAuxHi *merkletree.Hash `json:"issuerClaimNonRevMtpAuxHi"`
	IssuerClaimNonRevMtpAuxHv *merkletree.Hash `json:"issuerClaimNonRevMtpAuxHv"`
	IssuerClaimNonRevMtpNoAux string           `json:"issuerClaimNonRevMtpNoAux"`

	IssuerState_State          *merkletree.Hash `json:"issuerState_State"`
	IssuerState_ClaimsTreeRoot *merkletree.Hash `json:"issuerState_ClaimsTreeRoot"`
	IssuerState_RevTreeRoot    *merkletree.Hash `json:"issuerState_RevTreeRoot"`
	IssuerState_RootsTreeRoot  *merkletree.Hash `json:"issuerState_RootsTreeRoot"`

	// signature to prove the claim is issued using the selected private key of the issuer identity
	IssuerClaimSignatureR8X string `json:"issuerClaimSignatureR8x"`
	IssuerClaimSignatureR8Y string `json:"issuerClaimSignatureR8y"`
	IssuerClaimSignatureS   string `json:"issuerClaimSignatureS"`

	// TODO: figure out whether the following attribute is necessary
	IssuerClaimNonRevMtpBytes []byte `json:"issuerClaimNonRevMtpBytes"`
}

// Not currently used
type ClaimInputsForMTPCircuit struct {
	// inputs required to prove the auth claim (contains public key of a babyJubJub key pairs)
	// that is linked to the selected private key is still valid
	//   - it's in the claims tree of the issuer identity
	//   - it's not in the revocation tree of the issuer identity
	IssuerAuthClaimWithProof *AuthClaimWithProof `json:"issuerAuthState"`

	IssuerClaim *core.Claim `json:"issuerClaim"`
	ClaimSchema string      `json:"claimSchema"`

	// proof of the membership in claims tree for the claim
	IssuerClaimMtp []string `json:"issuerClaimMtp"`

	// proof of the non-membership in revocation tree for the claim
	IssuerClaimNonRevMtp      []string         `json:"issuerClaimNonRevMtp"`
	IssuerClaimNonRevMtpAuxHi *merkletree.Hash `json:"issuerClaimNonRevMtpAuxHi"`
	IssuerClaimNonRevMtpAuxHv *merkletree.Hash `json:"issuerClaimNonRevMtpAuxHv"`
	IssuerClaimNonRevMtpNoAux string           `json:"issuerClaimNonRevMtpNoAux"`

	IssuerState_State          *merkletree.Hash `json:"issuerState_State"`
	IssuerState_ClaimsTreeRoot *merkletree.Hash `json:"issuerState_ClaimsTreeRoot"`
	IssuerState_RevTreeRoot    *merkletree.Hash `json:"issuerState_RevTreeRoot"`
	IssuerState_RootsTreeRoot  *merkletree.Hash `json:"issuerState_RootsTreeRoot"`

	// signature to prove the claim is issued using the selected private key of the issuer identity
	IssuerClaimSignatureR8X string `json:"issuerClaimSignatureR8x"`
	IssuerClaimSignatureR8Y string `json:"issuerClaimSignatureR8y"`
	IssuerClaimSignatureS   string `json:"issuerClaimSignatureS"`
}

func getAuthClaimSchemaHash() (core.SchemaHash, error) {
	// https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/auth.json-ld
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

func assertNoError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func getWorkDir(identityName string) string {
	workDir := os.Getenv("IDEN3_WORKDIR")
	if workDir == "" {
		homeDir, _ := os.UserHomeDir()
		workDir = filepath.Join(homeDir, fmt.Sprintf("iden3/%s", identityName))
	}
	return workDir

}
