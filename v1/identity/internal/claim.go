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
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"time"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/poseidon"
	merkletree "github.com/iden3/go-merkletree-sql"
)

type ClaimRecord struct {
	Name string `json:"name"` // NOTE: this is not part of the iden3 protocol

	// issuer identity proofs
	IssuerAuthClaimWithProof *AuthClaimWithProof `json:"issuerAuthClaimWithProof,omitempty"` // not applicable for the genesis auth claim
	IssuerClaimSignatureR8X  string              `json:"issuerClaimSignatureR8x,omitempty"`  // not applicable for the genesis auth claim
	IssuerClaimSignatureR8Y  string              `json:"issuerClaimSignatureR8y,omitempty"`  // not applicable for the genesis auth claim
	IssuerClaimSignatureS    string              `json:"issuerClaimSignatureS,omitempty"`    // not applicable for the genesis auth claim

	Claim               *core.Claim  `json:"claim"`
	IncludedInClaimTree bool         `json:"includedInClaimTree"`
	PublishInfo         *PublishInfo `json:"publishInfo,omitempty"`
}

type PublishInfo struct {
	BlockNumber   int64     `json:"blockNumber"`
	Timestamp     time.Time `json:"timestamp"`
	IdentityState string    `json:"identityState"`
}

func (cr *ClaimRecord) persist(workDir string) {
	inputBytes, _ := json.MarshalIndent(cr, "", "  ")
	outputFile := filepath.Join(workDir, fmt.Sprintf("private/claims/%s.json", cr.Name))
	_ = os.MkdirAll(filepath.Dir(outputFile), os.ModePerm)
	fmt.Printf("   -> Persisting claim to %s\n", outputFile)
	os.WriteFile(outputFile, inputBytes, 0644)
}

func GetAuthClaimRecordFromIdentityStorageByKeyName(workDir, keyName string) *ClaimRecord {
	authSchemaHash, _ := getAuthClaimSchemaHash()
	authClaimFile := filepath.Join(workDir, fmt.Sprintf("private/claims/%s.json", fmt.Sprintf("authClaim-%s-%s", hex.EncodeToString(authSchemaHash[:]), keyName)))
	authClaim := new(ClaimRecord)

	content, err := os.ReadFile(authClaimFile)
	if err != nil {
		assertNoError(err)
	}

	err = json.Unmarshal(content, &authClaim)
	if err != nil {
		assertNoError(err)
	}
	return authClaim
}

func IssueClaim() {

	issueCmd := flag.NewFlagSet("claim", flag.ExitOnError)
	issuerNameStr := issueCmd.String("issuer", "", "name of the issuer identity")
	holderNameStr := issueCmd.String("holder", "", "name of the holder identity")
	schemaFile := issueCmd.String("schemaFile", "", "schema file to use (default is Polygon ID's KYC schema)")
	schemaType := issueCmd.String("schemaType", "AgeCredential", "schema type to use")
	indexDataStrA := issueCmd.String("indexDataA", "", "integer or string to set in index data slot A (string must use double quotes; its hash is stored)")
	indexDataStrB := issueCmd.String("indexDataB", "", "integer or string to set in index data slot B")
	valueDataStrA := issueCmd.String("valueDataA", "", "integer or string to set in value data slot A")
	valueDataStrB := issueCmd.String("valueDataB", "", "integer or string to set in value data slot B")
	expiryStr := issueCmd.String("expiry", "", "expiry time of claim in RFC3339 format (e.g. 2023-04-11T12:34:56Z, default is no expiry)")
	expiryDays := issueCmd.Int("expiryDays", 0, "expiry time of claim in days from now (0 for no expiry)")

	issueCmd.Parse(os.Args[2:])
	if *issuerNameStr == "" {
		fmt.Println("Must specify the name of the issuer using --issuer")
		os.Exit(1)
	}
	if *holderNameStr == "" {
		fmt.Println("Must specify the name of the holder using --holder")
		os.Exit(1)
	}
	if *schemaFile == "" {
		*schemaFile = "./schemas/kyc.json-ld"
	}
	if *schemaType == "" {
		fmt.Println("Must specify a schema type using --schemaType")
		os.Exit(1)
	}
	// Parse index and value data
	indexData := [2]*big.Int{
		parseValueArg("--indexDataA", *indexDataStrA),
		parseValueArg("--indexDataB", *indexDataStrB),
	}
	valueData := [2]*big.Int{
		parseValueArg("--valueDataA", *valueDataStrA),
		parseValueArg("--valueDataB", *valueDataStrB),
	}

	// Parse expiry date / duration
	expiryDate := parseExpiry(*expiryStr, *expiryDays)

	fmt.Println("Using:")
	fmt.Println("  issuer identity name:", *issuerNameStr)
	fmt.Println("  holder identity name:", *holderNameStr)
	fmt.Println("  schema file:", *schemaFile)
	fmt.Println("  schema type:", *schemaType)
	fmt.Println("  index data:", indexData)
	fmt.Println("  value data:", valueData)
	fmt.Println("  expiry date:", expiryDate)
	//
	// Retrieve the identity for issuing claims
	//
	fmt.Println("Loading issuer identity")
	issuerIdentity := GetIdentityFromIdentityStorage(*issuerNameStr, false)

	fmt.Println("Load holder identity in read only mode to figure out the ID")
	holderIdentityReadOnly := GetIdentityFromIdentityStorage(*holderNameStr, false)

	issuerIdentity.IssueNewGenericClaimViaSignature("", holderIdentityReadOnly, *schemaFile, *schemaType, indexData, valueData, expiryDate)

}

func parseValueArg(argName string, str string) *big.Int {
	val, err := parseValue(str)
	if err != nil {
		fmt.Printf("Error parsing %s arg value '%s': %s\n", argName, str, err)
		os.Exit(1)
	}
	return val
}

func parseValue(str string) (*big.Int, error) {
	if str == "" {
		return nil, nil
	}
	if str[0] == '"' {
		// parse as JSON string and return its Poseidon hash
		var strValue string
		err := json.Unmarshal([]byte(str), &strValue)
		// fmt.Println("value as string:", strValue, "error:", err)
		if err != nil {
			return nil, err
		}
		hash, err := poseidon.HashBytes([]byte(strValue))
		return hash, err
	} else {
		// parse as bigint
		var bigInt big.Int
		err := bigInt.UnmarshalText([]byte(str))
		if err != nil {
			return nil, err
		}
		return &bigInt, err
	}
}

func parseExpiry(expiryStr string, expiryDays int) *time.Time {
	if expiryStr != "" {
		t, err := time.Parse(time.RFC3339, expiryStr)
		if err != nil {
			fmt.Println("Error parsing expiry:", err)
			os.Exit(1)
		}
		return &t
	}

	if expiryDays != 0 {
		maxDays := math.MaxInt64 / (24 * int(time.Hour))
		if expiryDays < -maxDays || expiryDays > maxDays {
			fmt.Printf("Maximum number of days exceeded for --expiryDays. Value must be between -%d and %d.\n", maxDays, maxDays)
			os.Exit(1)
		}

		dur := time.Duration(expiryDays*24) * time.Hour
		t := time.Now().Add(dur).Round(time.Second)
		return &t
	}

	return nil
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
