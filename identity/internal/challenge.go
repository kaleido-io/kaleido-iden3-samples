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
	"errors"
	"flag"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/iden3/go-circuits"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	merkletree "github.com/iden3/go-merkletree-sql"
	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

const NOOP = "0"    // = - no operation, skip query verification if set
const EQUALS = "1"  // = - equals sign
const LESS = "2"    // = - less-than sign
const GREATER = "3" // = - greter-than sign
const IN = "4"      // = - in
const NOTIN = "5"   // = - notin

type Challenge struct {
	Message string `json:"message"`
	Scope   `json:"scope"`
}

type Scope struct {
	CircuitID string  `json:"circuit_id"`
	Queries   []Query `json:"queries"`
}

type Query struct {
	Property string      `json:"property"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

// Called against the holder identity to respond to the proof challenge
// and generates a zero knowledge proof based on the issued claim
func RespondToChallenge() {
	resCmd := flag.NewFlagSet("respond-to-challenge", flag.ExitOnError)
	holderNameStr := resCmd.String("holder", "", "name of the holder identity")
	challengeStr := resCmd.String("challenge", "", "challenge string")
	qrImgStr := resCmd.String("qrcode", "", "Image file for the challenge QR code")
	resCmd.Parse(os.Args[2:])
	if *holderNameStr == "" {
		fmt.Println("Must specify the name of the holder with a --holder parameter")
		os.Exit(1)
	}
	if *challengeStr == "" && *qrImgStr == "" {
		fmt.Println("Must specify a challenge with a --challenge parameter, or a QR image file, with the --qrcode parameter")
		os.Exit(1)
	}

	challengeId := &big.Int{}
	var challenge *Challenge
	if *qrImgStr != "" {
		challengeObj, err := decodeQRImage(*qrImgStr)
		assertNoError(err)
		challenge, err = decodeChallenge(challengeObj)
		assertNoError(err)
		fmt.Printf("Using the challenge %+v decoded from the QR Code\n", challenge)
		challengeId.SetString(challenge.Message, 10)
	} else {
		challengeId.SetString(*challengeStr, 10)
	}

	//
	// Before responding to the challenge, we need to first load the private key of the holder
	//

	ctx := context.Background()
	fmt.Println("Loading holder identity")
	holderIdentity := GetIdentityFromIdentityStorage(*holderNameStr, false)
	privKey := holderIdentity.Private.PrivateKeys[DEFAULT_PRIVATE_KEY_NAME]
	holderId := holderIdentity.Public.ID

	holderAuthTreeState := *holderIdentity.CalculateCurrentState()

	authClaimWithProof := holderIdentity.GetAuthClaimWithProofForKey(ctx, DEFAULT_PRIVATE_KEY_NAME)
	holderAuthMTProof, err := merkletree.NewProofFromBytes(authClaimWithProof.AuthClaimMtpBytes)
	inputsAuthClaim := circuits.Claim{
		//Schema:    authClaim.Schema,
		Claim:     &authClaimWithProof.AuthClaim,
		Proof:     holderAuthMTProof,
		TreeState: holderAuthTreeState,
		NonRevProof: &circuits.ClaimNonRevStatus{
			TreeState: holderAuthTreeState,
			Proof:     holderAuthMTProof,
		},
	}

	targetClaim, err := loadClaim(*holderNameStr)
	assertNoError(err)

	claimNonRevMtp, err := merkletree.NewProofFromBytes(targetClaim.IssuerClaimNonRevMtpBytes)
	assertNoError((err))

	issuerClaimTreeState := circuits.TreeState{
		State:          targetClaim.IssuerState_State,
		ClaimsRoot:     targetClaim.IssuerState_ClaimsTreeRoot,
		RevocationRoot: targetClaim.IssuerState_RevTreeRoot,
		RootOfRoots:    targetClaim.IssuerState_RootsTreeRoot,
	}

	issuerIdBigInt := &big.Int{}
	issuerIdBigInt.SetString(targetClaim.IssuerAuthClaimWithProof.UserID, 10)
	issuerId, err := core.IDFromInt(issuerIdBigInt)
	assertNoError(err)

	issuerAuthTreeState := circuits.TreeState{
		State:          targetClaim.IssuerAuthClaimWithProof.IDState,
		ClaimsRoot:     targetClaim.IssuerAuthClaimWithProof.ClaimsTreeRoot,
		RevocationRoot: &merkletree.HashZero,
		RootOfRoots:    &merkletree.HashZero,
	}

	issuerAuthClaimMTP, err := merkletree.NewProofFromBytes(targetClaim.IssuerAuthClaimWithProof.AuthClaimMtpBytes)
	assertNoError(err)

	issuerAuthClaimNonRevMTP, err := merkletree.NewProofFromBytes(targetClaim.IssuerAuthClaimWithProof.AuthClaimNonRevMtpBytes)
	assertNoError(err)

	x := &big.Int{}
	x.SetString(targetClaim.IssuerClaimSignatureR8X, 10)
	y := &big.Int{}
	y.SetString(targetClaim.IssuerClaimSignatureR8Y, 10)
	s := &big.Int{}
	s.SetString(targetClaim.IssuerClaimSignatureS, 10)
	point := &babyjub.Point{X: x, Y: y}
	claimSignature := &babyjub.Signature{R8: point, S: s}

	claimIssuerSignature := circuits.BJJSignatureProof{
		IssuerID:           &issuerId,
		IssuerTreeState:    issuerAuthTreeState,
		IssuerAuthClaimMTP: issuerAuthClaimMTP,
		Signature:          claimSignature,
		IssuerAuthClaim:    &targetClaim.IssuerAuthClaimWithProof.AuthClaim,
		IssuerAuthNonRevProof: circuits.ClaimNonRevStatus{
			TreeState: issuerAuthTreeState,
			Proof:     issuerAuthClaimNonRevMTP,
		},
	}

	inputsUserClaim := circuits.Claim{
		Claim:     targetClaim.IssuerClaim,
		TreeState: issuerClaimTreeState,
		NonRevProof: &circuits.ClaimNonRevStatus{
			TreeState: issuerClaimTreeState,
			Proof:     claimNonRevMtp,
		},
		IssuerID:       &issuerId,
		SignatureProof: claimIssuerSignature,
	}
	fmt.Println(challenge.Scope.Queries[0].Operator)
	operator, err := strconv.Atoi(challenge.Queries[0].Operator)
	dob := big.NewInt(int64(math.Round(challenge.Queries[0].Value.(float64))))
	values := []*big.Int{}
	values = append(values, dob)
	i := 1
	for i < 64 {
		// must have 64 items
		values = append(values, big.NewInt(0))
		i++
	}
	assertNoError(err)
	inputs := circuits.AtomicQuerySigInputs{
		ID:               holderId,
		AuthClaim:        inputsAuthClaim,
		Challenge:        challengeId,
		Signature:        privKey.SignPoseidon(challengeId),
		CurrentTimeStamp: time.Now().Unix(),
		Claim:            inputsUserClaim,
		Query: circuits.Query{
			SlotIndex: 2, // TODO: figure out the index by looking up the schema
			Operator:  operator,
			Values:    values,
		},
	}

	persistInputsForChallenge(*holderNameStr, inputs)
}

func persistInputsForChallenge(name string, inputs circuits.AtomicQuerySigInputs) error {
	inputsPath := filepath.Join(getWorkDir(name), "challenge.json")
	content, err := inputs.InputsMarshal()
	if err != nil {
		return err
	}
	err = os.WriteFile(inputsPath, content, os.ModePerm)
	if err != nil {
		return err
	}
	fmt.Printf("Challenge response inputs written to the file: %s\n", inputsPath)
	return nil
}

func loadClaim(name string) (*ClaimInputsForSigCircuit, error) {
	claimsPath := filepath.Join(getWorkDir(name), "private/received-claims")
	files, err := os.ReadDir(claimsPath)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no claims found in the received-claims directory")
	}
	file, err := files[0].Info()
	if err != nil {
		return nil, err
	}
	claimPath := filepath.Join(claimsPath, file.Name())
	content, err := os.ReadFile(claimPath)
	if err != nil {
		return nil, err
	}

	var claim ClaimInputsForSigCircuit
	err = json.Unmarshal(content, &claim)
	if err != nil {
		return nil, err
	}
	return &claim, err
}

func decodeQRImage(imageFile string) (map[string]interface{}, error) {
	// open and decode image file
	file, err := os.Open(imageFile)
	if err != nil {
		fmt.Println("Failed to open QR image file.", err)
		return nil, err
	}
	img, _, err := image.Decode(file)
	if err != nil {
		fmt.Println("Failed to decode image file.", err)
		return nil, err
	}

	// prepare BinaryBitmap
	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		fmt.Println("Failed to convert to bitmap.", err)
		return nil, err
	}

	// decode image
	qrReader := qrcode.NewQRCodeReader()
	result, err := qrReader.DecodeWithoutHints(bmp)
	if err != nil {
		fmt.Println("Failed to decode QR image.", err)
		return nil, err
	}

	var obj map[string]interface{}
	err = json.Unmarshal([]byte(result.GetText()), &obj)
	if err != nil {
		fmt.Println("Failed to decode QR content bytes.", err)
		return nil, err
	}

	return obj, nil
}

func decodeChallenge(challengeObj map[string]interface{}) (*Challenge, error) {
	challenge := &Challenge{}

	body := challengeObj["body"]
	if body == nil {
		return nil, errors.New(("invalid challenge object, missing the 'body' object"))
	} else {
		bodyObj, ok := body.(map[string]interface{})
		if !ok {
			return nil, errors.New("invalid challenge object, the 'body' property must be an object")
		}

		cstr := bodyObj["message"]
		if cstr == nil {
			return nil, errors.New("invalid challenge object, missing the 'message' string property in the 'body' object")
		}
		challenge.Message = cstr.(string)

		scope := bodyObj["scope"]
		if scope == nil {
			return nil, errors.New("invalid challenge object, missing the 'scope' object")
		}
		scopeArr := scope.([]interface{})
		scopeObj := scopeArr[0]
		challenge.Scope = Scope{}
		circuitId := scopeObj.(map[string]interface{})["circuit_id"]
		if circuitId == nil {
			return nil, errors.New("invalid challenge object, missing the 'circuit_id' property in the 'scope' object")
		} else {
			if circuitId.(string) != "credentialAtomicQuerySig" {
				return nil, errors.New("invalid challenge object, only supported circuit so far is 'credentialAtomicQuerySig'")
			}
		}
		challenge.Scope.CircuitID = circuitId.(string)
		rules := scopeObj.(map[string]interface{})["rules"]
		if rules == nil {
			return nil, errors.New("invalid challenge object, missing the 'rules' property in the 'scope' object")
		}
		query := rules.(map[string]interface{})["query"]
		if query == nil {
			return nil, errors.New("invalid challenge object, missing the 'query' property in the 'rules' object")
		}
		req := query.(map[string]interface{})["req"]
		if req == nil {
			return nil, errors.New("invalid challenge object, missing the 'req' property in the 'query' object")
		}
		reqMap := req.(map[string]interface{})
		challenge.Scope.Queries = make([]Query, len(reqMap))
		i := 0
		for k, v := range reqMap {
			q := Query{
				Property: k,
			}
			valueMap := v.(map[string]interface{})
			for k1, v1 := range valueMap {
				q.Operator = translateQueryOperator(k1)
				q.Value = v1
			}
			challenge.Scope.Queries[i] = q
			i++
		}
		return challenge, nil
	}
}

func translateQueryOperator(op string) string {
	switch op {
	case "$eq":
		return EQUALS
	case "$lt":
		return LESS
	case "$gt":
		return GREATER
	default:
		return NOOP
	}
}
