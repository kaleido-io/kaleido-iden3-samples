// Copyright © 2023 Kaleido, Inc.
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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/iden3/go-circuits"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/keccak256"
	"github.com/iden3/go-iden3-crypto/poseidon"
	merkletree "github.com/iden3/go-merkletree-sql"
	sqlstorage "github.com/iden3/go-merkletree-sql/db/sql"
)

const (
	DEFAULT_PRIVATE_KEY_NAME = "private"
)

type GenesisState struct {
	AuthClaimWithProof
	KeyName        string           `json:"keyName"` // Note: not part of the Iden3 protocol
	UserID         string           `json:"userID"`
	IDState        *merkletree.Hash `json:"newUserState"`
	ClaimsTreeRoot *merkletree.Hash `json:"claimsTreeRoot"`
	RevTreeRoot    *merkletree.Hash `json:"revTreeRoot"`
	RootsTreeRoot  *merkletree.Hash `json:"rootsTreeRoot"`
}

type Identity struct {
	Private *PrivateIdentityData
	Public  *PublicIdentityData
}

type PrivateIdentityData struct {
	// data in this section must be kept secret by the identity
	PrivateKeys map[string]*babyjub.PrivateKey
	ClaimsTree  *merkletree.MerkleTree // root hash of the claim tree is not secret as it doesn't reveal the content of the tree
}

type PublicIdentityData struct {
	Name           string   // NOTE: this name is not part of the Iden3 protocol, it's a human readable name which has a 1:1 mapping with identity ID. The mappings are stored and managed separately by this demo app
	ID             *core.ID // ID generated from the genesis state during identity creation
	RevocationTree *merkletree.MerkleTree
	RootsTree      *merkletree.MerkleTree
}

func (identityData *Identity) CalculateCurrentState() *circuits.TreeState {
	// generate the identityStateHash
	identityStateHash, err := merkletree.HashElems(
		identityData.Private.ClaimsTree.Root().BigInt(), /**the claimsTree itself is private data, but its root is not and will be stored in rootsTree, so it's safe to use it in this calculation*/
		identityData.Public.RevocationTree.Root().BigInt(),
		identityData.Public.RootsTree.Root().BigInt(),
	)
	assertNoError(err)
	fmt.Printf("-> Calculated state hash: %s\n", identityStateHash.BigInt())

	return &circuits.TreeState{
		State:          identityStateHash,
		ClaimsRoot:     identityData.Private.ClaimsTree.Root(),
		RevocationRoot: identityData.Public.RevocationTree.Root(),
		RootOfRoots:    identityData.Public.RootsTree.Root(),
	}
}

func (identityData *Identity) IssueNewAuthClaim(ctx context.Context, keyName string) *ClaimRecord {
	if keyName == "" {
		keyName = DEFAULT_PRIVATE_KEY_NAME
	}
	privKey, ok := identityData.Private.PrivateKeys[keyName]
	if !ok {
		assertNoError(fmt.Errorf("Cannot find a private key with name %s for Identity %s (ID: %s).", keyName, identityData.Public.Name, identityData.Public.ID.String()))
	}
	pubKey := privKey.Public()
	// A schema is registered using its hash. The hash is used to coordinate the validation by offline processes.
	fmt.Println("-> Issue an authentication claim for the identity")
	authSchemaHash, _ := getAuthClaimSchemaHash()

	revNonce := rand.Uint64()
	// An auth claim includes the X and Y curve coordinates of the public key, along with the revocation nonce
	authClaim, err := core.NewClaim(authSchemaHash, core.WithIndexDataInts(pubKey.X, pubKey.Y), core.WithRevocationNonce(revNonce))
	assertNoError(err)
	encodedAuthClaim, err := json.MarshalIndent(authClaim, "", "  ")
	assertNoError(err)
	fmt.Printf("   -> Issued auth claim: encoded=%s\n", encodedAuthClaim)

	fmt.Println("   -> Add the new auth claim to the claims tree")
	hIndex, hValue, _ := authClaim.HiHv()
	err = identityData.Private.ClaimsTree.Add(ctx, hIndex, hValue)
	assertNoError(err)

	authClaimRecord := &ClaimRecord{
		Name:                fmt.Sprintf("authClaim-%s-%s", hex.EncodeToString(authSchemaHash[:]), keyName),
		Claim:               authClaim,
		IncludedInClaimTree: true,
	}
	authClaimRecord.persist(getWorkDir(identityData.Public.Name))
	return authClaimRecord
}

func (identityData *Identity) RevokeClaim() {

}

func getSchemaHash(schemaFile string, schemaType string) core.SchemaHash {
	// load the schema for the claim (contents must be identical to schema resource indicated in challenge response)
	schemaBytes, err := os.ReadFile(schemaFile)
	assertNoError(err)

	var schemaHash core.SchemaHash
	h := keccak256.Hash(schemaBytes, []byte(schemaType))
	copy(schemaHash[:], h[len(h)-16:])

	schemaHashHex, _ := schemaHash.MarshalText()
	fmt.Printf("-> Schema hash for schema file '%s' and type '%s': %s\n", schemaFile, schemaType, string(schemaHashHex))

	return schemaHash
}

func createBasicClaim(holderId core.ID, schemaFile, schemaType string, indexData [2]*big.Int, valueData [2]*big.Int, expiryDate *time.Time) *core.Claim {
	schemaHash := getSchemaHash(schemaFile, schemaType)

	claim, err := core.NewClaim(
		schemaHash,
		core.WithIndexID(holderId),
		core.WithIndexDataInts(indexData[0], indexData[1]),
		core.WithValueDataInts(valueData[0], valueData[1]),
		core.WithRevocationNonce(rand.Uint64()),
	)
	assertNoError(err)
	if expiryDate != nil {
		claim.SetExpirationDate(*expiryDate)
	}

	return claim
}

func (identityData *Identity) GetAuthClaimWithProofForKey(ctx context.Context, keyName string) *AuthClaimWithProof {
	if keyName == "" {
		keyName = DEFAULT_PRIVATE_KEY_NAME
	}
	if _, ok := identityData.Private.PrivateKeys[keyName]; !ok {
		assertNoError(fmt.Errorf("Failed to generate AuthClaimWithProof for key %s, it doesn't exist", keyName))
	}
	authClaim := GetAuthClaimRecordFromIdentityStorageByKeyName(getWorkDir(identityData.Public.Name), keyName)

	hIndex, _ := authClaim.Claim.HIndex()

	authMTProof, _, err := identityData.Private.ClaimsTree.GenerateProof(ctx, hIndex, identityData.Private.ClaimsTree.Root())
	if err != nil {
		assertNoError(fmt.Errorf("Failed to generate Merkle tree proof of membership in the claims tree for auth claim: %s due to %s", authClaim.Name, err.Error()))
	}
	authNonRevMTProof, _, _ := identityData.Public.RevocationTree.GenerateProof(ctx, new(big.Int).SetInt64(int64(authClaim.Claim.GetRevocationNonce())), identityData.Public.RevocationTree.Root())
	if err != nil {
		assertNoError(fmt.Errorf("Failed to generate Merkle tree proof of non-membership in the revocation tree for auth claim: %s due to %s", authClaim.Name, err.Error()))
	}

	key, value, noAux := getNodeAuxValue(authNonRevMTProof.NodeAux)
	a := circuits.AtomicQuerySigInputs{}

	currentState := identityData.CalculateCurrentState()
	return &AuthClaimWithProof{
		AuthClaim:               *authClaim.Claim,
		AuthClaimMtp:            circuits.PrepareSiblingsStr(authMTProof.AllSiblings(), a.GetMTLevel()),
		AuthClaimNonRevMtp:      circuits.PrepareSiblingsStr(authNonRevMTProof.AllSiblings(), a.GetMTLevel()),
		AuthClaimNonRevMtpAuxHi: key,
		AuthClaimNonRevMtpAuxHv: value,
		AuthClaimNonRevMtpNoAux: noAux,

		UserID: identityData.Public.ID.BigInt().String(),

		ClaimsTreeRoot: currentState.ClaimsRoot,
		RevTreeRoot:    currentState.RevocationRoot,
		RootsTreeRoot:  currentState.RootOfRoots,

		IDState:                 currentState.State,
		AuthClaimMtpBytes:       authMTProof.Bytes(),
		AuthClaimNonRevMtpBytes: authNonRevMTProof.Bytes(),
	}
}

func (identityData *Identity) IssueNewGenericClaimViaSignature(keyName string, holderIdentity *Identity, schemaFile, schemaType string, indexData [2]*big.Int, valueData [2]*big.Int, expiryDate *time.Time) *ClaimRecord {
	ctx := context.TODO()
	if keyName == "" {
		keyName = DEFAULT_PRIVATE_KEY_NAME
	}
	fmt.Println("Creating the new claim")
	newClaim := createBasicClaim(*holderIdentity.Public.ID, schemaFile, schemaType, indexData, valueData, expiryDate)

	claimHashIndex, claimHashValue, _ := newClaim.HiHv()
	commonHash, _ := merkletree.HashElems(claimHashIndex, claimHashValue)
	claimSignature := identityData.Private.PrivateKeys[keyName].SignPoseidon(commonHash.BigInt())
	currentState := identityData.CalculateCurrentState()

	fmt.Println("Generating the non-membership proof of revocation tree")
	proofNotRevoke, _, _ := identityData.Public.RevocationTree.GenerateProof(ctx, big.NewInt(int64(newClaim.GetRevocationNonce())), identityData.Public.RevocationTree.Root())

	key, value, noAux := getNodeAuxValue(proofNotRevoke.NodeAux)
	a := circuits.AtomicQuerySigInputs{}
	schemaHash := newClaim.GetSchemaHash()
	claimRecord := &ClaimRecord{
		Name:                     fmt.Sprintf("genericClaim-%s-%s-%s-%s", hex.EncodeToString(schemaHash[:]), identityData.Public.Name, keyName, holderIdentity.Public.Name),
		Claim:                    newClaim,
		IssuerAuthClaimWithProof: identityData.GetAuthClaimWithProofForKey(ctx, keyName),
		IssuerClaimSignatureR8X:  claimSignature.R8.X.String(),
		IssuerClaimSignatureR8Y:  claimSignature.R8.Y.String(),
		IssuerClaimSignatureS:    claimSignature.S.String(),
		IncludedInClaimTree:      false,
	}
	claimRecord.persist(getWorkDir(identityData.Public.Name))

	fmt.Printf("Generating the auth Proof of key: %s and storing claim inputs for Signature Circuit\n", keyName)

	// as it's via signature, we have no new states to commit on chain
	// therefore, the holder can obtain the claim and use it straight away
	claimInputs := &ClaimInputsForSigCircuit{

		// inputs required to prove the auth claim (contains public key of a babyJubJub key pairs)
		// that is linked to the selected private key is still valid
		//   - it's in the claims tree of the issuer identity
		//   - it's not in the revocation tree of the issuer identity
		IssuerAuthClaimWithProof: identityData.GetAuthClaimWithProofForKey(ctx, keyName),

		// information of the issued claim
		IssuerClaim: newClaim,
		ClaimSchema: newClaim.GetSchemaHash().BigInt().String(),

		// inputs required to prove the issued claim is not rovoked
		IssuerState_State:          currentState.State,
		IssuerState_ClaimsTreeRoot: currentState.ClaimsRoot,
		IssuerState_RevTreeRoot:    currentState.RevocationRoot,
		IssuerState_RootsTreeRoot:  currentState.RootOfRoots,
		IssuerClaimNonRevMtp:       circuits.PrepareSiblingsStr(proofNotRevoke.AllSiblings(), a.GetMTLevel()),
		IssuerClaimNonRevMtpAuxHi:  key,
		IssuerClaimNonRevMtpAuxHv:  value,
		IssuerClaimNonRevMtpNoAux:  noAux,

		// signature to prove the claim is issued using the selected private key of the issuer identity
		IssuerClaimSignatureR8X: claimSignature.R8.X.String(),
		IssuerClaimSignatureR8Y: claimSignature.R8.Y.String(),
		IssuerClaimSignatureS:   claimSignature.S.String(),

		IssuerClaimNonRevMtpBytes: proofNotRevoke.Bytes(),
	}

	// NOTE: taking a short cut here, issuer is pushing the new claim into the Private folder of the holder
	// in a real world scenario, the holder should obtain the claim and store it in its Private folder instead
	inputBytes, _ := json.MarshalIndent(claimInputs, "", "  ")
	outputFile := filepath.Join(getWorkDir(holderIdentity.Public.Name), fmt.Sprintf("private/received-claims/%s-via-signature.json", claimRecord.Name))
	_ = os.MkdirAll(filepath.Dir(outputFile), os.ModePerm)
	err := os.WriteFile(outputFile, inputBytes, 0644)
	if err != nil {
		assertNoError(fmt.Errorf("Failed to store issued claim under %s", outputFile))
	}
	fmt.Printf("Claim issued by \"%s\" using key \"%s\" is received by holder \"%s\" under path: %s\n", identityData.Public.Name, keyName, holderIdentity.Public.Name, outputFile)
	return claimRecord
}

func (identityData *Identity) IssueNewGenericClaimViaMerkleTree() {
	// TODO
}

func (identityData *Identity) GenerateStateTransitionInputs(ctx context.Context, keyName string) {
	previousTreeState := identityData.getPreviousState()
	isGenesis := identityData.Public.RootsTree.Root().BigInt().String() == "0"
	if keyName == "" {
		keyName = DEFAULT_PRIVATE_KEY_NAME
	}
	claimTreeRootIndex := identityData.Private.ClaimsTree.Root().BigInt()
	_, _, _, err := identityData.Public.RootsTree.Get(ctx, claimTreeRootIndex)
	if err == merkletree.ErrKeyNotFound {
		// roots tree not up to date, add the latest claim tree root
		identityData.Public.RootsTree.Add(ctx, claimTreeRootIndex, big.NewInt(0))
	}
	// construct the new identity state
	fmt.Println("Calculate the new state")
	newState := identityData.CalculateCurrentState()

	// hash the [old state + new state] to be signed later
	hashOldAndNewState, _ := poseidon.Hash([]*big.Int{previousTreeState.State.BigInt(), newState.State.BigInt()})
	// sign using the identity key
	signature := identityData.Private.PrivateKeys[keyName].SignPoseidon(hashOldAndNewState)

	authClaim := GetAuthClaimRecordFromIdentityStorageByKeyName(getWorkDir(identityData.Public.Name), keyName)

	// construct the inputs to feed to the proof generation for the state transition
	isOldStateGenesis := "0"
	if isGenesis {
		isOldStateGenesis = "1"
	}

	hIndex, _ := authClaim.Claim.HIndex()

	authMTProof, _, err := identityData.Private.ClaimsTree.GenerateProof(ctx, hIndex, identityData.Private.ClaimsTree.Root())
	if err != nil {
		assertNoError(fmt.Errorf("Failed to generate Merkle tree proof of membership in the claims tree for auth claim: %s due to %s", authClaim.Name, err.Error()))
	}
	authNonRevMTProof, _, _ := identityData.Public.RevocationTree.GenerateProof(ctx, new(big.Int).SetInt64(int64(authClaim.Claim.GetRevocationNonce())), identityData.Public.RevocationTree.Root())
	if err != nil {
		assertNoError(fmt.Errorf("Failed to generate Merkle tree proof of non-membership in the revocation tree for auth claim: %s due to %s", authClaim.Name, err.Error()))
	}

	key, value, noAux := getNodeAuxValue(authNonRevMTProof.NodeAux)
	a := circuits.AtomicQuerySigInputs{}
	stateTransitionInputs := stateTransitionInputs{
		AuthClaim:               *authClaim.Claim,
		AuthClaimMtp:            circuits.PrepareSiblingsStr(authMTProof.AllSiblings(), a.GetMTLevel()),
		AuthClaimNonRevMtp:      circuits.PrepareSiblingsStr(authNonRevMTProof.AllSiblings(), a.GetMTLevel()),
		AuthClaimNonRevMtpAuxHi: key,
		AuthClaimNonRevMtpAuxHv: value,
		AuthClaimNonRevMtpNoAux: noAux,
		NewIdState:              newState.State,
		OldIdState:              previousTreeState.State,
		IsOldStateGenesis:       isOldStateGenesis,
		ClaimsTreeRoot:          previousTreeState.ClaimsRoot,
		RevTreeRoot:             previousTreeState.RevocationRoot,
		RootsTreeRoot:           previousTreeState.RootOfRoots,
		SignatureR8X:            signature.R8.X.String(),
		SignatureR8Y:            signature.R8.Y.String(),
		SignatureS:              signature.S.String(),
	}

	inputBytes, err := json.MarshalIndent(stateTransitionInputs, "", "  ")
	if err != nil {
		assertNoError(err)
	}
	outputFile := filepath.Join(getWorkDir(identityData.Public.Name), fmt.Sprintf("private/states/stateTransition_inputs.json"))
	err = os.WriteFile(outputFile, inputBytes, 0644)
	if err != nil {
		assertNoError(err)
	}
	fmt.Printf("-> State transition input bytes written to the file: %s\n", outputFile)

	treeStates := TreeStates{
		Old: &TreeState{
			IdentityState:  previousTreeState.State,
			ClaimsTreeRoot: previousTreeState.ClaimsRoot,
			RevTreeRoot:    previousTreeState.RevocationRoot,
			RootsTreeRoot:  previousTreeState.RootOfRoots,
		},
		New: &TreeState{
			IdentityState:  newState.State,
			ClaimsTreeRoot: newState.ClaimsRoot,
			RevTreeRoot:    newState.RevocationRoot,
			RootsTreeRoot:  newState.RootOfRoots,
		},
	}
	inputBytes2, err := json.MarshalIndent(treeStates, "", "  ")
	if err != nil {
		assertNoError(err)
	}
	outputFile2 := filepath.Join(getWorkDir(identityData.Public.Name), fmt.Sprintf("private/states/treeStates.json"))
	err = os.WriteFile(outputFile2, inputBytes2, 0644)
	if err != nil {
		assertNoError(err)
	}
	fmt.Printf("-> Tree states written into file: %s\n", outputFile2)
}

func NewIdentity(identityName, keyName string) *Identity {
	if keyName == "" {
		keyName = DEFAULT_PRIVATE_KEY_NAME
	}
	ctx := context.TODO()
	privateKeys := map[string]*babyjub.PrivateKey{}
	// generate a babyJubJub key
	privK := initializeBJJKey(identityName, keyName)
	privateKeys[keyName] = privK
	// initialize empty merkle trees
	clT, reT, roT := initializeMerkleTrees(ctx, identityName)
	newID := &Identity{
		Private: &PrivateIdentityData{
			PrivateKeys: privateKeys,
			ClaimsTree:  clT,
		},
		Public: &PublicIdentityData{
			RevocationTree: reT,
			RootsTree:      roT,
			Name:           identityName, // NOTE: this name is not part of the Iden3 protocol, it's a human readable name which has a 1:1 mapping with identity ID. The mappings are stored and managed separately by this demo app
		},
	}
	// create an auth claim for the generated babyJubJub key
	cr := newID.IssueNewAuthClaim(ctx, keyName)

	// calculate the ID using genesis state (only 1 auth claim in claims tree, empty revocation and roots tree)
	genesisState := newID.CalculateCurrentState()
	id, err := core.IdGenesisFromIdenState(core.TypeDefault, genesisState.State.BigInt())
	if err != nil {
		assertNoError(fmt.Errorf("Failed to calculate ID from identity state: %s", err.Error()))
	}

	fmt.Printf("-> ID of the generated identity: %s\n\n", id)
	newID.Public.ID = id

	// save the genesis state (only 1 auth claim in claims tree, empty revocation and roots tree)
	newID.persistGenesisState(ctx, cr)

	return newID
}

func GetIdentityFromIdentityStorage(identityName string, readOnly bool) *Identity {
	ctx := context.TODO()

	// discover all merkle trees
	claimsDB, revsDB, rootsDB, err := initMerkleTreeDBs(getWorkDir(identityName))
	if err != nil {
		assertNoError(err)
	}
	claimsStorage := sqlstorage.NewSqlStorage(&sqlDB{db: claimsDB}, 1)
	revsStorage := sqlstorage.NewSqlStorage(&sqlDB{db: revsDB}, 1)
	rootsStorage := sqlstorage.NewSqlStorage(&sqlDB{db: rootsDB}, 1)

	fmt.Println("Load the claims merkle tree")
	claimsTree, err := merkletree.NewMerkleTree(ctx, claimsStorage, 32)
	if err != nil {
		assertNoError(err)
	}
	fmt.Println("Load the revocations merkle tree")
	revocationTree, err := merkletree.NewMerkleTree(ctx, revsStorage, 32)
	if err != nil {
		assertNoError(err)
	}
	fmt.Println("Load the roots merkle tree")
	rootsTree, err := merkletree.NewMerkleTree(ctx, rootsStorage, 32)
	if err != nil {
		assertNoError(err)
	}

	// discover all babyJubJub keys
	keyFiles, err := os.ReadDir(filepath.Join(getWorkDir(identityName), "private/keys"))
	if err != nil {
		assertNoError(err)
	}

	privateKeys := map[string]*babyjub.PrivateKey{}

	for _, f := range keyFiles {
		if filepath.Ext(f.Name()) != ".key" {
			assertNoError(fmt.Errorf("Files in keys directory must have .key extension, found: %s", f.Name()))
		}
		keyName := strings.TrimSuffix(f.Name(), filepath.Ext(f.Name()))
		privKey, err := loadPrivateKey(identityName, keyName)
		if err != nil {
			assertNoError(fmt.Errorf("Failed to load private key %s for identity %s due to: %s", keyName, identityName, err.Error()))
		}
		privateKeys[keyName] = privKey
	}
	if len(privateKeys) < 1 {
		assertNoError(fmt.Errorf("Failed to initialize identity with name %s due to no keys were found.", identityName))
	}
	gs, err := loadGenesisState(identityName)
	if err != nil {
		assertNoError(fmt.Errorf("Failed to load genesis state due to: %s", err.Error()))
	}
	IDStringBigInt := gs.UserID
	IDBigInt := &big.Int{}
	IDBigInt.SetString(IDStringBigInt, 10)
	ID, err := core.IDFromInt(IDBigInt)
	if err != nil {
		assertNoError(fmt.Errorf("Failed to build ID from Big Int string: %s", gs.UserID))
	}
	if readOnly {
		return &Identity{
			// Private information are not returned for readOnly mode
			Public: &PublicIdentityData{
				Name:           identityName,
				ID:             &ID,
				RevocationTree: revocationTree,
				RootsTree:      rootsTree,
			},
		}
	} else {

		return &Identity{
			Private: &PrivateIdentityData{
				ClaimsTree:  claimsTree,
				PrivateKeys: privateKeys,
			},
			Public: &PublicIdentityData{
				Name:           identityName,
				ID:             &ID,
				RevocationTree: revocationTree,
				RootsTree:      rootsTree,
			},
		}
	}
}

func getPrivateKeyPath(identityName, keyName string) string {
	if keyName == "" {
		keyName = DEFAULT_PRIVATE_KEY_NAME
	}
	return filepath.Join(getWorkDir(identityName), fmt.Sprintf("private/keys/%s.key", keyName))
}

func loadPrivateKey(identityName, keyName string) (*babyjub.PrivateKey, error) {
	if keyName == "" {
		keyName = DEFAULT_PRIVATE_KEY_NAME
	}
	keyBytes, err := os.ReadFile(getPrivateKeyPath(identityName, keyName))
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %s", err)
	}
	var key32Bytes [32]byte
	copy(key32Bytes[:], keyBytes)
	privKey := babyjub.PrivateKey(key32Bytes)
	return &privKey, nil
}

func initializeBJJKey(identityName, keyName string) *babyjub.PrivateKey {
	if keyName == "" {
		keyName = DEFAULT_PRIVATE_KEY_NAME
	}
	fmt.Println("Generating new signing key from the \"babyjubjub\" curve")
	privKey := babyjub.NewRandPrivKey()

	// persist the private key for future use
	content := make([]byte, 32)
	src := privKey[:]
	copy(content[:], src)
	keyPath := getPrivateKeyPath(identityName, keyName)
	if _, err := os.Stat(filepath.Dir(keyPath)); !os.IsNotExist(err) {
		assertNoError(fmt.Errorf("Home folder for identify: %s already exists under path %s.", identityName, filepath.Dir(keyPath)))
	}
	err := os.MkdirAll(filepath.Dir(keyPath), os.ModePerm)
	if err != nil {
		assertNoError(fmt.Errorf("Failed to create home folder for identity name: %s due to: %s.", identityName, err.Error()))
	}
	err = os.WriteFile(keyPath, []byte(content), 0644)

	if err != nil {
		assertNoError(fmt.Errorf("Failed to store private key for identity name: %s due to: %s.", identityName, err.Error()))
	}
	return &privKey
}

func initializeMerkleTrees(ctx context.Context, identityName string) (ClT *merkletree.MerkleTree, ReT *merkletree.MerkleTree, RoT *merkletree.MerkleTree) {
	// Check and initialize merkle tree dbs if identity doesn't already exist
	claimsDB, revsDB, rootsDB, err := initMerkleTreeDBs(getWorkDir(identityName))
	assertNoError(err)
	claimsStorage := sqlstorage.NewSqlStorage(&sqlDB{db: claimsDB}, 1)
	revsStorage := sqlstorage.NewSqlStorage(&sqlDB{db: revsDB}, 1)
	rootsStorage := sqlstorage.NewSqlStorage(&sqlDB{db: rootsDB}, 1)

	// An iden3 state is made up of 3 parts:
	// - a claims tree. This is a sparse merkle tree where each claim is uniquely identified with a key
	// - a revocation tree. This captures whether a claim, identified by its revocation nonce, has been revoked
	// - a roots tree. This captures the historical progression of the merkle tree root of the claims tree
	//
	// To create a genesis state:
	// - issue an auth claim based on the public key and revocation nounce, this will determine the identity's ID
	// - add the auth claim to the claim tree
	// - add the claim tree root at this point in time to the roots tree
	fmt.Println("Generating genesis state for the identity")
	fmt.Println("-> Create the empty claims merkle tree")
	ClT, err = merkletree.NewMerkleTree(ctx, claimsStorage, 32)
	assertNoError(err)
	fmt.Println("-> Create the empty revocations merkle tree")
	ReT, err = merkletree.NewMerkleTree(ctx, revsStorage, 32)
	assertNoError(err)
	fmt.Println("-> Create the empty roots merkle tree")
	RoT, err = merkletree.NewMerkleTree(ctx, rootsStorage, 32)
	assertNoError(err)
	return
}

func (identityData *Identity) persistGenesisState(ctx context.Context, cr *ClaimRecord) {
	if identityData.Public.RootsTree.Root().BigInt().String() != "0" {
		assertNoError(fmt.Errorf("persistGenesisState failed for %s: should only be called when there is no claims tree root recorded in the roots tree.", identityData.Public.Name))
	}
	if !cr.IncludedInClaimTree {
		assertNoError(fmt.Errorf("AuthClaim %s must be included in the Claims Tree of identity %s", cr.Name, identityData.Public.Name))
	}
	hIndex, hValue, _ := cr.Claim.HiHv()

	_, storedValue, _, err := identityData.Private.ClaimsTree.Get(ctx, hIndex)
	if err != nil {
		assertNoError(err)
	}
	if hValue.String() != storedValue.String() {
		assertNoError(fmt.Errorf("AuthClaim %s doesn't exist in the Claims Tree of identity %s", cr.Name, identityData.Public.Name))
	}

	if len(identityData.Private.PrivateKeys) != 1 {
		assertNoError(fmt.Errorf("Identity has %d private keys for its genesis state: only 1 private key is allowed for genesis state.", len(identityData.Private.PrivateKeys)))
	}

	genesisKeyName := ""
	for kName := range identityData.Private.PrivateKeys {
		genesisKeyName = kName
	}

	state, _ := merkletree.HashElems(
		identityData.Private.ClaimsTree.Root().BigInt(),
		identityData.Public.RevocationTree.Root().BigInt(),
		identityData.Public.RootsTree.Root().BigInt(),
	)
	genState := GenesisState{
		AuthClaimWithProof: *identityData.GetAuthClaimWithProofForKey(ctx, genesisKeyName),
		KeyName:            genesisKeyName,
		UserID:             identityData.Public.ID.BigInt().String(),
		IDState:            state,
		ClaimsTreeRoot:     identityData.Private.ClaimsTree.Root(),
		RevTreeRoot:        identityData.Public.RevocationTree.Root(),
		RootsTreeRoot:      identityData.Public.RootsTree.Root(),
	}
	inputBytes, _ := json.MarshalIndent(genState, "", "  ")
	outputFile := filepath.Join(getWorkDir(identityData.Public.Name), fmt.Sprintf("private/states/genesis_state.json"))
	if err := os.MkdirAll(filepath.Dir(outputFile), os.ModePerm); err != nil {
		assertNoError(err)
	}
	if err := os.WriteFile(outputFile, inputBytes, 0644); err != nil {
		assertNoError(err)
	}
	fmt.Printf("-> Input bytes for the identity's genesis state written to the file: %s\n", outputFile)
}

func (identityData *Identity) getPreviousState() *circuits.TreeState {
	// before adding any claims work out the old state
	var oldTreeState circuits.TreeState
	// is there is already a pending state change, copy the old state from there
	// so that we can batch claim additions together
	pendingIssuerState, err := identityData.loadPendingState()
	if err != nil {
		if os.IsNotExist(err) {
			// there is no pending state, it's fine to calculate the old state from the merkle tree roots
			issuerState, _ := merkletree.HashElems(identityData.Private.ClaimsTree.Root().BigInt(), identityData.Public.RevocationTree.Root().BigInt(), identityData.Public.RootsTree.Root().BigInt())
			oldTreeState = circuits.TreeState{
				State:          issuerState,
				ClaimsRoot:     identityData.Private.ClaimsTree.Root(),
				RevocationRoot: identityData.Public.RevocationTree.Root(),
				RootOfRoots:    identityData.Public.RootsTree.Root(),
			}
		} else {
			assertNoError(err)
		}
	} else {
		oldTreeState = circuits.TreeState{
			State:          pendingIssuerState.OldIdState,
			ClaimsRoot:     pendingIssuerState.ClaimsTreeRoot,
			RevocationRoot: pendingIssuerState.RevTreeRoot,
			RootOfRoots:    pendingIssuerState.RootsTreeRoot,
		}
	}
	return &oldTreeState
}

func loadGenesisState(identityName string) (*GenesisState, error) {
	inputFile := filepath.Join(getWorkDir(identityName), fmt.Sprintf("private/states/genesis_state.json"))
	content, err := os.ReadFile(inputFile)
	if err != nil {
		return nil, err
	}
	var genesisState GenesisState
	err = json.Unmarshal(content, &genesisState)
	if err != nil {
		return nil, err
	}
	return &genesisState, nil
}

func (identityData *Identity) loadPendingState() (*stateTransitionInputs, error) {

	inputFile := filepath.Join(getWorkDir(identityData.Public.Name), fmt.Sprintf("private/states/stateTransition_inputs.json"))
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
