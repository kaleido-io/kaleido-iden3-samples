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
	merkletree "github.com/iden3/go-merkletree-sql"
	sqlstorage "github.com/iden3/go-merkletree-sql/db/sql"
	_ "github.com/mattn/go-sqlite3"
)

func GenerateIdentity() {
	initCmd := flag.NewFlagSet("init", flag.ExitOnError)
	nameStr := initCmd.String("name", "", "name of the identity")
	initCmd.Parse(os.Args[2:])
	if *nameStr == "" {
		fmt.Println("Must specify the name of the identity with a --name parameter")
		os.Exit(1)
	}

	fmt.Println("Generating new signing key from the \"babyjubjub\" curve")
	privKey := babyjub.NewRandPrivKey()
	pubKey := privKey.Public()
	fmt.Printf("-> Public key: %s\n\n", pubKey)

	// persist the private key for future use
	content := make([]byte, 32)
	src := privKey[:]
	copy(content[:], src)
	keyPath := getPrivateKeyPath(*nameStr)
	_ = os.MkdirAll(filepath.Dir(keyPath), os.ModePerm)
	err := os.WriteFile(keyPath, []byte(content), 0644)
	assertNoError(err)

	ctx := context.Background()
	claimsDB, revsDB, rootsDB, err := initMerkleTreeDBs(*nameStr)
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
	claimsTree, err := merkletree.NewMerkleTree(ctx, claimsStorage, 32)
	assertNoError(err)
	fmt.Println("-> Create the empty revocations merkle tree")
	revocationsTree, err := merkletree.NewMerkleTree(ctx, revsStorage, 32)
	assertNoError(err)
	fmt.Println("-> Create the empty roots merkle tree")
	rootsTree, err := merkletree.NewMerkleTree(ctx, rootsStorage, 32)
	assertNoError(err)

	// A schema is registered using its hash. The hash is used to coordinate the validation by offline processes.
	// There is no schema validation by the protocol.
	fmt.Println("-> Issue the authentication claim for the identity")
	authSchemaHash, _ := getAuthClaimSchemaHash()
	revNonce := uint64(1)
	// An auth claim includes the X and Y curve coordinates of the public key, along with the revocation nonce
	authClaim, err := core.NewClaim(authSchemaHash, core.WithIndexDataInts(pubKey.X, pubKey.Y), core.WithRevocationNonce(revNonce))
	assertNoError(err)
	encodedAuthClaim, err := json.MarshalIndent(authClaim, "", "  ")
	assertNoError(err)
	fmt.Printf("   -> Issued auth claim: encoded=%s\n", encodedAuthClaim)

	fmt.Println("   -> Add the new auth claim to the claims tree")
	hIndex, hValue, _ := authClaim.HiHv()
	err = claimsTree.Add(ctx, hIndex, hValue)
	assertNoError(err)

	// print the genesis state
	genesisState, err := merkletree.HashElems(claimsTree.Root().BigInt(), revocationsTree.Root().BigInt(), rootsTree.Root().BigInt())
	assertNoError(err)
	fmt.Printf("-> Genesis State: %s\n", genesisState.BigInt())

	// print the ID
	id, _ := core.IdGenesisFromIdenState(core.TypeDefault, genesisState.BigInt())
	fmt.Printf("-> ID of the generated identity: %s\n\n", id)

	// construct the genesis state snapshot, to be used as input to the ZKP for the state transition
	fmt.Println("Construct the state snapshot (later as input to the ZK proof generation)")
	fmt.Println("-> Generate a merkle proof of the inclusion of the auth claim in the claims tree")
	authMTProof, _, _ := claimsTree.GenerateProof(ctx, hIndex, claimsTree.Root())
	fmt.Printf("-> Generate a merkle proof of the exclusion of the revocation nonce in the revocation tree\n\n")
	authNonRevMTProof, _, _ := revocationsTree.GenerateProof(ctx, new(big.Int).SetInt64(int64(revNonce)), revocationsTree.Root())
	genesisTreeState := circuits.TreeState{
		State:          genesisState,
		ClaimsRoot:     claimsTree.Root(),
		RevocationRoot: revocationsTree.Root(),
		RootOfRoots:    rootsTree.Root(),
	}

	// persist the genesis state before modifying the roots tree
	err = persistGenesisState(*nameStr, id, claimsTree.Root(), revocationsTree.Root(), rootsTree.Root(), authClaim, authMTProof, authNonRevMTProof)
	assertNoError(err)

	updateIdentifyLookupFile(*nameStr, id.String())

	fmt.Printf("Add the current claim tree root to the roots tree\n")
	err = rootsTree.Add(ctx, claimsTree.Root().BigInt(), big.NewInt(0))
	assertNoError(err)

	err = persistNewState(*nameStr, claimsTree, revocationsTree, rootsTree, genesisTreeState, privKey)
	assertNoError(err)
}
