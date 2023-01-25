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
	"flag"
	"fmt"
	"os"

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

	ctx := context.TODO()

	newID := NewIdentity(*nameStr, "")

	updateIdentifyLookupFile(*nameStr, newID.Public.ID.String())

	newID.GenerateStateTransitionInputs(ctx, "")

}
