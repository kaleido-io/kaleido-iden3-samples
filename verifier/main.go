package main

import (
	"fmt"
	"os"

	"github.com/kaleido-io/kaleido-iden3-verifier/cmd"
)

var buildDate, buildVersion string // Set by ldflags

func main() {
	print("Copyright (C) 2023 Kaleido\n")
	print(fmt.Sprintf("Version: %s (Build Date: %s)\n\n", buildVersion, buildDate))
	exitVal := cmd.Execute()
	os.Exit(exitVal)
}
