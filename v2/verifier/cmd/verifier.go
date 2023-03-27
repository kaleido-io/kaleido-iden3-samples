package cmd

import (
	"context"
	"encoding/json"
	"fmt"

	ffconfig "github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/kaleido-io/kaleido-iden3-verifier/internal/apiserver"
	"github.com/kaleido-io/kaleido-iden3-verifier/internal/config"
	"github.com/kaleido-io/kaleido-iden3-verifier/internal/msgs"
	"github.com/spf13/cobra"
)

var rootCmd = cobra.Command{
	Use:   "iden3_verifier",
	Short: "Microservice for the Decentralized Identity verifier server based on iden3",
	RunE: func(cmd *cobra.Command, args []string) error {
		return run(cmd.Context())
	},
}

func Execute() int {
	rootCtx := context.Background()
	err := rootCmd.ExecuteContext(rootCtx)
	if err != nil {
		log.L(rootCtx).Errorf("Exiting: %s", err)
		return 1
	}
	return 0
}

var cfgFile string

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "f", "", "config file")
}

func initConfig() {
	config.InitConfig()
}

func run(ctx context.Context) error {
	log.L(ctx).Infof(string(msgs.StartupMsg))

	initConfig()
	err := ffconfig.ReadConfig("iden3.verifier", cfgFile)
	if err != nil {
		return err
	}
	output, _ := json.MarshalIndent(ffconfig.GetConfig(), "", "  ")
	fmt.Printf("Config: %s\n", string(output))

	// Start Server
	as, err := apiserver.NewAPIServer(ctx)
	if err != nil {
		return err
	}
	if err := as.Serve(ctx); err != nil {
		return err
	}

	return nil
}
