package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	ffconfig "github.com/hyperledger/firefly-common/pkg/config"
	"github.com/kaleido-io/kaleido-iden3-verifier/internal/config"
	"github.com/stretchr/testify/assert"
)

func TestServer(t *testing.T) {
	wdir, _ := os.Getwd()
	cfgFile := path.Join(wdir, "../services/resources/test-config.yaml")
	config.InitConfig()
	err := ffconfig.ReadConfig("iden3.verifier", cfgFile)
	assert.NoError(t, err)
	output, _ := json.MarshalIndent(ffconfig.GetConfig(), "", "  ")
	fmt.Printf("Config: %s\n", string(output))
	aServer, err := NewAPIServer(context.Background())
	server := aServer.(*apiServer)
	assert.NoError(t, err)
	timeout, _ := time.ParseDuration("20s")
	assert.Equal(t, timeout, server.apiTimeout)
}
