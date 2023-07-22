package config

import (
	ffconfig "github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly-common/pkg/httpserver"
)

var APIConfig = ffconfig.RootSection("api")
var CORSConfig = ffconfig.RootSection("cors")
var Iden3Config = ffconfig.RootSection("iden3")
var DatabaseConfig = ffconfig.RootSection("database")
var APIRequestTimeout = "requestTimeout"
var APIRequestTimeoutMax = "requestMaxTimeout"
var Iden3CircuitKeysDir = "verificationKeysDir"
var Iden3EthUrl = "ethUrl"
var Iden3EthContractAddress = "ethContractAddress"
var Iden3ServerHostname = "publicHost"
var Iden3Self = "self"
var DatabasePath = "databasePath"

func InitConfig() {
	httpserver.InitHTTPConfig(APIConfig, 8000)
	httpserver.InitCORSConfig(CORSConfig)

	APIConfig.AddKnownKey(APIRequestTimeout, "120s")
	APIConfig.AddKnownKey(APIRequestTimeoutMax, "10m")

	Iden3Config.AddKnownKey(Iden3CircuitKeysDir, "")
	Iden3Config.AddKnownKey(Iden3EthUrl, "")
	Iden3Config.AddKnownKey(Iden3EthContractAddress, "")
	Iden3Config.AddKnownKey(Iden3ServerHostname, "http://localhost:8000")
	Iden3Config.AddKnownKey(Iden3Self, "")

	DatabaseConfig.AddKnownKey(DatabasePath, "")
}
