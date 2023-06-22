package services

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"testing"

	ffconfig "github.com/hyperledger/firefly-common/pkg/config"
	"github.com/iden3/iden3comm/protocol"
	"github.com/kaleido-io/kaleido-iden3-verifier/internal/config"
	"github.com/stretchr/testify/assert"
)

const ProofRequest = `{
  "id": "675195b5-345b-4e98-a944-856327c24af5",
  "thid": "7f38a193-0918-4a48-9fac-36adfdb8b542",
  "typ": "application/iden3comm-plain-json",
  "type": "https://iden3-communication.io/authorization/1.0/response",
  "from": "11CTrdFu6JSHuCkQREazTK97qnxJyRxxeoohpmgi4s",
  "to": "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ",
  "body": {
    "message": "316390273",
    "scope": [
      {
        "id": 316390273,
        "circuitId": "credentialAtomicQuerySigV2",
        "proof": {
          "pi_a": [
            "1367349194085033796347949745269671531925694878878703944754290105947522943152",
            "6613083637320618877253228853825716978645570779321620777868187059042168424395",
            "1"
          ],
          "pi_b": [
            [
              "11640104334558847384140403959950999268465504130431969201036041041934754973721",
              "3738733907351526874839106886022901330224378758929233733545407586615205349439"
            ],
            [
              "17651081767355674983361576572795638441299403869559407710505281972478286268529",
              "13121747023909758854334480847592247137950608500065614649906741052433293684022"
            ],
            [
              "1",
              "0"
            ]
          ],
          "pi_c": [
            "2759097258150265142722491065262535370776060173830464906521787403688370782500",
            "14040123792095584940630968457061957096827464719951638043127436885479733506781",
            "1"
          ],
          "protocol": "groth16",
          "curve": "bn128"
        },
        "pub_signals": [
          "6854687553561755076575365405419700972893015792611056026671376866204285551185",
          "388810994377423128487512780010859891736102037821588190178637432347745320960",
          "18688660605480843883772538245460479234300434093354513235793097725209660470215",
          "316390273",
          "167961360854030376296506555801506768898821179215366838866119658154479583232",
          "6854687553561755076575365405419700972893015792611056026671376866204285551185",
          "1677095464",
          "291655261179041654345552265454745556840",
          "2",
          "2",
          "20000101",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0",
          "0"
        ]
      }
    ]
  }
}
`

func TestConstructor(t *testing.T) {
	wdir, _ := os.Getwd()
	cfgFile := path.Join(wdir, "./resources/test-config.yaml")
	config.InitConfig()
	err := ffconfig.ReadConfig("iden3.verifier", cfgFile)
	assert.NoError(t, err)
	output, _ := json.MarshalIndent(ffconfig.GetConfig(), "", "  ")
	ffconfig.Set("iden3.verificationKeysDir", path.Join(wdir, "../../pkg/circuits"))
	fmt.Printf("Config: %s\n", string(output))
	newInst, err := NewManager(context.Background())
	assert.NoError(t, err)
	vm := newInst.(*verifierManager)
	assert.NotEmpty(t, vm.verifier)
}

func TestCreateChallenge(t *testing.T) {
	vm, _ := NewManager(context.Background())
	query := &Query{
		CredentialSubject: &map[string]Predicate{
			"birthdate": map[string]interface{}{
				"$lt": 20010101,
			},
		},
		Type: "AgeCredential",
	}
	msg, err := vm.CreateChallenge(context.Background(), query)
	assert.NoError(t, err)
	assert.Equal(t, "did:iden3:tTjhYsRM2B6fbbsuQhubfPkQiUrGwYY6QEznBQxn6", msg.From)
	assert.Equal(t, 1, len(msg.Body.Scope))
	scope := msg.Body.Scope[0]
	assert.Equal(t, "credentialAtomicQuerySigV2", scope.CircuitID)
	issuers := scope.Query["allowedIssuers"].([]string)
	assert.Equal(t, 1, len(issuers))
	assert.Equal(t, "*", issuers[0])
	assert.Equal(t, "AgeCredential", scope.Query["type"])
}

func TestGetChallenge(t *testing.T) {
	vm, _ := NewManager(context.Background())
	query := &Query{
		CredentialSubject: &map[string]Predicate{
			"birthdate": map[string]interface{}{
				"$lt": 20010101,
			},
		},
		Type: "AgeCredential",
	}
	msg, _ := vm.CreateChallenge(context.Background(), query)
	status, _ := vm.GetChallenge(context.Background(), msg.ThreadID)
	assert.NotEmpty(t, status)
	assert.Equal(t, false, status.Verified)
	assert.Equal(t, msg.ThreadID, status.ID)
}

func TestVerifyNonExistentRequest(t *testing.T) {
	vm, _ := NewManager(context.Background())
	authResponse := &protocol.AuthorizationResponseMessage{}
	err := json.Unmarshal([]byte(ProofRequest), authResponse)
	assert.NoError(t, err)
	result, err := vm.VerifyProof(context.Background(), authResponse)
	assert.EqualError(t, err, "the Authorization Request 7f38a193-0918-4a48-9fac-36adfdb8b542 does not exist")
	assert.Equal(t, false, result)
}

func TestVerifySuccess(t *testing.T) {
	vmgr, _ := NewManager(context.Background())
	vm := vmgr.(*verifierManager)
	authResponse := &protocol.AuthorizationResponseMessage{}
	err := json.Unmarshal([]byte(ProofRequest), authResponse)
	assert.NoError(t, err)
	query := &Query{
		CredentialSubject: &map[string]Predicate{
			"birthdate": map[string]interface{}{
				"$lt": 20010101,
			},
		},
		Type: "AgeCredential",
	}
	msg, _ := vm.CreateChallenge(context.Background(), query)
	// hack the request object to match the pre-generated proof object
	msg.Body.Message = authResponse.Body.Message
	msg.Body.Scope[0].ID = authResponse.Body.Scope[0].ID
	// hack the response object to match the request object by the thread ID
	authResponse.ThreadID = msg.ID
	result, err := vm.VerifyProof(context.Background(), authResponse)
	assert.NoError(t, err)
	assert.Equal(t, true, result)
}
