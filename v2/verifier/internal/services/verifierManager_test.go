package services

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	ffconfig "github.com/hyperledger/firefly-common/pkg/config"
	"github.com/iden3/iden3comm/protocol"
	"github.com/kaleido-io/kaleido-iden3-verifier/internal/config"
	"github.com/stretchr/testify/assert"
)

const JWZString = `eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6IjhlMTA1ODMwLTk1NTAtNGExZS05NDA1LTc0Yjk1MjAwNDY2ZSIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zLXprcC1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI1YWVlOWNhNS03NzM0LTRmZDctYTE1NC0wODYzYTBmMTQ2ZDEiLCJib2R5Ijp7Im1lc3NhZ2UiOiIxNjkyMTU4Mzg0Iiwic2NvcGUiOlt7ImlkIjoxNjkyMTU4Mzg0LCJjaXJjdWl0SWQiOiJjcmVkZW50aWFsQXRvbWljUXVlcnlTaWdWMiIsInByb29mIjp7InBpX2EiOlsiNTQ1Mjg0MTU4MjExNzUyNjU0MzI2MjI3NzM4Njc2Mzc1MzI1MjQyNzkwOTI0MjY3NTk4MDI4OTE0MjY5Mzk2OTY4OTE1Mjk3MTc1NSIsIjEzMzc2MTkwMDc5OTE4NDk4NDcwOTY5NjcxNjkyMjUxNDY4MDk2NDAyOTc2NTA5NTcwMDEyNzM5OTY4OTEwMTkxNDg0OTc2OTc0MDg2IiwiMSJdLCJwaV9iIjpbWyIxMDY4NjQ2NTE0NTI3ODA1OTMzNzgwNDQ4MDQ5ODQyNzIxMjQ5NzMyNTMyOTM1OTcwNzY3MTA0NDc3NDc4MDcxMzgzMjk2MTE5OTg3NiIsIjE5OTUzNjQ3OTA1MjQyNjU1NzMxODc5MjM3MDM4OTEyNzA0NzU5ODg2MzczNjM2NTM3MTIyNjI2ODY0MzM1MDk0NzQwODQ1ODQ5MDYiXSxbIjE2MzYzMjkyMTAyMTQ5MzE1NjE5MjYwODYyMDMxODcyNjU4NjM2NTY3Mzg1NDU3NDIyMjAyOTI2MDcxNjczMDkwNzU4NzcyMTU3NDIyIiwiMTE1Mjg5Mzk0OTIxMjY5MzYzNDI1Mzc3ODQ5MTczNDE0MTc1Mjg0MTU5Mjc3Njg4OTY2MTk5NjA5NTA5MTAxMDQwNTE3NTcxNTg5OTYiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjEzODQyNzkxNDg3MzQ5NDI2NTQ0MzA4MzI1MDU1NzMzNjM1MzAzNjc5MjcxOTQ5NDc0MzA4MTU3MTE4NzcwODU5NDQyNjg5MjI2Njg1IiwiNTU4OTk2MjI0NTM0NTQwMjU4MTcyMDA4MTc3NDc1NjI3NTk0ODU3OTg4MjU5NDM0MDM2MDkyMjQxNDg3MDEwNTg3OTk0NDEyNDAxOSIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2IiwiY3VydmUiOiJibjEyOCJ9LCJwdWJfc2lnbmFscyI6WyIxIiwiMjEwNzExNjcyOTA1MzYwMjM3MjUxMzUxNDM1ODQxMDYzNTY0NjA3Mzk0MDkxNDQ0NjU5ODc0MTE2ODQ5MDE1NDU1OTYwMjY4ODEiLCIxMDA5NTUwMjc0OTUwOTg0NTc5NzU2ODY0NTQ2OTc1ODQ5MzI3NTg0MTQ4NDI5OTY1NjY0NTAxMjg3MDMwNTUzMzU2Njk5NTA0MTcyNCIsIjE2OTIxNTgzODQiLCIyMTEyNjg0NzMwNjM4MTEyOTI2NzA1NzY3ODMyNzM4NTM5MjQ1MzIwMTcyNjk0NTk4NTg3ODg5NDkxMjc1MTYxMjI5MTA1NTYxNyIsIjEiLCIxMDA5NTUwMjc0OTUwOTg0NTc5NzU2ODY0NTQ2OTc1ODQ5MzI3NTg0MTQ4NDI5OTY1NjY0NTAxMjg3MDMwNTUzMzU2Njk5NTA0MTcyNCIsIjE2ODkxOTY3NTciLCI3NDk3NzMyNzYwMDg0ODIzMTM4NTY2MzI4MDE4MTQ3NjMwNzY1NyIsIjAiLCIyMDM3NjAzMzgzMjM3MTEwOTE3NzY4MzA0ODQ1NjAxNDUyNTkwNTExOTE3MzY3NDk4NTg0MzkxNTQ0NTYzNDcyNjE2NzQ1MDk4OTYzMCIsIjIiLCIyIiwiMjAwMjEwMTAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiXX1dfSwiZnJvbSI6ImRpZDppZGVuMzp0VE1SbURqdWI5U2R4QzFMQ2l5NUZSTUtwdXV5clBFaTZIZWM3d2hSQyIsInRvIjoiZGlkOmlkZW4zOnRUamhZc1JNMkI2ZmJic3VRaHViZlBrUWlVckd3WVk2UUV6bkJReG42In0.eyJwcm9vZiI6eyJwaV9hIjpbIjE4MTgwNDg2MjI4NTgxNTM5MDcxMzI5MDgxMzM1OTgxNzA1NzkxODE5NzU0MTIzNTUwNDc3MDM1Njc5OTUzNjY1NTQ3NjM4NjIxNjA1IiwiODYxMTI1OTA2ODY4MjE3NTE5NDg5MDAxOTg3MDA2ODM3MzkyMDgwNDEzOTkzMTgyNTMwODIwOTY5MzIxNjkwMjAxNzc4NDE5MzQzNyIsIjEiXSwicGlfYiI6W1siMjExOTM5NjMwMDE3MDI0OTI4MDY0NzMzNzQ0NDAwNTcxNzMzNTAyNTE5MDM2NzAzODIyODE1MDg1NzcxNzk4MzIyNDAyMTM0MTM0ODciLCIyMDY0NDc5MDkyMTgzMjkxNTY0NTY3NDU0MDE2NDA5NDAwOTg4NDAxMDgyOTY5OTkzMzU2NDcyMTY3NTczMTExNjE3OTkzMDg0MTY1NSJdLFsiMjEzMzE2Mjc4MDkwODY5NDA4NjUwOTY4MjcwMzYxMTYzMjIyNzU2OTYyNjUzNjg0MTQwMzk4OTkyODU5MjYzODQwMzg1MjUwODU0OTciLCIyMTY2NjMyMjgwNzYwMjY3MTA1NjUwODIwNzc0NTAxNjAxNDEyMDMyMzYxMTgyMDU4NzAyOTE5OTcxODU0MjQ1Mzk4NzkwNDAwMDY0OCJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMzY1MTYyNDQzNjM5MTk0ODg4NjMwNzIwMzQ2MDE5MzEyMDI0OTc1OTczMDg3NTI5ODI2NzMxOTg4ODgwMjkyMjk5Mzg3MjI5MjY5MiIsIjEyMTgwMjQ2NDg2NzMzODM1NzY2Njg3MTA3MjI0MjUxODY4NzEwMjc5MzQyMDUyODAyMTgwNTAwMTgyNTk2NTA4MjM5MjEyNjk0NTciLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMjEwNzExNjcyOTA1MzYwMjM3MjUxMzUxNDM1ODQxMDYzNTY0NjA3Mzk0MDkxNDQ0NjU5ODc0MTE2ODQ5MDE1NDU1OTYwMjY4ODEiLCI5ODY2NzE4MjI0OTMyODE3NzA1NTYyMjExMzM2NTgwNTk0NzAwMDY2MzEwMjc0NTE0MTk0OTc4NDc2MTczODMxNTYxODM0NDEzMzA5IiwiMjYzMjAxNDg5MzkyMTMyOTQyNTkxNjk4MTk2MDkzMzkzMjA4Nzk1OTgwMDExODk1NzAxMjc3MTY2OTE0MTczODk0MDM4NDQxNDU5NyJdfQ`
const ProofRequest = `{
  "id": "46722b8b-4e78-4b2b-ac64-8e61f1bd5521",
  "typ": "application/iden3-zkp-json",
  "type": "https://iden3-communication.io/authorization/1.0/response",
  "thid": "5aee9ca5-7734-4fd7-a154-0863a0f146d1",
  "body": {
    "message": "1692158384",
    "scope": [
      {
        "id": 1692158384,
        "circuitId": "credentialAtomicQuerySigV2",
        "proof": {
          "pi_a": [
            "1711175984413221517288142766747407998872402540132944272690172116463924597027",
            "18696771148085896119578033418401261229969278767618994861190452858434360329542",
            "1"
          ],
          "pi_b": [
            [
              "11126180328522027856248213589432992020542222337881125102112321099408640464402",
              "711191150913249480599023803176462516964110694111149891483673623697124324238"
            ],
            [
              "13408318478771104868790777123701682125122277956521358082959433102042559412059",
              "9505250034842469231593162763153333040474728119176832403262007255701678303900"
            ],
            [
              "1",
              "0"
            ]
          ],
          "pi_c": [
            "11265890126006011901802151181792043170776365105262737114206178419904942077185",
            "18397919526332570563734736697329411584794386577670781583095811452872976731983",
            "1"
          ],
          "protocol": "groth16",
          "curve": "bn128"
        },
        "pub_signals": [
          "1",
          "21071167290536023725135143584106356460739409144465987411684901545596026881",
          "10095502749509845797568645469758493275841484299656645012870305533566995041724",
          "1692158384",
          "21126847306381129267057678327385392453201726945985878894912751612291055617",
          "1",
          "10095502749509845797568645469758493275841484299656645012870305533566995041724",
          "1689194049",
          "74977327600848231385663280181476307657",
          "0",
          "20376033832371109177683048456014525905119173674985843915445634726167450989630",
          "2",
          "2",
          "20021010",
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
  },
  "from": "did:iden3:tTMRmDjub9SdxC1LCiy5FRMKpuuyrPEi6Hec7whRC",
  "to": "did:iden3:tTjhYsRM2B6fbbsuQhubfPkQiUrGwYY6QEznBQxn6"
}
`
const ABI = `[
	{
		"inputs": [{ "internalType": "uint256", "name": "state", "type": "uint256" }],
		"name": "getStateInfoByState",
		"outputs": [
			{
				"components": [
					{ "internalType": "uint256", "name": "id", "type": "uint256" },
					{ "internalType": "uint256", "name": "state", "type": "uint256" },
					{ "internalType": "uint256", "name": "replacedByState", "type": "uint256" },
					{ "internalType": "uint256", "name": "createdAtTimestamp", "type": "uint256" },
					{ "internalType": "uint256", "name": "replacedAtTimestamp", "type": "uint256" },
					{ "internalType": "uint256", "name": "createdAtBlock", "type": "uint256" },
					{ "internalType": "uint256", "name": "replacedAtBlock", "type": "uint256" }
				],
				"internalType": "struct StateV2.StateInfo",
				"name": "",
				"type": "tuple"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "root",
				"type": "uint256"
			}
		],
		"name": "getGISTRootInfo",
		"outputs": [
			{
				"components": [
					{
						"internalType": "uint256",
						"name": "root",
						"type": "uint256"
					},
					{
						"internalType": "uint256",
						"name": "replacedByRoot",
						"type": "uint256"
					},
					{
						"internalType": "uint256",
						"name": "createdAtTimestamp",
						"type": "uint256"
					},
					{
						"internalType": "uint256",
						"name": "replacedAtTimestamp",
						"type": "uint256"
					},
					{
						"internalType": "uint256",
						"name": "createdAtBlock",
						"type": "uint256"
					},
					{
						"internalType": "uint256",
						"name": "replacedAtBlock",
						"type": "uint256"
					}
				],
				"internalType": "struct Smt.RootInfo",
				"name": "",
				"type": "tuple"
			}
		],
		"stateMutability": "view",
		"type": "function"
	}
]`

type rpcRequest struct {
	Version string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
	Id      uint64      `json:"id"`
}

func mockRPCServer(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		assert.NoError(t, err)
		fmt.Printf("%+v\n", req)

		if req.Method == "eth_call" {
			abiSpec, err := abi.JSON(strings.NewReader(ABI))
			assert.NoError(t, err)
			params := req.Params.([]interface{})[0].(map[string]interface{})
			data := params["data"].(string)
			decodedSig, _ := hex.DecodeString(data[2:10])
			method, _ := abiSpec.MethodById(decodedSig)
			fmt.Printf("method: %s\n", method)
			if method.Name == "getStateInfoByState" {
				http.Error(w, `{"error":{"message":"execution reverted: State does not exist"}}`, 200)
			} else if method.Name == "getGISTRootInfo" {
				msg := `{"jsonrpc":"2.0","id":1,"result":"0x05d1aaea55142a867782fd4a074bb3335206d14c91cba00861d2f7b6f8a80b8500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000064adb4ad00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000325ae70000000000000000000000000000000000000000000000000000000000000000"}`
				_, err := w.Write([]byte(msg))
				assert.NoError(t, err)
			}
		}
	}))
}

func TestConstructor(t *testing.T) {
	wdir, _ := os.Getwd()
	cfgFile := path.Join(wdir, "./resources/test-config.yaml")
	config.InitConfig()
	err := ffconfig.ReadConfig("iden3.verifier", cfgFile)
	assert.NoError(t, err)
	ffconfig.Set("iden3.verificationKeysDir", path.Join(wdir, "../../pkg/circuits"))
	output, _ := json.MarshalIndent(ffconfig.GetConfig(), "", "  ")
	fmt.Printf("Config: %s\n", string(output))
	newInst, err := NewManager(context.Background(), "http://localhost:8545", "0xabcd")
	assert.NoError(t, err)
	vm := newInst.(*verifierManager)
	assert.NotEmpty(t, vm.verifier)
}

func TestCreateChallenge(t *testing.T) {
	vm, _ := NewManager(context.Background(), "http://localhost:8545", "0xabcd")
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
	vm, _ := NewManager(context.Background(), "http://localhost:8545", "0xabcd")
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
	vm, _ := NewManager(context.Background(), "http://localhost:8545", "0xabcd")
	authResponse := &protocol.AuthorizationResponseMessage{}
	err := json.Unmarshal([]byte(ProofRequest), authResponse)
	assert.NoError(t, err)
	result, err := vm.VerifyProof(context.Background(), authResponse)
	assert.EqualError(t, err, "the Authorization Request 5aee9ca5-7734-4fd7-a154-0863a0f146d1 does not exist")
	assert.Equal(t, false, result)
}

func TestVerifySuccess(t *testing.T) {
	server := mockRPCServer(t)
	defer server.Close()
	vmgr, _ := NewManager(context.Background(), server.URL, "0xabcd")
	vm := vmgr.(*verifierManager)
	authResponse := &protocol.AuthorizationResponseMessage{}
	err := json.Unmarshal([]byte(ProofRequest), authResponse)
	assert.NoError(t, err)
	query := &Query{
		CredentialSubject: &map[string]Predicate{
			"birthday": map[string]interface{}{
				"$lt": 20021010,
			},
		},
		Context: "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
		Type:    "KYCAgeCredential",
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

func TestFullVerifySuccess(t *testing.T) {
	server := mockRPCServer(t)
	defer server.Close()
	vmgr, _ := NewManager(context.Background(), server.URL, "0xabcd")
	vm := vmgr.(*verifierManager)
	authResponse := &protocol.AuthorizationResponseMessage{}
	err := json.Unmarshal([]byte(ProofRequest), authResponse)
	assert.NoError(t, err)
	query := &Query{
		CredentialSubject: &map[string]Predicate{
			"birthday": map[string]interface{}{
				"$lt": 20021010,
			},
		},
		Context: "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
		Type:    "KYCAgeCredential",
	}
	msg, _ := vm.CreateChallenge(context.Background(), query)
	// hack the request object to match the pre-generated proof object
	msg.Body.Message = authResponse.Body.Message
	msg.Body.Scope[0].ID = authResponse.Body.Scope[0].ID
	// hack the response object to match the request object by the thread ID
	authResponse.ThreadID = msg.ID
	result, err := vm.verifier.VerifyJWZ(context.Background(), JWZString)
	assert.NoError(t, err)
	assert.Equal(t, "authV2", result.CircuitID)
	assert.Equal(t, "groth16", result.Alg)
}
