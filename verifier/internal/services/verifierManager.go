package services

import (
	"context"
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"net/url"

	"github.com/iden3/go-circuits"
	auth "github.com/iden3/go-iden3-auth"
	"github.com/iden3/go-iden3-auth/loaders"
	"github.com/iden3/go-iden3-auth/pubsignals"
	"github.com/iden3/go-iden3-auth/state"
	"github.com/iden3/iden3comm/protocol"
	"github.com/kaleido-io/kaleido-iden3-verifier/internal/config"
)

const (
	CredentialAtomicQuerySigV2 = "credentialAtomicQuerySigV2"
)

type Predicate map[string]interface{}

type Query struct {
	AllowedIssuers    *[]string             `json:"allowedIssuers"`
	CredentialSubject *map[string]Predicate `json:"credentialSubject"`
	Context           string                `json:"context"`
	Type              string                `json:"type"`
}

type AuthorizationRequestMessageWithStatus struct {
	Verified bool                                  `json:"verified"`
	Message  *protocol.AuthorizationRequestMessage `json:"message"`
}

type ChallengeStatus struct {
	ID       string `json:"id"`
	Verified bool   `json:"verified"`
}

type VerifierManager interface {
	Status(context.Context) (*OverallStatus, error)
	CreateChallenge(context.Context, *Query) (*protocol.AuthorizationRequestMessage, error)
	GetChallenge(context.Context, string) (*ChallengeStatus, error)
	VerifyProof(context.Context, *protocol.AuthorizationResponseMessage) (bool, error)
	VerifyJWZ(context.Context, string, string) (bool, error)
}

// verifierManager has the core orchestration endpoints for the iden3 verifier
// TODO: use a db for the request cache to track across server instances
type verifierManager struct {
	verifier     *auth.Verifier
	requestCache map[string]*AuthorizationRequestMessageWithStatus
}

func NewManager(ctx context.Context, url, contract string) (vm VerifierManager, err error) {
	schemaLoader := &loaders.DefaultSchemaLoader{}
	verificationKeyLoader := &loaders.FSKeyLoader{
		Dir: config.Iden3Config.GetString(config.Iden3CircuitKeysDir),
	}
	ethResolver := state.NewETHResolver(url, contract)
	ethStateResolvers := map[string]pubsignals.StateResolver{
		// until the go-iden3-core is enhanced to support custom blockchain and network names,
		// we'll just use "" for both names
		":":              ethResolver,
		"polygon:mumbai": ethResolver,
	}
	authInstance := auth.NewVerifier(verificationKeyLoader, schemaLoader, ethStateResolvers)
	vm = &verifierManager{
		verifier:     authInstance,
		requestCache: make(map[string]*AuthorizationRequestMessageWithStatus),
	}
	return vm, nil
}

func (m *verifierManager) Status(ctx context.Context) (s *OverallStatus, err error) {
	s = &OverallStatus{
		Status: "OK",
	}

	return s, nil
}

func (m *verifierManager) CreateChallenge(ctx context.Context, query *Query) (*protocol.AuthorizationRequestMessage, error) {
	req := protocol.ZeroKnowledgeProofRequest{}
	id, err := getRandomUint32()
	if err != nil {
		return nil, err
	}
	req.ID = id
	req.CircuitID = string(circuits.AtomicQuerySigV2CircuitID)
	optional := true
	req.Optional = &optional
	issuers := []string{"*"}
	if query.AllowedIssuers != nil {
		issuers = *query.AllowedIssuers
	}
	req.Query = map[string]interface{}{
		"allowedIssuers":    issuers,
		"credentialSubject": *query.CredentialSubject,
		"context":           query.Context,
		"type":              query.Type,
	}
	callbackUrl, err := getCallbackUrl()
	if err != nil {
		return nil, err
	}
	challengeMsg := fmt.Sprintf("%d", id)
	self := config.Iden3Config.GetString(config.Iden3Self)
	msg := auth.CreateAuthorizationRequestWithMessage("challenge", challengeMsg, self, callbackUrl.String())
	msg.Body.Scope = append(msg.Body.Scope, req)
	// append the thread ID to the callback URL
	values := callbackUrl.Query()
	values.Add("threadId", msg.ThreadID)
	callbackUrl.RawQuery = values.Encode()
	msg.Body.CallbackURL = callbackUrl.String()
	m.requestCache[msg.ThreadID] = &AuthorizationRequestMessageWithStatus{
		Message: &msg,
	}
	return &msg, nil
}

func (m *verifierManager) GetChallenge(ctx context.Context, requestId string) (*ChallengeStatus, error) {
	req := m.requestCache[requestId]
	if req == nil {
		return nil, fmt.Errorf("challenge by the id %s not found", requestId)
	}
	return &ChallengeStatus{
		ID:       requestId,
		Verified: req.Verified,
	}, nil
}

func (m *verifierManager) VerifyProof(ctx context.Context, message *protocol.AuthorizationResponseMessage) (bool, error) {
	threadId := message.ThreadID
	request := m.requestCache[threadId]
	if request == nil {
		return false, fmt.Errorf("the Authorization Request %s does not exist", threadId)
	}

	err := m.verifier.VerifyAuthResponse(ctx, *message, *request.Message)
	if err != nil {
		return false, err
	}
	request.Verified = true
	return true, nil
}

func (m *verifierManager) VerifyJWZ(ctx context.Context, jwz string, threadId string) (bool, error) {
	// parse the thread ID from the jwz token

	request := m.requestCache[threadId]
	if request == nil {
		return false, fmt.Errorf("the Authorization Request %s does not exist", threadId)
	}
	_, err := m.verifier.FullVerify(ctx, jwz, *request.Message)
	if err != nil {
		return false, err
	}
	request.Verified = true
	return true, nil
}

func getRandomUint32() (uint32, error) {
	value, err := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
	if err != nil {
		return 0, err
	}
	return uint32(value.Uint64()), nil
}

func getCallbackUrl() (*url.URL, error) {
	publicHost := config.Iden3Config.GetString(config.Iden3ServerHostname)
	url, err := url.Parse(publicHost)
	if err != nil {
		return nil, err
	}
	fullUrl := url.JoinPath("api/v1/verify")
	return fullUrl, nil
}
