package messages

import (
	"encoding/json"
	"github.com/iden3/iden3comm/protocol"
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
	Verified               bool                                  `json:"verified"`
	Message                *protocol.AuthorizationRequestMessage `json:"message"`
	VerifiablePresentation json.RawMessage                       `json:"vp,omitempty"`
}

type ChallengeStatus struct {
	ID                     string          `json:"id"`
	Verified               bool            `json:"verified"`
	VerifiablePresentation json.RawMessage `json:"vp,omitempty"`
}
