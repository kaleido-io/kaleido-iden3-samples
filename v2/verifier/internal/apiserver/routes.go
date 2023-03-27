package apiserver

import (
	"io"
	"net/http"

	"github.com/hyperledger/firefly-common/pkg/ffapi"
	"github.com/iden3/iden3comm/protocol"
	"github.com/kaleido-io/kaleido-iden3-verifier/internal/services"
)

type VerifierRequest struct {
	vm services.VerifierManager
}

type VerifierExtensions struct {
	Handle func(r *ffapi.APIRequest, sr *VerifierRequest) (output interface{}, err error)
}

var StatusRoute = &ffapi.Route{
	Name:            "Status",
	Path:            "status",
	Method:          http.MethodGet,
	Description:     "Status of the verifier server",
	PathParams:      nil,
	QueryParams:     nil,
	JSONInputValue:  nil,
	JSONOutputValue: func() interface{} { return &services.OverallStatus{} },
	JSONOutputCodes: []int{http.StatusOK},
	Extensions: &VerifierExtensions{
		Handle: func(r *ffapi.APIRequest, sr *VerifierRequest) (output interface{}, err error) {
			// For liveness, as long as we are happy with the fundamentals, all is ok
			return sr.vm.Status(r.Req.Context())
		},
	},
}

var CreateChallengeRoute = &ffapi.Route{
	Name:            "Challenge",
	Path:            "challenges",
	Method:          http.MethodPost,
	Description:     "Generate a challenge message",
	PathParams:      nil,
	QueryParams:     nil,
	JSONInputValue:  func() interface{} { return &services.Query{} },
	JSONOutputValue: func() interface{} { return &protocol.AuthorizationRequestMessage{} },
	JSONOutputCodes: []int{http.StatusOK},
	Extensions: &VerifierExtensions{
		Handle: func(r *ffapi.APIRequest, sr *VerifierRequest) (output interface{}, err error) {
			// For liveness, as long as we are happy with the fundamentals, all is ok
			return sr.vm.CreateChallenge(r.Req.Context(), r.Input.(*services.Query))
		},
	},
}

var ChallengeStatusRoute = &ffapi.Route{
	Name:        "Challenge",
	Path:        "challenges/{threadId}",
	Method:      http.MethodGet,
	Description: "Get the status of a challenge",
	PathParams: []*ffapi.PathParam{
		{Name: "threadId", Description: "threadId of a challenge message"},
	},
	QueryParams:     nil,
	JSONInputValue:  nil,
	JSONOutputValue: func() interface{} { return &services.ChallengeStatus{} },
	JSONOutputCodes: []int{http.StatusOK},
	Extensions: &VerifierExtensions{
		Handle: func(r *ffapi.APIRequest, sr *VerifierRequest) (output interface{}, err error) {
			// For liveness, as long as we are happy with the fundamentals, all is ok
			return sr.vm.GetChallenge(r.Req.Context(), r.PP["threadId"])
		},
	},
}

var VerifyRoute = &ffapi.Route{
	Name:        "Verify",
	Path:        "verify",
	Method:      http.MethodPost,
	Description: "Verify a proof response",
	PathParams:  nil,
	QueryParams: []*ffapi.QueryParam{
		{Name: "threadId", Description: "Id of the credential challenge"},
	},
	JSONInputValue:  nil, // input is text instead of JSON
	JSONOutputValue: func() interface{} { return &services.OverallStatus{} },
	JSONOutputCodes: []int{http.StatusOK},
	Extensions: &VerifierExtensions{
		Handle: func(r *ffapi.APIRequest, sr *VerifierRequest) (output interface{}, err error) {
			tokenBytes, err := io.ReadAll(r.Req.Body)
			if err != nil {
				return nil, err
			}
			return sr.vm.VerifyJWZ(r.Req.Context(), string(tokenBytes), r.QP["threadId"])
		},
	},
}

var Routes []*ffapi.Route

func init() {
	Routes = append(Routes, StatusRoute)
	Routes = append(Routes, CreateChallengeRoute)
	Routes = append(Routes, ChallengeStatusRoute)
	Routes = append(Routes, VerifyRoute)
}
