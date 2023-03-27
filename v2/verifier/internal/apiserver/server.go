package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/gorilla/mux"
	ffconfig "github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly-common/pkg/ffapi"
	"github.com/hyperledger/firefly-common/pkg/httpserver"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/kaleido-io/kaleido-iden3-verifier/internal/config"
	"github.com/kaleido-io/kaleido-iden3-verifier/internal/services"
	"gopkg.in/yaml.v2"
)

type Server interface {
	Serve(ctx context.Context) error
}

type apiServer struct {
	// Defaults set with config
	defaultFilterLimit uint64
	maxFilterLimit     uint64
	maxFilterSkip      uint64
	apiTimeout         time.Duration
	apiMaxTimeout      time.Duration
	vm                 services.VerifierManager
	// metricsEnabled     bool
}

func NewAPIServer(ctx context.Context) (Server, error) {
	vm, err := services.NewManager(ctx)
	if err != nil {
		return nil, err
	}
	return &apiServer{
		defaultFilterLimit: 0, // unused: no filtered APIs
		maxFilterLimit:     0, // unused: no filtered APIs
		maxFilterSkip:      0, // unused: no filtered APIs
		apiTimeout:         config.APIConfig.GetDuration(config.APIRequestTimeout),
		apiMaxTimeout:      config.APIConfig.GetDuration(config.APIRequestTimeoutMax),
		vm:                 vm,
	}, nil
}

func (ser *apiServer) Serve(ctx context.Context) (err error) {
	httpErrChan := make(chan error)

	apiHttpServer, err := httpserver.NewHTTPServer(ctx, "Kaleido-iden3-verifier", ser.createMuxRouter(ctx), httpErrChan, config.APIConfig, config.CORSConfig, &httpserver.ServerOptions{
		MaximumRequestTimeout: 60,
	})

	if err != nil {
		log.L(ctx).Errorf("Error in setting new HTTP servers")
		return err
	}

	go apiHttpServer.ServeHTTP(ctx)

	httperr := <-httpErrChan
	return httperr
}

func (ser *apiServer) createMuxRouter(ctx context.Context) *mux.Router {
	r := mux.NewRouter().UseEncodedPath()
	hf := ser.handlerFactory()

	publicURL := ser.getPublicURL(config.APIConfig, "")
	apiBaseURL := fmt.Sprintf("%s/api/v1", publicURL)
	log.L(ctx).Infof("API Base URL - %s", apiBaseURL)
	for _, route := range Routes {
		r.HandleFunc(fmt.Sprintf("/api/v1/%s", route.Path), ser.routeHandler(hf, route)).Methods(route.Method)
	}

	r.HandleFunc(`/api/swagger{ext:\.yaml|\.json|}`, hf.APIWrapper(ser.swaggerHandler(ser.swaggerGenerator(Routes, apiBaseURL))))
	r.HandleFunc(`/api`, hf.APIWrapper(hf.SwaggerUIHandler(publicURL+"/api/swagger.yaml")))
	log.L(ctx).Infof("Swagger UI at %s", publicURL+"/api/swagger.yaml")
	r.NotFoundHandler = hf.APIWrapper(ser.notFoundHandler)
	return r
}

func (ser *apiServer) routeHandler(hf *ffapi.HandlerFactory, route *ffapi.Route) http.HandlerFunc {
	ce := route.Extensions
	cr := ce.(*VerifierExtensions)
	route.JSONHandler = func(r *ffapi.APIRequest) (output interface{}, err error) {
		return cr.Handle(r, &VerifierRequest{
			vm: ser.vm,
		})
	}
	return hf.RouteHandler(route)
}

func (ser *apiServer) getPublicURL(conf ffconfig.Section, pathPrefix string) string {
	publicURL := conf.GetString(httpserver.HTTPConfPublicURL)

	if publicURL == "" {
		proto := "https"
		if !conf.GetBool(httpserver.HTTPConfTLSEnabled) {
			proto = "http"
		}
		publicURL = fmt.Sprintf("%s://%s:%s", proto, conf.GetString(httpserver.HTTPConfAddress), conf.GetString(httpserver.HTTPConfPort))
	}
	if pathPrefix != "" {
		publicURL += "/" + pathPrefix
	}

	return publicURL
}

func (ser *apiServer) swaggerGenConf(apiBaseURL string) *ffapi.Options {
	return &ffapi.Options{
		BaseURL:                   apiBaseURL,
		Title:                     "Kaleido Iden3 Verifier",
		Version:                   "1.0",
		PanicOnMissingDescription: false,
		DefaultRequestTimeout:     ser.apiTimeout,
	}
}

func (ser *apiServer) swaggerHandler(generator func(req *http.Request) (*openapi3.T, error)) func(res http.ResponseWriter, req *http.Request) (status int, err error) {
	return func(res http.ResponseWriter, req *http.Request) (status int, err error) {
		vars := mux.Vars(req)
		doc, err := generator(req)
		if err != nil {
			return 500, err
		}
		if vars["ext"] == ".json" {
			res.Header().Add("Content-Type", "application/json")
			b, _ := json.Marshal(&doc)
			_, _ = res.Write(b)
		} else {
			res.Header().Add("Content-Type", "application/x-yaml")
			b, _ := yaml.Marshal(&doc)
			_, _ = res.Write(b)
		}
		return 200, nil
	}
}

func (ser *apiServer) swaggerGenerator(routes []*ffapi.Route, apiBaseURL string) func(req *http.Request) (*openapi3.T, error) {
	swg := ffapi.NewSwaggerGen(ser.swaggerGenConf(apiBaseURL))
	return func(req *http.Request) (*openapi3.T, error) {
		return swg.Generate(req.Context(), routes), nil
	}
}

func (ser *apiServer) handlerFactory() *ffapi.HandlerFactory {
	return &ffapi.HandlerFactory{
		DefaultRequestTimeout: ser.apiTimeout,
		MaxTimeout:            ser.apiMaxTimeout,
	}
}

func (as *apiServer) notFoundHandler(res http.ResponseWriter, req *http.Request) (status int, err error) {
	res.Header().Add("Content-Type", "application/json")
	return 404, i18n.NewError(req.Context(), "Not Found. 404 Error")
}
