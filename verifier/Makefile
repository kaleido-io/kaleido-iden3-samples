VGO=go
GOFILES := $(shell find cmd internal -name '*.go' -print)
GOBIN := $(shell $(VGO) env GOPATH)/bin
LINT := $(GOBIN)/golangci-lint
MOCKERY := $(GOBIN)/mockery
GOGC=30

.DELETE_ON_ERROR:

all: build test go-mod-tidy
test: deps lint
		$(VGO) test ./... -cover -coverprofile=coverage.txt -covermode=atomic -timeout=30s
coverage.html:
		$(VGO) tool cover -html=coverage.txt
coverage: test coverage.html
lint: ${LINT}
		GOGC=20 $(LINT) run -v --timeout 5m
${MOCKERY}:
		$(VGO) install github.com/vektra/mockery/cmd/mockery@latest
${LINT}:
		$(VGO) install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.47.0

define makemock
mocks: mocks-$(strip $(1))-$(strip $(2))
mocks-$(strip $(1))-$(strip $(2)): ${MOCKERY}
	${MOCKERY} --case underscore --dir $(1) --name $(2) --outpkg $(3) --output mocks/$(strip $(3))
endef

build: ${GOFILES}
	$(VGO) build -o verifier -ldflags "-X main.buildDate=`date -u +\"%Y-%m-%dT%H:%M:%SZ\"`" -v
build_prod: ${GOFILES}
	$(VGO) build -o verifier -ldflags "-X main.buildDate=`date -u +\"%Y-%m-%dT%H:%M:%SZ\"`" -v -tags=prod
go-mod-tidy: .ALWAYS
		$(VGO) mod tidy
.ALWAYS: ;
clean:
		$(VGO) clean
deps:
		$(VGO) get ./...
reference:
		$(VGO) test ./... -timeout=10s -tags docs
.PHONY: docker
docker:
		docker build --build-arg BUILD_VERSION=${BUILD_VERSION} ${DOCKER_ARGS} -t iden3_verifier .

run: build
	./verifier
