## Setting up Go
ARG BUILD_VERSION
FROM golang:1.20.5 as builder

COPY . /service

WORKDIR /service
RUN make build_prod

# use small base image for distribution, don't need any build tools in final image
FROM alpine:3.16.0

RUN apk add --no-cache libstdc++ gcompat libgomp

WORKDIR /service
COPY --from=builder /service/verifier /usr/local/bin
COPY --from=builder /service/api /service/api
COPY --from=builder /service/pkg/circuits /service/pkg/circuits
COPY --from=builder "/go/pkg/mod/github.com/iden3/wasmer-go@v0.0.1/wasmer/packaged/lib/linux-amd64/libwasmer.so" \
  "/go/pkg/mod/github.com/iden3/wasmer-go@v0.0.1/wasmer/packaged/lib/linux-amd64/libwasmer.so"

ENTRYPOINT [ "verifier" ]
