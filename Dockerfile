FROM golang:1.26-alpine3.23 AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG GITCOMMIT=unknown
ARG GITDATE=0
ARG VERSION=v0.0.0

WORKDIR /
COPY . op-alt-da
RUN apk add --no-cache make ca-certificates && update-ca-certificates
WORKDIR /op-alt-da
RUN GOFLAGS="-buildvcs=false" make da-server \
    TARGETOS="${TARGETOS}" \
    TARGETARCH="${TARGETARCH}" \
    GITCOMMIT="${GITCOMMIT}" \
    GITDATE="${GITDATE}" \
    VERSION="${VERSION}"

FROM alpine:3.23

# wget for internal healthcheck
RUN apk add --no-cache ca-certificates wget && update-ca-certificates

COPY --from=builder /op-alt-da/bin/da-server /usr/local/bin/da-server

EXPOSE 3100
ENTRYPOINT ["/usr/local/bin/da-server"]
