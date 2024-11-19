FROM golang:1.20.6-alpine AS builder
RUN apk add --no-cache git
RUN go install -v github.com/projectdiscovery/pdtm-agent/cmd/pdtm-agent@latest

FROM alpine:3.18.2
RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates
COPY --from=builder /go/bin/pdtm-agent /usr/local/bin/

ENTRYPOINT ["pdtm-agent"]
