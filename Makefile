# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOMOD=$(GOCMD) mod
GOTEST=$(GOCMD) test
# -trimpath: reproducible builds, no build-machine paths in the binary.
GOFLAGS := -v -trimpath
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X main.Version=$(VERSION)

# CGO is disabled across the board: Mzack9999/gopacket dlopens libpcap at
# runtime via purego, so neither libpcap headers nor a C toolchain are needed
# to build. Cross-compiles are plain GOOS/GOARCH go build.
export CGO_ENABLED=0

.PHONY: all build build-linux-amd64 build-linux-arm64 build-darwin-amd64 build-darwin-arm64 build-windows-amd64 test tidy

all: build
build:
	$(GOBUILD) $(GOFLAGS) -ldflags '$(LDFLAGS)' -o "pd-agent" ./cmd/pd-agent/
build-linux-amd64:
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(GOFLAGS) -ldflags '$(LDFLAGS)' -o "pd-agent-linux-amd64" ./cmd/pd-agent/
build-linux-arm64:
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(GOFLAGS) -ldflags '$(LDFLAGS)' -o "pd-agent-linux-arm64" ./cmd/pd-agent/
build-darwin-amd64:
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(GOFLAGS) -ldflags '$(LDFLAGS)' -o "pd-agent-darwin-amd64" ./cmd/pd-agent/
build-darwin-arm64:
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(GOFLAGS) -ldflags '$(LDFLAGS)' -o "pd-agent-darwin-arm64" ./cmd/pd-agent/
build-windows-amd64:
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(GOFLAGS) -ldflags '$(LDFLAGS)' -o "pd-agent-windows-amd64.exe" ./cmd/pd-agent/
test:
	$(GOTEST) $(GOFLAGS) ./...
tidy:
	$(GOMOD) tidy
