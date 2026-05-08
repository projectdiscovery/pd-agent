# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOMOD=$(GOCMD) mod
GOTEST=$(GOCMD) test
GOFLAGS := -v
# This should be disabled if the binary uses pprof
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X main.Version=$(VERSION)

ifneq ($(shell go env GOOS),darwin)
LDFLAGS := -extldflags "-static"
endif

.PHONY: all build build-linux-amd64 build-linux-arm64 build-windows-amd64 test tidy

all: build
build:
	$(GOBUILD) $(GOFLAGS) -ldflags '$(LDFLAGS)' -o "pd-agent" ./cmd/pd-agent/
build-linux-amd64:
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
	CC="zig cc -target x86_64-linux-musl" \
	CXX="zig c++ -target x86_64-linux-musl" \
	CGO_CFLAGS="-I$(CURDIR)/build/libpcap-linux-amd64/include" \
	CGO_LDFLAGS="-L$(CURDIR)/build/libpcap-linux-amd64/lib" \
	$(GOBUILD) -ldflags '-s -w -X main.Version=$(VERSION) -extldflags "-static"' -o "pd-agent-linux-amd64" ./cmd/pd-agent/
build-linux-arm64:
	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
	CC="zig cc -target aarch64-linux-musl" \
	CXX="zig c++ -target aarch64-linux-musl" \
	$(GOBUILD) -ldflags '-s -w -X main.Version=$(VERSION) -extldflags "-static"' -o "pd-agent-linux-arm64" ./cmd/pd-agent/
build-windows-amd64:
	@test -d "$(CURDIR)/build/npcap-sdk-windows-amd64/Include" || (echo "Npcap SDK missing. Download https://npcap.com/dist/npcap-sdk-1.13.zip and extract to build/npcap-sdk-windows-amd64/ (so Include/ and Lib/x64/ exist)" && exit 1)
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 \
	CC="zig cc -target x86_64-windows-gnu" \
	CXX="zig c++ -target x86_64-windows-gnu" \
	CGO_CFLAGS="-I$(CURDIR)/build/npcap-sdk-windows-amd64/Include" \
	CGO_LDFLAGS="-L$(CURDIR)/build/npcap-sdk-windows-amd64/Lib/x64" \
	$(GOBUILD) -ldflags '-s -w -X main.Version=$(VERSION)' -o "pd-agent-windows-amd64.exe" ./cmd/pd-agent/
test:
	$(GOTEST) $(GOFLAGS) ./...
tidy:
	$(GOMOD) tidy
