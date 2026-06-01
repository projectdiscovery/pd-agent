FROM --platform=$BUILDPLATFORM golang:1.25 AS builder

RUN apt-get update && apt-get install -y git

ENV CGO_ENABLED=0

ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Build pd-agent. All PD scanners (nuclei/naabu/httpx/dnsx/tlsx) are linked
# into the binary via pkg/runtools, so this is the only artifact we need to
# ship. Mzack9999/gopacket dlopens libpcap at runtime via purego, so no cgo
# or libpcap headers are needed at build time; features that need libpcap
# warn-and-skip at runtime if the lib is missing. The builder runs on the
# native BUILDPLATFORM and cross-compiles to TARGETARCH, so multi-arch images
# build without QEMU-emulating the Go toolchain.
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w -X main.Version=${VERSION}" -o /go/bin/pd-agent ./cmd/pd-agent

FROM debian:bookworm-slim
# Runtime dependencies: chromium for nuclei/httpx headless screenshots. Debian
# ships chromium for both amd64 and arm64 (Google Chrome is amd64-only), so the
# image is genuinely multi-arch. fonts-liberation gives headless renders a base
# font set; procps provides pgrep for the example k8s liveness/readiness probes;
# ca-certificates for outbound TLS. naabu does service-version detection
# natively (nmap-service-probes parsed in-process), so no nmap binary is
# required. libpcap is intentionally not installed: naabu's syn-scan warns and
# skips when it's missing. Extend with `apt install libpcap0.8` if you need it.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    chromium \
    fonts-liberation \
    procps \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ENV CHROME_BIN=/usr/bin/chromium
ENV CHROME_PATH=/usr/bin/
ENV CHROME_NO_SANDBOX=true

COPY --from=builder /go/bin/pd-agent /usr/local/bin/pd-agent

# Non-root user (UID 1000 matches the example k8s securityContext). debian-slim
# has no default user, so create one with a writable home for scan output.
RUN useradd --create-home --uid 1000 --shell /usr/sbin/nologin pd-agent \
    && mkdir -p /home/pd-agent/output \
    && chown -R pd-agent:pd-agent /home/pd-agent

USER pd-agent
WORKDIR /home/pd-agent

ENTRYPOINT ["pd-agent"]
