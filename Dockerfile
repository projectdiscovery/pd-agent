FROM --platform=linux/amd64 golang:1.25 AS builder

RUN apt-get update && apt-get install -y git

ENV CGO_ENABLED=0

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Build pd-agent. All PD scanners (nuclei/naabu/httpx/dnsx/tlsx) are linked
# into the binary via pkg/runtools, so this is the only artifact we need to
# ship. Mzack9999/gopacket dlopens libpcap at runtime via purego, so no cgo
# or libpcap headers are needed at build time; features that need libpcap
# warn-and-skip at runtime if the lib is missing.
RUN GOOS=linux go build -ldflags="-s -w" -o /go/bin/pd-agent ./cmd/pd-agent/main.go

FROM --platform=linux/amd64 ubuntu:latest
# Runtime dependencies: Chrome for nuclei/httpx headless screenshots, plus
# ca-certificates for outbound TLS. nmap was dropped — naabu's service
# detection is moving to native fingerprinting (naabu PR #1667). libpcap is
# intentionally not installed: syn-scan and IGMP discovery warn-and-skip when
# it's missing. Users who want either can extend this image with
# `apt install nmap libpcap0.8`.
RUN apt update && apt install -y \
    ca-certificates \
    wget \
    gnupg \
    && wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | gpg --dearmor -o /usr/share/keyrings/google-chrome.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google-chrome.list \
    && apt update \
    && apt install -y google-chrome-stable \
    && apt clean \
    && rm -rf /var/lib/apt/lists/*

ENV CHROME_BIN=/usr/bin/google-chrome-stable
ENV CHROME_PATH=/usr/bin/
ENV CHROME_NO_SANDBOX=true

COPY --from=builder /go/bin/pd-agent /usr/local/bin/pd-agent

# Writable output directory for the ubuntu user (UID 1000)
RUN mkdir -p /home/ubuntu/output && \
    chown -R ubuntu:ubuntu /home/ubuntu

ENV PDCP_API_KEY=""
ENV PDCP_TEAM_ID=""

USER ubuntu
WORKDIR /home/ubuntu

ENTRYPOINT ["pd-agent"]
