FROM --platform=linux/amd64 golang:1.25 AS builder
RUN apt-get update && apt-get install -y git libpcap-dev
ARG GITHUB_TOKEN
RUN git config --global url."https://${GITHUB_TOKEN}:x-oauth-basic@github.com/".insteadOf "https://github.com/"
RUN go env -w GOPRIVATE=github.com/projectdiscovery

# Copy source code
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Build pd-agent binary
# CGO_ENABLED=1 is required for libpcap/gopacket support (passive discovery feature)
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /go/bin/pd-agent ./cmd/pd-agent/main.go

# Tools dependencies
# dnsx
RUN go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
# naabu
RUN go install -v github.com/projectdiscovery/naabu/cmd/naabu@latest
# httpx
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
# tlsx
RUN go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
# nuclei
RUN go install -v github.com/projectdiscovery/nuclei/cmd/nuclei@latest

FROM --platform=linux/amd64 ubuntu:latest
# install dependencies
# required: libpcap-dev, chrome
RUN apt update && apt install -y \
    bind9-dnsutils \
    ca-certificates \
    nmap \
    libpcap-dev \
    wget \
    gnupg \
    && wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | gpg --dearmor -o /usr/share/keyrings/google-chrome.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google-chrome.list \
    && apt update \
    && apt install -y google-chrome-stable \
    && apt clean \
    && rm -rf /var/lib/apt/lists/*

# Set environment variables for Chrome
ENV CHROME_BIN=/usr/bin/google-chrome-stable
ENV CHROME_PATH=/usr/bin/
ENV CHROME_NO_SANDBOX=true

# Copy agent binary
COPY --from=builder /go/bin/pd-agent /usr/local/bin/pd-agent

# Copy tools binaries
COPY --from=builder /go/bin/dnsx /usr/local/bin/
COPY --from=builder /go/bin/naabu /usr/local/bin/
COPY --from=builder /go/bin/httpx /usr/local/bin/
COPY --from=builder /go/bin/tlsx /usr/local/bin/
COPY --from=builder /go/bin/nuclei /usr/local/bin/

# Set default environment variables (can be overridden at runtime)
ENV PDCP_API_KEY=""
ENV PDCP_TEAM_ID=""

# ENTRYPOINT allows passing command-line arguments at runtime
# Environment variables should be passed via -e flags or docker-compose
ENTRYPOINT ["pd-agent"]
