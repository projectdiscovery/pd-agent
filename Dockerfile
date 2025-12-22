FROM --platform=linux/amd64 golang:1.25 AS builder

RUN apt-get update && apt-get install -y git libpcap-dev

# Tools dependencies with optimization flags
# dnsx
RUN go install -ldflags="-s -w" github.com/projectdiscovery/dnsx/cmd/dnsx@latest
# naabu
RUN go install -ldflags="-s -w" github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
# httpx
RUN go install -ldflags="-s -w" github.com/projectdiscovery/httpx/cmd/httpx@latest
# tlsx
RUN go install -ldflags="-s -w" github.com/projectdiscovery/tlsx/cmd/tlsx@latest
# nuclei
RUN go install -ldflags="-s -w" github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest


# Copy source code
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Build pd-agent binary
# CGO_ENABLED=1 is required for libpcap/gopacket support (passive discovery feature)
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w" -o /go/bin/pd-agent ./cmd/pd-agent/main.go

# Clean Go module cache to reduce image size
RUN go clean -modcache && \
    rm -rf /root/.cache/go-build

FROM --platform=linux/amd64 ubuntu:22.04
# install dependencies
# required: libpcap-dev, chrome
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        libpcap-dev \
        wget \
        gnupg \
    && wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | gpg --dearmor -o /usr/share/keyrings/google-chrome.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google-chrome.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends google-chrome-stable \
    && apt-get purge -y wget gnupg \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /usr/share/doc /usr/share/man /usr/share/locale /usr/share/info

# Set environment variables for Chrome
ENV CHROME_BIN=/usr/bin/google-chrome-stable
ENV CHROME_PATH=/usr/bin/
ENV CHROME_NO_SANDBOX=true

# Copy tools binaries
COPY --from=builder /go/bin/dnsx /usr/local/bin/
COPY --from=builder /go/bin/naabu /usr/local/bin/
COPY --from=builder /go/bin/httpx /usr/local/bin/
COPY --from=builder /go/bin/tlsx /usr/local/bin/
COPY --from=builder /go/bin/nuclei /usr/local/bin/

# Copy agent binary
COPY --from=builder /go/bin/pd-agent /usr/local/bin/pd-agent

# Create ubuntu user and writable output directory
RUN useradd -m -u 1000 ubuntu && \
    mkdir -p /home/ubuntu/output && \
    chown -R ubuntu:ubuntu /home/ubuntu

# Set default environment variables (can be overridden at runtime)
ENV PDCP_API_KEY=""
ENV PDCP_TEAM_ID=""

# Switch to non-root user
USER ubuntu
WORKDIR /home/ubuntu

# ENTRYPOINT allows passing command-line arguments at runtime
# Environment variables should be passed via -e flags or docker-compose
ENTRYPOINT ["pd-agent"]
