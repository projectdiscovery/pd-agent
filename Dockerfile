FROM --platform=linux/amd64 golang:1.24 AS builder
RUN apt-get update && apt-get install -y git
ARG GITHUB_TOKEN
RUN git config --global url."https://${GITHUB_TOKEN}:x-oauth-basic@github.com/".insteadOf "https://github.com/"
RUN go env -w GOPRIVATE=github.com/projectdiscovery
RUN go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest

FROM --platform=linux/amd64 ubuntu:latest
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

COPY --from=builder /go/bin/pdtm /usr/local/bin/

ENTRYPOINT ["pdtm-agent"]
