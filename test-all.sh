#!/bin/bash
set -e

BASE_DIR="$HOME/GitHubTest"
LOG_FILE="$BASE_DIR/dev-setup.log"

# Create BASE_DIR if it doesn't exist
mkdir -p "$BASE_DIR"
touch "$LOG_FILE"

# Check if GITHUB_TOKEN is defined
if [ -z "$GITHUB_TOKEN" ]; then
  echo "Error: GITHUB_TOKEN environment variable is not set"
  echo "Please set it with: export GITHUB_TOKEN=your_token_here"
  exit 1
fi

# Define all API keys
export AURORA_API_KEY="5bc39e68-2d04-45d2-9acf-d41bc6497644"
export AURORA_SERVICE_API_KEY="5bc39e68-2d04-45d2-9acf-d41bc6497644"
export SCHEDULER_SERVICE_API_KEY="86ea1d37-1b39-411f-b31a-d9b64a7bc4fe"
export PDCP_DEV_API_KEY="47fd9e1c-542f-4ef8-86df-ffdc815dfd2e"

# Function to create .env file
create_env() {
  local vars=("$@")
  > .env
  for var in "${vars[@]}"; do
    echo "${var}=${!var}" >> .env
  done
}

cd "$BASE_DIR"

# 1. Aurora
if [ ! -d aurora ]; then
  git clone https://github.com/projectdiscovery/aurora.git | tee -a "$LOG_FILE"
fi
cd aurora
git fetch origin | tee -a "$LOG_FILE"
gh pr checkout 2544 | tee -a "$LOG_FILE"
git pull | tee -a "$LOG_FILE"
cd cmd/dev

# Create .env file for aurora
echo "Creating .env file for aurora..." | tee -a "$LOG_FILE"
create_env "AURORA_API_KEY"

echo "[AURORA] Running dev..." | tee -a "$LOG_FILE"
GITHUB_TOKEN="$GITHUB_TOKEN" go run . -test-type scan -skip-run 2>&1 | tee -a "$LOG_FILE"
cd "$BASE_DIR"

# 2. Scan-Scheduler
if [ ! -d scan-scheduler ]; then
  git clone https://github.com/projectdiscovery/scan-scheduler.git | tee -a "$LOG_FILE"
fi
cd scan-scheduler
git fetch origin | tee -a "$LOG_FILE"
gh pr checkout 101 | tee -a "$LOG_FILE"
git pull | tee -a "$LOG_FILE"

cd cmd/dev

# Create .env file for scan-scheduler
echo "Creating .env file for scan-scheduler..." | tee -a "$LOG_FILE"
create_env "AURORA_SERVICE_API_KEY" "SCHEDULER_SERVICE_API_KEY"

echo "[SCAN-SCHEDULER] Running dev..." | tee -a "$LOG_FILE"
GITHUB_TOKEN="$GITHUB_TOKEN" go run . 2>&1 | tee -a "$LOG_FILE"
cd "$BASE_DIR"

# 3. Platform Backend
if [ ! -d platform-backend ]; then
  git clone https://github.com/projectdiscovery/platform-backend.git | tee -a "$LOG_FILE"
fi
cd platform-backend
git fetch origin | tee -a "$LOG_FILE"
gh pr checkout 1051 | tee -a "$LOG_FILE"
git pull | tee -a "$LOG_FILE"
cd cmd/dev

# Create .env file for platform-backend
echo "Creating .env file for platform-backend..." | tee -a "$LOG_FILE"
create_env "AURORA_SERVICE_API_KEY" "SCHEDULER_SERVICE_API_KEY"

echo "[PLATFORM BACKEND] Running dev..." | tee -a "$LOG_FILE"
GITHUB_TOKEN="$GITHUB_TOKEN" go run . 2>&1 | tee -a "$LOG_FILE"
cd "$BASE_DIR"

# 4. PDTM-AGENT
# if [ ! -d pdtm-agent ]; then
#   git clone https://github.com/projectdiscovery/pdtm-agent.git | tee -a "$LOG_FILE"
# fi
# cd pdtm-agent
# git fetch origin | tee -a "$LOG_FILE"
# gh pr checkout 1 | tee -a "$LOG_FILE"
# git pull | tee -a "$LOG_FILE"
# cd cmd/pdtm-agent
# echo "[PDTM-AGENT] Running agent in background..." | tee -a "$LOG_FILE"
# PDCP_API_KEY="$PDCP_DEV_API_KEY" PDCP_API_SERVER="http://localhost:8088" PUNCH_HOLE_HOST="127.0.0.1" PUNCH_HOLE_HTTP_PORT="8880" \
#   nohup go run . -agent -agent-output test -verbose -agent-tags test-group > "$BASE_DIR/pdtm-agent.log" 2>&1 &
# PDTM_AGENT_PID=$!
# echo "[PDTM-AGENT] Started with PID: $PDTM_AGENT_PID" | tee -a "$LOG_FILE"
# cd "$BASE_DIR"

# echo "All dev services have completed. PDTM-Agent is running in background with PID: $PDTM_AGENT_PID"
# echo "See $LOG_FILE for main logs and $BASE_DIR/pdtm-agent.log for agent-specific logs."
# echo "To stop the agent, run: kill $PDTM_AGENT_PID"
