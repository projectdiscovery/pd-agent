#!/bin/bash
set -e

BASE_DIR="$HOME/GitHubTest"
LOG_FILE="$BASE_DIR/dev-setup.log"
ENV_FILE="$BASE_DIR/.env.local"

# Create BASE_DIR if it doesn't exist
mkdir -p "$BASE_DIR"
touch "$LOG_FILE"

# Helper to prompt for env vars if not already set
get_env() {
  local varname="$1"
  local prompt="$2"
  if [ -z "${!varname}" ]; then
    read -rp "Enter value for $varname ($prompt): " value
    export $varname="$value"
    echo "export $varname=\"$value\"" >> "$ENV_FILE"
  fi
}

# Load previous env vars if any
if [ -f "$ENV_FILE" ]; then
  set -o allexport
  source "$ENV_FILE"
  set +o allexport
fi

get_env "GITHUB_TOKEN" "GitHub personal access token"
export PDCP_DEV_API_KEY="47fd9e1c-542f-4ef8-86df-ffdc815dfd2e"

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
echo "[AURORA] Running dev..." | tee -a "$LOG_FILE"
GITHUB_TOKEN="$GITHUB_TOKEN" go run . -test-type scan -skip-run 2>&1 | tee -a "$LOG_FILE"
cd "$BASE_DIR"

# 2. Scan-Scheduler
if [ ! -d scan-scheduler ]; then
  git clone https://github.com/projectdiscovery/scan-scheduler.git | tee -a "$LOG_FILE"
fi
cd scan-scheduler
git fetch origin | tee -a "$LOG_FILE"
gh pr checkout 86 | tee -a "$LOG_FILE"
git pull | tee -a "$LOG_FILE"
cd cmd/dev
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
echo "[PLATFORM BACKEND] Running dev..." | tee -a "$LOG_FILE"
GITHUB_TOKEN="$GITHUB_TOKEN" go run . 2>&1 | tee -a "$LOG_FILE"
cd "$BASE_DIR"

# 4. PDTM-AGENT
if [ ! -d pdtm-agent ]; then
  git clone https://github.com/projectdiscovery/pdtm-agent.git | tee -a "$LOG_FILE"
fi
cd pdtm-agent
git fetch origin | tee -a "$LOG_FILE"
gh pr checkout 1 | tee -a "$LOG_FILE"
git pull | tee -a "$LOG_FILE"
cd cmd/pdtm-agent
echo "[PDTM-AGENT] Running agent in background..." | tee -a "$LOG_FILE"
PDCP_API_KEY="$PDCP_DEV_API_KEY" PDCP_API_SERVER="http://localhost:8088" PUNCH_HOLE_HOST="127.0.0.1" PUNCH_HOLE_HTTP_PORT="8880" \
  nohup go run . -agent -agent-output test -verbose -agent-tags test-group > "$BASE_DIR/pdtm-agent.log" 2>&1 &
PDTM_AGENT_PID=$!
echo "[PDTM-AGENT] Started with PID: $PDTM_AGENT_PID" | tee -a "$LOG_FILE"
cd "$BASE_DIR"

echo "All dev services have completed. PDTM-Agent is running in background with PID: $PDTM_AGENT_PID"
echo "See $LOG_FILE for main logs and $BASE_DIR/pdtm-agent.log for agent-specific logs."
echo "To stop the agent, run: kill $PDTM_AGENT_PID"
