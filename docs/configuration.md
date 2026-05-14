# Configuration

`pd-agent` reads configuration from environment variables and CLI flags. **CLI flags win on conflict**, with one exception: env vars override flag defaults at startup (so a `PDCP_VERBOSE=true` in your service unit takes effect without changing `ExecStart`).

## Environment variables

### Required

| Variable | Description |
| --- | --- |
| `PDCP_API_KEY` | API key for the PDCP team. Generate at <https://cloud.projectdiscovery.io>. |
| `PDCP_TEAM_ID` | Team identifier the agent belongs to. |

### Routing & identity

| Variable | Default | Description |
| --- | --- | --- |
| `PDCP_AGENT_NAME` | hostname | Display name in the cloud UI. |
| `PDCP_AGENT_NETWORK` | `default` | Network name the agent lives in. Scans from the cloud are routed to agents by network. |
| `AGENT_NETWORK` | — | Legacy alias for `PDCP_AGENT_NETWORK`. `PDCP_AGENT_NETWORK` wins if both are set. |
| `PDCP_AGENT_OUTPUT` | — (temp dir) | Folder where the agent stashes per-chunk scan output before uploading. Each chunk gets its own subdirectory: `<PDCP_AGENT_OUTPUT>/<chunk-id>/`. Files are deleted after upload unless `PDCP_KEEP_OUTPUT_FILES=true`. If unset, the embedded scanners write to the OS temp directory. |

### Concurrency

| Variable | Default | Description |
| --- | --- | --- |
| `PDCP_CHUNK_PARALLELISM` | auto (≈`NumCPU`) | Number of chunks from a single scan to run in parallel. `0` or unset → auto-detect from CPU. See [docs/adaptive-chunk-parallelism.md](adaptive-chunk-parallelism.md). |
| `PDCP_SCAN_PARALLELISM` | `1` | Number of distinct scans this agent will hold open at once. |

### Local storage

The agent keeps a small rolling log + metrics buffer at `~/.pd-agent/pd-agent-<agent-id>.db`. On graceful shutdown it's uploaded to the platform for postmortem; on crash it stays on disk.

| Variable | Default | Description |
| --- | --- | --- |
| `PDCP_AGENTDB_DIR` | `~/.pd-agent` (falls back to binary dir) | Where the local debug DB lives. |
| `PDCP_AGENTDB_LOG_CAP_MB` | built-in | Cap on the log buffer, in MB. |
| `PDCP_AGENTDB_METRIC_CAP_MB` | built-in | Cap on the metric buffer, in MB. |
| `PDCP_DISABLE_DIAGNOSTIC_UPLOAD` | `false` | If `true`, skip the shutdown upload of the debug DB. Useful for air-gapped runs. |

### Behaviour toggles

| Variable | Default | Description |
| --- | --- | --- |
| `PDCP_VERBOSE` | `false` | Verbose logging. Same as `-verbose`. |
| `PDCP_KEEP_OUTPUT_FILES` | `false` | Keep per-chunk output files after upload (debugging). Same as `-keep-output-files`. |
| `PDCP_ENABLE_SCAN_LOG_UPLOAD` | `false` | Upload the gzipped per-scan log to the platform. Off by default — leave off unless the platform has scan-log storage provisioned for your team. |
| `LOCAL_K8S` | `false` | Use `KUBECONFIG` instead of the in-cluster service account when discovering Kubernetes subnets. Strict `true` match. |

### Networking & API

| Variable | Default | Description |
| --- | --- | --- |
| `PDCP_API_SERVER` | `https://api.projectdiscovery.io` | Override only for dev environments. |
| `PROXY_URL` | — | Outbound HTTP(S) proxy for agent → platform traffic. |

### Observability

| Variable | Default | Description |
| --- | --- | --- |
| `PDCP_METRICS_ADDR` | — | Bind address for the Prometheus endpoint (e.g. `:9090`). Empty disables it. See [docs/scaling.md](scaling.md). |

### Self-update

| Variable | Default | Description |
| --- | --- | --- |
| `PDCP_UPDATE_URL` | — | Override the download URL for self-update. Empty → resolves via GitHub releases. |

### Nuclei integration

| Variable | Default | Description |
| --- | --- | --- |
| `PDCP_REPORTING_CONFIG` | — | Path to a local nuclei reporting config (`-rc` YAML). Use this when you want Jira / Linear / GitHub tracker credentials to stay on the agent host instead of being configured in the cloud. Overrides whatever reporting config the scan would otherwise use. |

---

## CLI flags

Every flag has an equivalent env var. Use whichever fits your deployment style — flags are fine for one-off runs, env vars are friendlier for service units and container images.

| Flag | Short | Env equivalent | Description |
| --- | --- | --- | --- |
| `-verbose` | | `PDCP_VERBOSE` | Verbose logging. |
| `-keep-output-files` | | `PDCP_KEEP_OUTPUT_FILES` | Keep output files after processing. |
| `-agent-output` | | `PDCP_AGENT_OUTPUT` | Output folder for per-chunk scan files. |
| `-agent-network` | `-an` | `PDCP_AGENT_NETWORK` | Network the agent belongs to. Scans are routed by this name. |
| `-agent-name` | | `PDCP_AGENT_NAME` | Display name. |
| `-agent-id` | | — | Pin the agent ID (auto-generated and persisted across self-updates if empty). |
| `-chunk-parallelism` | `-c` | `PDCP_CHUNK_PARALLELISM` | Chunks per scan in parallel. |
| `-scan-parallelism` | `-s` | `PDCP_SCAN_PARALLELISM` | Scans in parallel. |
| `-version` | | — | Print version and exit. |

Run `pd-agent -h` for the live list.

---

## Precedence

For each setting the value used at startup is, in order:

1. CLI flag, if explicitly provided.
2. Matching env var, if set.
3. Compiled-in default.

After registration, the **platform can override** `network` and `name` if they're configured for that agent ID in the cloud UI. The agent logs the override and uses the server values for that session.
