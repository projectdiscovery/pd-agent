// Package envconfig is the single source of truth for every environment
// variable the agent reads. If you want to know what knobs exist, look here.
// If you want to add a new knob, add it here.
//
// Conventions:
//   - Every env var name lives in a Key* constant. No raw string literals
//     anywhere else in the codebase.
//   - Each accessor is a function (not a package var) so values are re-read
//     on every call. That matches the prior os.Getenv behaviour and lets
//     operators flip flags without restarting (and keeps tests easy).
//   - Defaults live next to their accessor as a Default* constant.
//   - Lookups + type parsing delegate to envutil.GetEnvOrDefault from
//     projectdiscovery/utils. That gives us strconv.ParseBool semantics
//     for boolean flags ("true"/"false"/"1"/"0"/"t"/"f", case-insensitive)
//     instead of hand-rolled string compares.
//
// System env vars the agent also reads but doesn't own (PATH, SHELL,
// KUBECONFIG, SystemRoot, KUBERNETES_SERVICE_HOST) are deliberately
// excluded — they belong to the OS / k8s, not to us.
package envconfig

import envutil "github.com/projectdiscovery/utils/env"

// ---------- Identity & auth ----------

const (
	KeyAPIKey    = "PDCP_API_KEY"
	KeyTeamID    = "PDCP_TEAM_ID"
	KeyAPIServer = "PDCP_API_SERVER"
	KeyUpdateURL = "PDCP_UPDATE_URL"

	DefaultAPIServer = "https://api.projectdiscovery.io"
)

// APIKey returns the PDCP API key. Required for authenticated calls.
func APIKey() string { return envutil.GetEnvOrDefault(KeyAPIKey, "") }

// TeamID returns the PDCP team identifier used for X-Team-Id headers.
func TeamID() string { return envutil.GetEnvOrDefault(KeyTeamID, "") }

// APIServer returns the platform API base URL. Defaults to production.
func APIServer() string { return envutil.GetEnvOrDefault(KeyAPIServer, DefaultAPIServer) }

// UpdateURL overrides the self-update download URL (local/staging testing).
// Empty => resolve from GitHub releases.
func UpdateURL() string { return envutil.GetEnvOrDefault(KeyUpdateURL, "") }

// ---------- Agent identity & topology ----------

const (
	KeyAgentName       = "PDCP_AGENT_NAME"
	KeyAgentNetwork    = "PDCP_AGENT_NETWORK"
	KeyAgentNetworkAlt = "AGENT_NETWORK" // legacy alias; PDCP_AGENT_NETWORK wins
	KeyAgentOutput     = "PDCP_AGENT_OUTPUT"
	KeyAgentTags       = "PDCP_AGENT_TAGS"

	DefaultAgentTags    = "default"
	DefaultAgentNetwork = "default"
)

// AgentName returns the explicit agent name override.
func AgentName() string { return envutil.GetEnvOrDefault(KeyAgentName, "") }

// AgentNetwork returns PDCP_AGENT_NETWORK (no fallback). parseOptions composes
// CLI > PDCP_AGENT_NETWORK > AGENT_NETWORK > default, so callers that want the
// resolved value should use the parsed Options.AgentNetwork instead.
func AgentNetwork() string { return envutil.GetEnvOrDefault(KeyAgentNetwork, "") }

// AgentNetworkLegacy returns AGENT_NETWORK (the older alias).
func AgentNetworkLegacy() string { return envutil.GetEnvOrDefault(KeyAgentNetworkAlt, "") }

// AgentNetworkLegacyOrDefault returns AGENT_NETWORK, falling back to
// DefaultAgentNetwork. Used as the CLI --agent-network flag default to
// preserve legacy behaviour where the env was the implicit default.
func AgentNetworkLegacyOrDefault() string {
	return envutil.GetEnvOrDefault(KeyAgentNetworkAlt, DefaultAgentNetwork)
}

// AgentOutput returns the output directory override.
func AgentOutput() string { return envutil.GetEnvOrDefault(KeyAgentOutput, "") }

// AgentTags returns the raw PDCP_AGENT_TAGS string (comma-separated).
func AgentTags() string { return envutil.GetEnvOrDefault(KeyAgentTags, "") }

// AgentTagsOrDefault returns PDCP_AGENT_TAGS, falling back to "default".
func AgentTagsOrDefault() string { return envutil.GetEnvOrDefault(KeyAgentTags, DefaultAgentTags) }

// ---------- Concurrency ----------

const (
	KeyChunkParallelism = "PDCP_CHUNK_PARALLELISM"
	KeyScanParallelism  = "PDCP_SCAN_PARALLELISM"

	DefaultScanParallelism = "1"
)

// ChunkParallelism returns the raw PDCP_CHUNK_PARALLELISM string. Empty => auto.
// Callers parse the int themselves so an invalid value can be diagnosed in place.
func ChunkParallelism() string { return envutil.GetEnvOrDefault(KeyChunkParallelism, "") }

// ScanParallelism returns PDCP_SCAN_PARALLELISM, defaulting to "1".
func ScanParallelism() string {
	return envutil.GetEnvOrDefault(KeyScanParallelism, DefaultScanParallelism)
}

// ---------- Local storage (agentdb) ----------

const (
	KeyAgentDBDir         = "PDCP_AGENTDB_DIR"
	KeyAgentDBLogCapMB    = "PDCP_AGENTDB_LOG_CAP_MB"
	KeyAgentDBMetricCapMB = "PDCP_AGENTDB_METRIC_CAP_MB"
)

// AgentDBDir overrides the default ~/.pd-agent directory for the local
// observability DB. Empty => use ~/.pd-agent (binary dir as last-resort fallback).
func AgentDBDir() string { return envutil.GetEnvOrDefault(KeyAgentDBDir, "") }

// AgentDBLogCapMB returns the raw cap value (MB) for the log ring buffer.
// pkg/agentdb parses + validates; empty => package default.
func AgentDBLogCapMB() string { return envutil.GetEnvOrDefault(KeyAgentDBLogCapMB, "") }

// AgentDBMetricCapMB returns the raw cap value (MB) for the metric ring buffer.
func AgentDBMetricCapMB() string { return envutil.GetEnvOrDefault(KeyAgentDBMetricCapMB, "") }

// ---------- Behavior toggles ----------
//
// All booleans use envutil.GetEnvOrDefault[bool], which calls strconv.ParseBool.
// Accepted truthy values: "1", "t", "T", "true", "TRUE", "True".
// Falsy: "0", "f", "F", "false", "FALSE", "False". Anything else => default.

const (
	KeyVerbose                 = "PDCP_VERBOSE"
	KeyKeepOutputFiles         = "PDCP_KEEP_OUTPUT_FILES"
	KeyPassiveDiscovery        = "PASSIVE_DISCOVERY"
	KeyLocalK8s                = "LOCAL_K8S"
	KeyDisableDiagnosticUpload = "PDCP_DISABLE_DIAGNOSTIC_UPLOAD"
	KeyEnableScanLogUpload     = "PDCP_ENABLE_SCAN_LOG_UPLOAD"
)

// Verbose returns true when PDCP_VERBOSE is truthy.
func Verbose() bool { return envutil.GetEnvOrDefault(KeyVerbose, false) }

// KeepOutputFiles returns true when PDCP_KEEP_OUTPUT_FILES is truthy.
// When true, runtools won't delete chunk output files after upload.
func KeepOutputFiles() bool { return envutil.GetEnvOrDefault(KeyKeepOutputFiles, false) }

// PassiveDiscovery returns true when PASSIVE_DISCOVERY is truthy.
// Requires libpcap/gopacket at runtime; falls back to warn-and-skip on cgo-free builds.
func PassiveDiscovery() bool { return envutil.GetEnvOrDefault(KeyPassiveDiscovery, false) }

// LocalK8s returns true when LOCAL_K8S is truthy.
// When true, the agent loads kubeconfig from KUBECONFIG instead of in-cluster service account.
func LocalK8s() bool { return envutil.GetEnvOrDefault(KeyLocalK8s, false) }

// DisableDiagnosticUpload returns true when PDCP_DISABLE_DIAGNOSTIC_UPLOAD is truthy.
// Opt-out for shipping the local SQLite DB to GCS during shutdown.
func DisableDiagnosticUpload() bool {
	return envutil.GetEnvOrDefault(KeyDisableDiagnosticUpload, false)
}

// ScanLogUploadEnabled returns true when PDCP_ENABLE_SCAN_LOG_UPLOAD is truthy.
// Default off so agents in envs without scan-log storage don't hammer rejected uploads.
func ScanLogUploadEnabled() bool {
	return envutil.GetEnvOrDefault(KeyEnableScanLogUpload, false)
}

// ---------- Observability ----------

const KeyMetricsAddr = "PDCP_METRICS_ADDR"

// MetricsAddr returns the host:port the Prometheus /metrics + /healthz server
// binds to. Empty => server disabled (opt-in feature).
func MetricsAddr() string { return envutil.GetEnvOrDefault(KeyMetricsAddr, "") }

// ---------- Networking ----------

const KeyProxyURL = "PROXY_URL"

// ProxyURL returns the HTTP/S proxy URL used by the authenticated PDCP client.
func ProxyURL() string { return envutil.GetEnvOrDefault(KeyProxyURL, "") }

// ---------- Nuclei ----------

const KeyReportingConfig = "PDCP_REPORTING_CONFIG"

// ReportingConfigPath returns the path to a local nuclei reporting (-rc) YAML
// on the agent. When set, takes precedence over the work-message ReportConfig
// — lets operators keep Jira/Linear/GitHub creds off the platform entirely.
func ReportingConfigPath() string { return envutil.GetEnvOrDefault(KeyReportingConfig, "") }
