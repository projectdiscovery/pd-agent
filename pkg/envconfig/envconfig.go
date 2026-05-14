// Package envconfig owns every environment variable the agent reads. Each
// name has a Key* constant; accessors re-read on every call so flags can flip
// without a restart. System env vars (PATH, KUBECONFIG, ...) stay at callsites.
package envconfig

import (
	"os"

	envutil "github.com/projectdiscovery/utils/env"
)

// ---------- Identity & auth ----------

const (
	KeyAPIKey    = "PDCP_API_KEY"
	KeyTeamID    = "PDCP_TEAM_ID"
	KeyAPIServer = "PDCP_API_SERVER"
	KeyUpdateURL = "PDCP_UPDATE_URL"

	DefaultAPIServer = "https://api.projectdiscovery.io"
)

// APIKey returns the PDCP API key.
func APIKey() string { return envutil.GetEnvOrDefault(KeyAPIKey, "") }

// TeamID returns the PDCP team identifier.
func TeamID() string { return envutil.GetEnvOrDefault(KeyTeamID, "") }

// APIServer returns the platform API base URL.
func APIServer() string { return envutil.GetEnvOrDefault(KeyAPIServer, DefaultAPIServer) }

// UpdateURL overrides the self-update download URL; empty resolves via GitHub releases.
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

// AgentName returns the agent-name override.
func AgentName() string { return envutil.GetEnvOrDefault(KeyAgentName, "") }

// AgentNetwork returns PDCP_AGENT_NETWORK.
func AgentNetwork() string { return envutil.GetEnvOrDefault(KeyAgentNetwork, "") }

// AgentNetworkLegacy returns the older AGENT_NETWORK alias.
func AgentNetworkLegacy() string { return envutil.GetEnvOrDefault(KeyAgentNetworkAlt, "") }

// AgentNetworkLegacyOrDefault returns AGENT_NETWORK or DefaultAgentNetwork.
func AgentNetworkLegacyOrDefault() string {
	return envutil.GetEnvOrDefault(KeyAgentNetworkAlt, DefaultAgentNetwork)
}

// AgentOutput returns the output-directory override.
func AgentOutput() string { return envutil.GetEnvOrDefault(KeyAgentOutput, "") }

// AgentTags returns the raw comma-separated tag list.
func AgentTags() string { return envutil.GetEnvOrDefault(KeyAgentTags, "") }

// AgentTagsOrDefault returns PDCP_AGENT_TAGS or "default".
func AgentTagsOrDefault() string { return envutil.GetEnvOrDefault(KeyAgentTags, DefaultAgentTags) }

// ---------- Concurrency ----------

const (
	KeyChunkParallelism = "PDCP_CHUNK_PARALLELISM"
	KeyScanParallelism  = "PDCP_SCAN_PARALLELISM"

	DefaultScanParallelism = "1"
)

// ChunkParallelism returns the raw value; empty means auto-detect.
func ChunkParallelism() string { return envutil.GetEnvOrDefault(KeyChunkParallelism, "") }

// ScanParallelism returns PDCP_SCAN_PARALLELISM or "1".
func ScanParallelism() string {
	return envutil.GetEnvOrDefault(KeyScanParallelism, DefaultScanParallelism)
}

// ---------- Local storage (agentdb) ----------

const (
	KeyAgentDBDir         = "PDCP_AGENTDB_DIR"
	KeyAgentDBLogCapMB    = "PDCP_AGENTDB_LOG_CAP_MB"
	KeyAgentDBMetricCapMB = "PDCP_AGENTDB_METRIC_CAP_MB"
)

// AgentDBDir overrides the local observability DB directory.
func AgentDBDir() string { return envutil.GetEnvOrDefault(KeyAgentDBDir, "") }

// AgentDBLogCapMB returns the log ring-buffer cap in MB.
func AgentDBLogCapMB() string { return envutil.GetEnvOrDefault(KeyAgentDBLogCapMB, "") }

// AgentDBMetricCapMB returns the metric ring-buffer cap in MB.
func AgentDBMetricCapMB() string { return envutil.GetEnvOrDefault(KeyAgentDBMetricCapMB, "") }

// ---------- Behavior toggles ----------
//
// Booleans use strconv.ParseBool semantics; unrecognised values use the default.

const (
	KeyVerbose                 = "PDCP_VERBOSE"
	KeyKeepOutputFiles         = "PDCP_KEEP_OUTPUT_FILES"
	KeyLocalK8s                = "LOCAL_K8S"
	KeyDisableDiagnosticUpload = "PDCP_DISABLE_DIAGNOSTIC_UPLOAD"
	KeyEnableScanLogUpload     = "PDCP_ENABLE_SCAN_LOG_UPLOAD"
)

// Verbose returns true when PDCP_VERBOSE is truthy.
func Verbose() bool { return envutil.GetEnvOrDefault(KeyVerbose, false) }

// KeepOutputFiles preserves per-chunk output files after upload.
func KeepOutputFiles() bool { return envutil.GetEnvOrDefault(KeyKeepOutputFiles, false) }

// LocalK8s switches to KUBECONFIG instead of the in-cluster service account.
// Strict "true" match: ParseBool would let LOCAL_K8S=1 flip to a path that
// fails silently when KUBECONFIG is unset.
func LocalK8s() bool { return os.Getenv(KeyLocalK8s) == "true" }

// DisableDiagnosticUpload disables shipping the SQLite DB to GCS at shutdown.
func DisableDiagnosticUpload() bool {
	return envutil.GetEnvOrDefault(KeyDisableDiagnosticUpload, false)
}

// ScanLogUploadEnabled is off by default so agents without scan-log storage
// provisioned don't hammer the API with rejected uploads.
func ScanLogUploadEnabled() bool {
	return envutil.GetEnvOrDefault(KeyEnableScanLogUpload, false)
}

// ---------- Observability ----------

const KeyMetricsAddr = "PDCP_METRICS_ADDR"

// MetricsAddr returns the Prometheus bind address; empty disables the server.
func MetricsAddr() string { return envutil.GetEnvOrDefault(KeyMetricsAddr, "") }

// ---------- Networking ----------

const KeyProxyURL = "PROXY_URL"

// ProxyURL returns the outbound HTTP/S proxy URL.
func ProxyURL() string { return envutil.GetEnvOrDefault(KeyProxyURL, "") }

// ---------- Nuclei ----------

const KeyReportingConfig = "PDCP_REPORTING_CONFIG"

// ReportingConfigPath returns a local nuclei -rc YAML path. When set, it
// overrides the reporting config in the work message, keeping tracker
// credentials off the platform.
func ReportingConfigPath() string { return envutil.GetEnvOrDefault(KeyReportingConfig, "") }
