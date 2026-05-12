// Package envconfig is the single source of truth for environment variables
// the agent reads. Every name lives in a Key* constant; accessors re-read on
// every call so operators can flip flags without restarting.
//
// System env vars the agent reads but does not own (PATH, SHELL, KUBECONFIG,
// SystemRoot, KUBERNETES_SERVICE_HOST) live at their callsites, not here.
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

// APIKey returns the PDCP API key.
func APIKey() string { return envutil.GetEnvOrDefault(KeyAPIKey, "") }

// TeamID returns the PDCP team identifier.
func TeamID() string { return envutil.GetEnvOrDefault(KeyTeamID, "") }

// APIServer returns the platform API base URL.
func APIServer() string { return envutil.GetEnvOrDefault(KeyAPIServer, DefaultAPIServer) }

// UpdateURL overrides the self-update download URL. Empty resolves from GitHub releases.
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

// AgentNetwork returns PDCP_AGENT_NETWORK without fallback.
func AgentNetwork() string { return envutil.GetEnvOrDefault(KeyAgentNetwork, "") }

// AgentNetworkLegacy returns AGENT_NETWORK, the older alias.
func AgentNetworkLegacy() string { return envutil.GetEnvOrDefault(KeyAgentNetworkAlt, "") }

// AgentNetworkLegacyOrDefault returns AGENT_NETWORK, falling back to DefaultAgentNetwork.
func AgentNetworkLegacyOrDefault() string {
	return envutil.GetEnvOrDefault(KeyAgentNetworkAlt, DefaultAgentNetwork)
}

// AgentOutput returns the output directory override.
func AgentOutput() string { return envutil.GetEnvOrDefault(KeyAgentOutput, "") }

// AgentTags returns the raw comma-separated tag list.
func AgentTags() string { return envutil.GetEnvOrDefault(KeyAgentTags, "") }

// AgentTagsOrDefault returns PDCP_AGENT_TAGS, falling back to "default".
func AgentTagsOrDefault() string { return envutil.GetEnvOrDefault(KeyAgentTags, DefaultAgentTags) }

// ---------- Concurrency ----------

const (
	KeyChunkParallelism = "PDCP_CHUNK_PARALLELISM"
	KeyScanParallelism  = "PDCP_SCAN_PARALLELISM"

	DefaultScanParallelism = "1"
)

// ChunkParallelism returns the raw value. Empty means auto-detect.
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

// AgentDBDir overrides the local observability DB directory.
func AgentDBDir() string { return envutil.GetEnvOrDefault(KeyAgentDBDir, "") }

// AgentDBLogCapMB returns the raw log ring-buffer cap (MB).
func AgentDBLogCapMB() string { return envutil.GetEnvOrDefault(KeyAgentDBLogCapMB, "") }

// AgentDBMetricCapMB returns the raw metric ring-buffer cap (MB).
func AgentDBMetricCapMB() string { return envutil.GetEnvOrDefault(KeyAgentDBMetricCapMB, "") }

// ---------- Behavior toggles ----------
//
// Booleans use strconv.ParseBool: 1/t/T/true/TRUE/True are truthy, the
// corresponding false forms are falsy, anything else falls back to default.

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

// KeepOutputFiles preserves per-chunk output files after upload.
func KeepOutputFiles() bool { return envutil.GetEnvOrDefault(KeyKeepOutputFiles, false) }

// PassiveDiscovery enables libpcap/gopacket-backed discovery. Warns and skips
// at runtime when libpcap is missing on cgo-free builds.
func PassiveDiscovery() bool { return envutil.GetEnvOrDefault(KeyPassiveDiscovery, false) }

// LocalK8s loads kubeconfig from KUBECONFIG instead of the in-cluster service account.
func LocalK8s() bool { return envutil.GetEnvOrDefault(KeyLocalK8s, false) }

// DisableDiagnosticUpload opts out of shipping the local SQLite DB to GCS at shutdown.
func DisableDiagnosticUpload() bool {
	return envutil.GetEnvOrDefault(KeyDisableDiagnosticUpload, false)
}

// ScanLogUploadEnabled is opt-in. Default off so agents in environments
// without scan-log storage provisioned don't hammer the API with rejected uploads.
func ScanLogUploadEnabled() bool {
	return envutil.GetEnvOrDefault(KeyEnableScanLogUpload, false)
}

// ---------- Observability ----------

const KeyMetricsAddr = "PDCP_METRICS_ADDR"

// MetricsAddr returns the Prometheus bind address. Empty disables the server.
func MetricsAddr() string { return envutil.GetEnvOrDefault(KeyMetricsAddr, "") }

// ---------- Networking ----------

const KeyProxyURL = "PROXY_URL"

// ProxyURL returns the outbound HTTP/S proxy URL.
func ProxyURL() string { return envutil.GetEnvOrDefault(KeyProxyURL, "") }

// ---------- Nuclei ----------

const KeyReportingConfig = "PDCP_REPORTING_CONFIG"

// ReportingConfigPath returns a local path to a nuclei -rc YAML. When set,
// it overrides any reporting config carried in the work message, letting
// operators keep tracker credentials off the platform.
func ReportingConfigPath() string { return envutil.GetEnvOrDefault(KeyReportingConfig, "") }
