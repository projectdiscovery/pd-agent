package natsrpc

import "encoding/json"

// Response is the standard JSON envelope sent back over NATS reply subjects.
// Data uses encoding/json.RawMessage for compatibility across packages.
type Response struct {
	Status string          `json:"status"`         // "ok" or "error"
	Data   json.RawMessage `json:"data,omitempty"` // handler-specific payload
	Error  string          `json:"error,omitempty"`
}

// HTTPXRequest is the payload for the "httpx" RPC method.
type HTTPXRequest struct {
	Target string `json:"target"`
}

// NucleiRetestRequest is the payload for the "nuclei-retest" RPC method.
// Template resolution priority: template_encoded > template_url > template_id.
type NucleiRetestRequest struct {
	Targets         []string `json:"targets"`
	TemplateID      string   `json:"template_id"`
	TemplateEncoded string   `json:"template_encoded,omitempty"`
	TemplateURL     string   `json:"template_url,omitempty"`
	VulnID          string   `json:"vuln_id,omitempty"`
}

// PortProbeRequest is the payload for the "port-probe" RPC method.
type PortProbeRequest struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// HealthCheckData is returned by the "health-check" broadcast handler.
type HealthCheckData struct {
	AgentID      string `json:"agent_id"`
	AgentName    string `json:"agent_name"`
	Version      string `json:"version"`
	Uptime       string `json:"uptime"`
	TasksRunning int    `json:"tasks_running"`
	Idle         bool   `json:"idle"`                 // true if idle > 1 min
	IdleSince    string `json:"idle_since,omitempty"` // RFC3339 timestamp if idle > 1 min
}

// LogsRequest is the payload for the "logs" RPC method.
type LogsRequest struct {
	Offset int    `json:"offset"`          // 0 = oldest available entry
	Limit  int    `json:"limit"`           // max entries to return (default 100, max 500)
	Since  string `json:"since,omitempty"` // RFC3339 UTC
	Until  string `json:"until,omitempty"` // RFC3339 UTC
}

// LogsResponse is returned by the "logs" direct handler.
type LogsResponse struct {
	Lines  []string `json:"lines"`
	Total  int      `json:"total"`
	Offset int      `json:"offset"`
	Limit  int      `json:"limit"`
}

// MetricsRequest is the payload for the "metrics" RPC method.
type MetricsRequest struct {
	Range string `json:"range"`           // "5m","15m","30m","1h","3h","6h","24h","custom"
	Start string `json:"start,omitempty"` // RFC3339 UTC, required when range="custom"
	End   string `json:"end,omitempty"`   // RFC3339 UTC, required when range="custom"
}

// MetricsResponse is returned by the "metrics" direct handler.
type MetricsResponse struct {
	Range        string        `json:"range"`
	Since        string        `json:"since"`         // actual start (RFC3339 UTC)
	Until        string        `json:"until"`         // actual end (RFC3339 UTC)
	TotalSamples int           `json:"total_samples"` // raw count in DB for this range
	Returned     int           `json:"returned"`      // points returned after downsampling
	Points       []MetricPoint `json:"points"`
}

// MetricPoint is a single data point for time-series graphing.
type MetricPoint struct {
	T             string  `json:"t"`   // RFC3339 UTC
	CPU           float64 `json:"cpu"` // cpu_percent
	RSSMB         uint64  `json:"rss_mb"`
	HeapMB        uint64  `json:"heap_mb"` // heap_alloc_mb
	FDUsed        int     `json:"fd_used"`
	FDLimit       int     `json:"fd_limit"`
	MemTotalMB    uint64  `json:"mem_total_mb"`
	MemAvailMB    uint64  `json:"mem_avail_mb"`
	Goroutines    int     `json:"goroutines"`
	ActiveWorkers int32   `json:"active_workers"` // chunks currently being processed
	Capacity      int     `json:"capacity"`       // max concurrent chunks (parallelism)
}

// DebugData is returned by the "debug" direct handler.
type DebugData struct {
	Agent   AgentInfo   `json:"agent"`
	System  SystemInfo  `json:"system"`
	Process ProcessInfo `json:"process"`
	Runtime RuntimeInfo `json:"runtime"`
}

// AgentInfo contains agent identity and status.
type AgentInfo struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	Version       string  `json:"version"`
	Uptime        string  `json:"uptime"`
	UptimeSeconds float64 `json:"uptime_seconds"`
	TasksRunning  int     `json:"tasks_running"`
}

// SystemInfo contains host-level resource info.
type SystemInfo struct {
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	NumCPU   int    `json:"num_cpu"`
	Hostname string `json:"hostname"`
}

// ProcessInfo contains pd-agent process resource usage.
// Uses runtime.MemStats (cross-platform) instead of syscall.Rusage.
type ProcessInfo struct {
	PID        int     `json:"pid"`
	MemAllocMB float64 `json:"mem_alloc_mb"` // runtime.MemStats.Sys — total memory from OS
}

// RuntimeInfo contains Go runtime metrics.
type RuntimeInfo struct {
	GoVersion    string  `json:"go_version"`
	NumGoroutine int     `json:"num_goroutine"`
	HeapAllocMB  float64 `json:"heap_alloc_mb"`
	HeapInuseMB  float64 `json:"heap_inuse_mb"`
	StackInuseMB float64 `json:"stack_inuse_mb"`
	TotalAllocMB float64 `json:"total_alloc_mb"`
	NumGC        uint32  `json:"num_gc"`
	LastGC       string  `json:"last_gc,omitempty"`
}

// --- JetStream Work Distribution Types ---

// WorkMessage is published by the server to the group stream to notify agents
// about a new scan or enumeration to process. All messages (work notifications,
// chunks, etc.) live in a single group-level stream; consumers use FilterSubject
// to scope what they read.
type WorkMessage struct {
	Type          string   `json:"type"`                  // "scan" or "enumeration"
	ScanID        string   `json:"scan_id"`               // scan_id or enumeration_id
	ChunkSubject  string   `json:"chunk_subject"`         // subject filter for chunks (e.g., "ws-123.scanners.scan-1.chunks")
	ChunkConsumer string   `json:"chunk_consumer"`        // shared consumer name (typically agent-network)
	ChunkCount    int      `json:"chunk_count,omitempty"` // number of chunks in the stream
	Config        string   `json:"config,omitempty"`      // base64 scan configuration
	Templates     []string `json:"templates,omitempty"`   // nuclei template paths (scans)
	Steps         []string `json:"steps,omitempty"`       // enumeration steps (enumerations)
	Assets        []string `json:"assets,omitempty"`      // all targets (for pre-scan port filtering)
}

// ChunkMessage is a single unit of work decoded from the group stream.
// For scan chunks: ZSTD-compressed protobuf (ScanRequest).
// For enumeration chunks: plain protobuf (AssetEnrichmentRequest).
type ChunkMessage struct {
	ChunkID          string   `json:"chunk_id"`
	Targets          []string `json:"targets"`
	PublicTemplates  []string `json:"public_templates,omitempty"`
	PrivateTemplates []string `json:"private_templates,omitempty"`
	ScanConfig       string   `json:"scan_configuration,omitempty"`

	// Enrichment-specific fields (populated for enumeration chunks)
	EnrichmentID   string `json:"enrichment_id,omitempty"`
	EnrichmentType string `json:"enrichment_type,omitempty"`
	EnumConfig     string `json:"enumeration_configuration,omitempty"`
}
