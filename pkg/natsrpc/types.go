package natsrpc

import "encoding/json"

// Response is the standard JSON envelope sent back over NATS reply subjects.
type Response struct {
	Status string          `json:"status"`         // "ok" or "error"
	Data   json.RawMessage `json:"data,omitempty"` // handler-specific payload
	Error  string          `json:"error,omitempty"`
}

// HTTPXRequest is the payload for the "httpx" RPC method.
type HTTPXRequest struct {
	Targets []string `json:"targets"`
	Flags   []string `json:"flags,omitempty"`
}

// NucleiRetestRequest is the payload for the "nuclei-retest" RPC method.
type NucleiRetestRequest struct {
	Targets         []string `json:"targets"`
	TemplateID      string   `json:"template_id"`
	TemplateEncoded string   `json:"template_encoded,omitempty"`
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
	ID           string `json:"id"`
	Name         string `json:"name"`
	Version      string `json:"version"`
	Uptime       string `json:"uptime"`
	UptimeSeconds float64 `json:"uptime_seconds"`
	TasksRunning int    `json:"tasks_running"`
}

// SystemInfo contains host-level resource info.
type SystemInfo struct {
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	NumCPU   int    `json:"num_cpu"`
	Hostname string `json:"hostname"`
}

// ProcessInfo contains pd-agent process resource usage.
type ProcessInfo struct {
	PID          int     `json:"pid"`
	MemoryRSSMB  float64 `json:"memory_rss_mb"`
	UserTimeSec  float64 `json:"user_time_sec"`
	SysTimeSec   float64 `json:"sys_time_sec"`
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
