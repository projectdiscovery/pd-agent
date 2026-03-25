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
	ScanID  string   `json:"scan_id"`
}

// NucleiRetestRequest is the payload for the "nuclei-retest" RPC method.
type NucleiRetestRequest struct {
	Targets     []string `json:"targets"`
	TemplateIDs []string `json:"template_ids"`
	ScanID      string   `json:"scan_id"`
}

// HealthCheckData is returned by the "health-check" broadcast handler.
type HealthCheckData struct {
	AgentID      string `json:"agent_id"`
	AgentName    string `json:"agent_name"`
	Version      string `json:"version"`
	Uptime       string `json:"uptime"`
	TasksRunning int    `json:"tasks_running"`
}
