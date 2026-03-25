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
	Targets         []string `json:"targets"`
	TemplateID      string   `json:"template_id"`
	TemplateEncoded string   `json:"template_encoded,omitempty"`
	VulnID          string   `json:"vuln_id,omitempty"`
}


// HealthCheckData is returned by the "health-check" broadcast handler.
type HealthCheckData struct {
	AgentID      string `json:"agent_id"`
	AgentName    string `json:"agent_name"`
	Version      string `json:"version"`
	Uptime       string `json:"uptime"`
	TasksRunning int    `json:"tasks_running"`
}
