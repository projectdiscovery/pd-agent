// Package agentdb persists agent info, structured logs, and resource metrics
// in a local SQLite database so they survive restarts and can be uploaded
// for offline investigation.
package agentdb

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/pd-agent/pkg/envconfig"
)

// Store persists local agent observability data. Implementations must be
// safe for concurrent use.
type Store interface {
	// UpsertAgentInfo inserts or replaces the single agent_info row.
	UpsertAgentInfo(ctx context.Context, info *AgentInfo) error

	// GetAgentInfo returns the current agent info, or nil if not yet stored.
	GetAgentInfo(ctx context.Context) (*AgentInfo, error)

	// InsertLog appends a structured log entry.
	InsertLog(ctx context.Context, entry *LogEntry) error

	// InsertMetric appends a resource metrics sample.
	InsertMetric(ctx context.Context, sample *MetricSample) error

	// QueryLogs returns log entries matching the filter, ordered oldest-first.
	QueryLogs(ctx context.Context, filter LogFilter) ([]LogEntry, error)

	// QueryMetrics returns metric samples within the time range, ordered oldest-first.
	QueryMetrics(ctx context.Context, since, until time.Time, limit int) ([]MetricSample, error)

	// InsertTask records a new scan/enumeration task as running.
	InsertTask(ctx context.Context, task *Task) error

	// FinishTask updates a task's status and sets finished_at.
	FinishTask(ctx context.Context, taskID, status string) error

	// ActiveTasks returns tasks with status "running", newest first.
	ActiveTasks(ctx context.Context) ([]Task, error)

	// RecentTasks returns the most recent tasks (any status), newest first.
	RecentTasks(ctx context.Context, limit int) ([]Task, error)

	// DBSizeBytes returns the database file size in bytes.
	DBSizeBytes() (int64, error)

	// Close closes the database connection.
	Close() error
}

// AgentInfo holds agent identity and system information.
type AgentInfo struct {
	AgentID      string
	AgentName    string
	AgentNetwork string
	Version      string
	OS           string
	Arch         string
	NumCPU       int
	Hostname     string
	PID          int
	NetworkInfo  NetInfo
	StartupArgs  string // masked os.Args as JSON array
	StartupEnv   string // masked key env vars as JSON object
	StartedAt    time.Time
	UpdatedAt    time.Time
}

// NetInfo holds local network detection results.
type NetInfo struct {
	Interfaces   []InterfaceInfo `json:"interfaces"`
	Gateway      string          `json:"gateway"`
	DNSResolvers []string        `json:"dns_resolvers"`
	PublicIPs    []string        `json:"public_ips"`
	PrivateIPs   []string        `json:"private_ips"`
	NetworkType  string          `json:"network_type"` // "direct_public", "nat_likely", "no_external"
}

// InterfaceInfo describes a single network interface.
type InterfaceInfo struct {
	Name  string   `json:"name"`
	Addrs []string `json:"addrs"` // CIDR notation
}

// LogEntry is a single structured log record.
type LogEntry struct {
	ID        int64
	Timestamp time.Time
	Line      string // full slog-formatted line
}

// LogFilter controls which log entries are returned by QueryLogs.
type LogFilter struct {
	Since  time.Time // zero = no lower bound
	Until  time.Time // zero = no upper bound
	Offset int
	Limit  int // 0 = default 500
}

// MetricSample is a single point-in-time resource measurement.
type MetricSample struct {
	ID               int64
	Timestamp        time.Time
	CPUPercent       float64
	RSSMB            uint64
	HeapAllocMB      uint64
	HeapSysMB        uint64
	FDUsed           int
	FDLimit          int
	MemTotalMB       uint64
	MemAvailMB       uint64
	Goroutines       int
	ActiveWorkers    int32
	ChunkParallelism int
}

// Task tracks a scan or enumeration the agent is working on.
type Task struct {
	ID         int64
	Type       string // "scan" or "enumeration"
	TaskID     string // scan_id or enumeration_id
	Status     string // "running", "completed", "failed"
	StartedAt  time.Time
	FinishedAt time.Time // zero if still running
}

// RFC6598 CGNAT range; net.IP.IsPrivate does not cover it.
var _, cgnatRange, _ = net.ParseCIDR("100.64.0.0/10")

// classifyIP returns true for private/reserved addresses (RFC1918, RFC6598,
// link-local, loopback, IPv6 ULA).
func classifyIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || cgnatRange.Contains(ip)
}

// SizeCaps holds the byte-based size limits for logs and metrics tables.
type SizeCaps struct {
	LogCapBytes    int64
	MetricCapBytes int64
}

const (
	defaultLogCapMB    = 10
	defaultMetricCapMB = 18
)

// LoadSizeCaps reads PDCP_AGENTDB_LOG_CAP_MB and PDCP_AGENTDB_METRIC_CAP_MB,
// defaulting to 10MB logs and 18MB metrics. Returns an error only if a value
// is set but not a positive integer.
func LoadSizeCaps() (SizeCaps, error) {
	caps := SizeCaps{
		LogCapBytes:    defaultLogCapMB * 1024 * 1024,
		MetricCapBytes: defaultMetricCapMB * 1024 * 1024,
	}

	if v := envconfig.AgentDBLogCapMB(); v != "" {
		mb, err := strconv.Atoi(v)
		if err != nil || mb <= 0 {
			return caps, fmt.Errorf("invalid %s=%q: must be a positive integer", envconfig.KeyAgentDBLogCapMB, v)
		}
		caps.LogCapBytes = int64(mb) * 1024 * 1024
	}

	if v := envconfig.AgentDBMetricCapMB(); v != "" {
		mb, err := strconv.Atoi(v)
		if err != nil || mb <= 0 {
			return caps, fmt.Errorf("invalid %s=%q: must be a positive integer", envconfig.KeyAgentDBMetricCapMB, v)
		}
		caps.MetricCapBytes = int64(mb) * 1024 * 1024
	}

	return caps, nil
}

// sensitiveKeys trigger value masking in args and env vars.
var sensitiveKeys = []string{"key", "secret", "password", "token", "cred", "auth"}

func isSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	for _, s := range sensitiveKeys {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

// MaskArgs returns os.Args as a JSON array with sensitive flag values masked.
func MaskArgs(args []string) string {
	masked := make([]string, len(args))
	skipNext := false
	for i, arg := range args {
		if skipNext {
			masked[i] = "***"
			skipNext = false
			continue
		}
		if strings.HasPrefix(arg, "-") && strings.Contains(arg, "=") {
			parts := strings.SplitN(arg, "=", 2)
			if isSensitiveKey(parts[0]) {
				masked[i] = parts[0] + "=***"
				continue
			}
		}
		if strings.HasPrefix(arg, "-") && isSensitiveKey(arg) {
			masked[i] = arg
			skipNext = true
			continue
		}
		masked[i] = arg
	}
	b, _ := json.Marshal(masked)
	return string(b)
}

// MaskEnv returns PDCP_* and AGENT_* env vars as a JSON object with sensitive values masked.
func MaskEnv() string {
	result := make(map[string]string)
	for _, kv := range os.Environ() {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := parts[0]
		if !strings.HasPrefix(key, "PDCP_") && !strings.HasPrefix(key, "AGENT_") {
			continue
		}
		if isSensitiveKey(key) {
			result[key] = "***"
		} else {
			result[key] = parts[1]
		}
	}
	b, _ := json.Marshal(result)
	return string(b)
}

func deriveNetworkType(publicIPs []string, gateway string) string {
	if len(publicIPs) > 0 {
		return "direct_public"
	}
	if gateway != "" {
		return "nat_likely"
	}
	return "no_external"
}
