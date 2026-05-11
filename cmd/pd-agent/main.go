package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	json "github.com/json-iterator/go"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"go.uber.org/automaxprocs/maxprocs"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	httpxrunner "github.com/projectdiscovery/httpx/runner"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/pd-agent/pkg"
	"github.com/projectdiscovery/pd-agent/pkg/agentdb"
	"github.com/projectdiscovery/pd-agent/pkg/client"
	"github.com/projectdiscovery/pd-agent/pkg/natsrpc"
	"github.com/projectdiscovery/pd-agent/pkg/prereq"
	"github.com/projectdiscovery/pd-agent/pkg/resourceprofile"
	"github.com/projectdiscovery/pd-agent/pkg/runtools"
	"github.com/projectdiscovery/pd-agent/pkg/scanlog"
	"github.com/projectdiscovery/pd-agent/pkg/selfupdate"
	"github.com/projectdiscovery/pd-agent/pkg/types"
	"github.com/projectdiscovery/utils/batcher"
	envutil "github.com/projectdiscovery/utils/env"
	fileutil "github.com/projectdiscovery/utils/file"
	sliceutil "github.com/projectdiscovery/utils/slice"
	"github.com/rs/xid"
	"github.com/tidwall/gjson"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// ensureNucleiTemplates downloads nuclei templates if missing, or updates them
// if the directory already exists. Stale templates cause "file not found" errors
// when the cloud sends template paths that don't exist locally. Uses the
// embedded nuclei TemplateManager SDK — no shell-out.
func ensureNucleiTemplates() {
	templateDir := pkg.GetNucleiDefaultTemplateDir()
	if templateDir == "" {
		slog.Warn("Could not determine nuclei template directory, skipping template download")
		return
	}

	if info, err := os.Stat(templateDir); err == nil && info.IsDir() {
		slog.Info("Nuclei templates directory exists, checking for updates...", "path", templateDir)
	} else {
		slog.Info("Nuclei templates not found, downloading...", "path", templateDir)
	}

	if err := runtools.UpdateNucleiTemplates(); err != nil {
		slog.Error("Failed to update nuclei templates", "error", err)
		return
	}
	slog.Info("Nuclei templates are up to date", "path", templateDir)
}

// Version is set at build time via -ldflags "-X main.Version=v1.0.0"
var Version = "dev"

var (
	PDCPApiKey          = envutil.GetEnvOrDefault("PDCP_API_KEY", "")
	TeamIDEnv           = envutil.GetEnvOrDefault("PDCP_TEAM_ID", "")
	AgentTagsEnv        = envutil.GetEnvOrDefault("PDCP_AGENT_TAGS", "default")
	PdcpApiServer       = envutil.GetEnvOrDefault("PDCP_API_SERVER", "https://api.projectdiscovery.io")
	ChunkParallelismEnv = envutil.GetEnvOrDefault("PDCP_CHUNK_PARALLELISM", "")
	ScanParallelismEnv  = envutil.GetEnvOrDefault("PDCP_SCAN_PARALLELISM", "1")
	AgentNetworkEnv     = envutil.GetEnvOrDefault("AGENT_NETWORK", "default")
)

// Options contains the configuration options for the agent
type Options struct {
	TeamID           string
	AgentId          string
	AgentTags        goflags.StringSlice
	AgentNetwork     string
	AgentOutput      string
	AgentName        string
	Verbose          bool
	PassiveDiscovery bool // Enable passive discovery
	ChunkParallelism int  // Number of chunks to process in parallel
	ScanParallelism  int  // Number of scans to process in parallel
	KeepOutputFiles  bool // If true, don't delete output files after processing
}

// Response represents a simplified HTTP response
type Response struct {
	StatusCode int
	Body       []byte
	Error      error
}

// makeRequest performs an HTTP request and returns a simplified response
// It includes retry logic that retries up to 5 times on errors with minimal sleep time between retries
func (r *Runner) makeRequest(ctx context.Context, method, url string, body io.Reader, headers map[string]string) *Response {
	// Read body into bytes if provided, so we can reuse it for retries
	var bodyBytes []byte
	var err error
	if body != nil {
		bodyBytes, err = io.ReadAll(body)
		if err != nil {
			return &Response{
				StatusCode: 0,
				Body:       nil,
				Error:      fmt.Errorf("error reading request body: %v", err),
			}
		}
	}

	maxRetries := 5

	for attempt := 1; attempt <= maxRetries; attempt++ {
		client, err := client.CreateAuthenticatedClient(r.options.TeamID, PDCPApiKey)
		if err != nil {
			if attempt < maxRetries {
				r.logHelper("WARNING", fmt.Sprintf("error creating authenticated client (attempt %d/%d): %v, retrying...", attempt, maxRetries, err))
				time.Sleep(200 * time.Millisecond)
				continue
			}
			return &Response{
				StatusCode: 0,
				Body:       nil,
				Error:      fmt.Errorf("error creating authenticated client after %d attempts: %v", maxRetries, err),
			}
		}

		var bodyReader io.Reader
		if bodyBytes != nil {
			bodyReader = bytes.NewReader(bodyBytes)
		}

		req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
		if err != nil {
			if attempt < maxRetries {
				r.logHelper("WARNING", fmt.Sprintf("error creating request (attempt %d/%d): %v, retrying...", attempt, maxRetries, err))
				time.Sleep(200 * time.Millisecond)
				continue
			}
			return &Response{
				StatusCode: 0,
				Body:       nil,
				Error:      fmt.Errorf("error creating request after %d attempts: %v", maxRetries, err),
			}
		}

		// Add custom headers if provided
		for key, value := range headers {
			req.Header.Set(key, value)
		}

		resp, err := client.Do(req)
		if err != nil {
			if attempt < maxRetries {
				r.logHelper("WARNING", fmt.Sprintf("error sending request (attempt %d/%d): %v, retrying...", attempt, maxRetries, err))
				time.Sleep(200 * time.Millisecond)
				continue
			}
			return &Response{
				StatusCode: 0,
				Body:       nil,
				Error:      fmt.Errorf("error sending request after %d attempts: %v", maxRetries, err),
			}
		}

		respBodyBytes, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			if attempt < maxRetries {
				r.logHelper("WARNING", fmt.Sprintf("error reading response (attempt %d/%d): %v, retrying...", attempt, maxRetries, err))
				time.Sleep(200 * time.Millisecond)
				continue
			}
			return &Response{
				StatusCode: resp.StatusCode,
				Body:       nil,
				Error:      fmt.Errorf("error reading response after %d attempts: %v", maxRetries, err),
			}
		}

		// Success - return the response
		return &Response{
			StatusCode: resp.StatusCode,
			Body:       respBodyBytes,
			Error:      nil,
		}
	}

	// This should never be reached
	return &Response{
		StatusCode: 0,
		Body:       nil,
		Error:      fmt.Errorf("request failed after %d attempts", maxRetries),
	}
}

// NATSCredentials contains connection metadata returned by the /in endpoint
type NATSCredentials struct {
	Credentials string `json:"credentials"`
	NatsURL     string `json:"nats_url"`
	Stream      string `json:"stream"`
	GroupPrefix string `json:"group_prefix"`
	Subjects    struct {
		Broadcast string `json:"broadcast"`
		Requests  string `json:"requests"`
	} `json:"subjects"`
	InboxPrefix          string    `json:"inbox_prefix"`
	ExpiresAt            time.Time `json:"expires_at"`
	DebugUploadURL       string    `json:"debug_upload_url,omitempty"`
	DebugUploadExpiresAt time.Time `json:"debug_upload_expires_at,omitzero"`
}

// AgentInResponse represents the response from POST /v1/agents/in
type AgentInResponse struct {
	Message string           `json:"message"`
	Nats    *NATSCredentials `json:"nats,omitempty"`
}

// Runner contains the internal logic of the agent
type Runner struct {
	options        *Options
	inRequestCount int       // Number of /in requests sent
	agentStartTime time.Time // When the agent started

	natsCreds   *NATSCredentials
	natsCredsMu sync.RWMutex

	// Lifecycle context — cancelled on agent shutdown
	ctx       context.Context
	cancelCtx context.CancelFunc

	// NATS RPC connection and subscriptions
	natsConn    *nats.Conn
	natsSubs    []*nats.Subscription
	natsConnMu  sync.Mutex
	natsStarted bool // true after first successful NATS connect

	// JetStream work distribution
	jsPool   atomic.Pointer[natsrpc.WorkerPool]
	jsCancel atomic.Pointer[context.CancelFunc]

	// Chunk parallelism semaphores. scanSem is fixed at NumCPU because nuclei
	// is heavy and warms up slowly — letting the adaptive scaler ramp it up
	// before nuclei reaches steady-state CPU/mem causes oversubscription.
	// chunkSem (enumeration) keeps the adaptive scaler since discovery work
	// is short and resource-light.
	scanSem     atomic.Pointer[resourceprofile.ResizableSemaphore]
	chunkSem    atomic.Pointer[resourceprofile.ResizableSemaphore]
	chunkScaler atomic.Pointer[resourceprofile.Scaler]

	// Group-level chunk backlog metrics (for autoscaling). Set when JetStream
	// workers come up; cleared on resetForRestart.
	groupMetrics atomic.Pointer[natsrpc.GroupMetricsCollector]

	// Short cache for ActiveTasks to absorb bursty health-check/debug calls.
	activeTasksCache atomic.Pointer[activeTasksCacheEntry]

	// Local observability database (nil if open failed)
	agentDB agentdb.Store

	restartRequested atomic.Bool
}

var (
	// K8s subnets cache
	k8sSubnetsCache     []string
	k8sSubnetsCacheOnce sync.Once
)

type activeTasksCacheEntry struct {
	tasks     []agentdb.Task
	expiresAt time.Time
}

// getActiveTasksCached returns the active tasks list, caching for 2s so that
// bursty health-check/debug RPCs don't hammer SQLite.
func (r *Runner) getActiveTasksCached() []agentdb.Task {
	if entry := r.activeTasksCache.Load(); entry != nil && time.Now().Before(entry.expiresAt) {
		return entry.tasks
	}
	if r.agentDB == nil {
		return nil
	}
	tasks, err := r.agentDB.ActiveTasks(context.Background())
	if err != nil {
		return nil
	}
	r.activeTasksCache.Store(&activeTasksCacheEntry{tasks: tasks, expiresAt: time.Now().Add(2 * time.Second)})
	return tasks
}

// logHelper delegates to the appropriate slog level.
// The agentLogHandler tees output to console, ring buffer, and SQLite.
func (r *Runner) logHelper(level, message string) {
	switch level {
	case "WARNING":
		slog.Warn(message)
	case "ERROR", "FATAL":
		slog.Error(message)
	case "DEBUG", "VERBOSE":
		slog.Debug(message)
	default:
		slog.Info(message)
	}
}

// NewRunner creates a new runner instance
func NewRunner(options *Options) (*Runner, error) {
	r := &Runner{
		options:        options,
		agentStartTime: time.Now(),
	}

	// Generate or validate agent ID (xid format: 20 chars, base32-encoded).
	if r.options.AgentId == "" {
		r.options.AgentId = xid.New().String()
	} else {
		// Validate that a user-provided or self-update-injected ID is a valid xid.
		if _, err := xid.FromString(r.options.AgentId); err != nil {
			slog.Error("invalid agent ID (must be a valid xid)", "agent_id", r.options.AgentId, "error", err)
			os.Exit(1)
		}
	}

	// Initialize AgentName after AgentId is generated
	if r.options.AgentName == "" {
		// Try to use hostname first
		if hostname, err := os.Hostname(); err == nil && hostname != "" {
			r.options.AgentName = hostname
		} else {
			// Fallback to agent ID if hostname is not available
			r.options.AgentName = r.options.AgentId
		}
	}

	// Open local observability database.
	// Default location: ~/.pd-agent (cross-platform via os.UserHomeDir).
	// PDCP_AGENTDB_DIR overrides the default for users who want it elsewhere.
	// Last-resort fallback: next to the binary, preserving prior behaviour
	// when HOME isn't set (e.g. some service contexts).
	// Non-fatal: if everything fails, the agent runs without local persistence.
	dbDir := os.Getenv("PDCP_AGENTDB_DIR")
	if dbDir == "" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			candidate := filepath.Join(home, ".pd-agent")
			if err := os.MkdirAll(candidate, 0o755); err == nil {
				dbDir = candidate
			} else {
				slog.Warn("agentdb: cannot create ~/.pd-agent, falling back to binary dir", "error", err)
			}
		}
	}
	if dbDir == "" {
		if execPath, err := os.Executable(); err == nil {
			dbDir = filepath.Dir(execPath)
		}
	}
	if dbDir != "" {
		dbPath := filepath.Join(dbDir, fmt.Sprintf("pd-agent-%s.db", r.options.AgentId))
		slog.Info("agentdb: opening local DB", "path", dbPath)
		if db, err := agentdb.Open(dbPath); err != nil {
			slog.Warn("agentdb: failed to open, local observability disabled", "path", dbPath, "error", err)
		} else {
			r.agentDB = db
			warnOrphanDBs(dbDir, r.options.AgentId)
		}
	}

	// Start passive discovery if enabled
	// if r.options.PassiveDiscovery {
	// 	go r.startPassiveDiscovery()
	// }

	return r, nil
}

// GetNATSCredentials returns the current NATS credentials (thread-safe).
// Returns nil if no credentials have been received yet.
func (r *Runner) GetNATSCredentials() *NATSCredentials {
	r.natsCredsMu.RLock()
	defer r.natsCredsMu.RUnlock()
	return r.natsCreds
}

// extractJWT parses the JWT from a NATS .creds formatted string.
func extractJWT(credsContent string) (string, error) {
	return nkeys.ParseDecoratedJWT([]byte(credsContent))
}

// signNonce parses the NKey seed from a NATS .creds formatted string
// and signs the given nonce. The seed is wiped after signing.
func signNonce(credsContent string, nonce []byte) ([]byte, error) {
	kp, err := nkeys.ParseDecoratedNKey([]byte(credsContent))
	if err != nil {
		return nil, fmt.Errorf("failed to parse nkey seed: %w", err)
	}
	defer kp.Wipe()
	return kp.Sign(nonce)
}

// startNATSRPC connects to NATS using the current credentials, sets up the
// request/broadcast routers, and subscribes. It replaces any existing connection.
func (r *Runner) startNATSRPC() error {
	creds := r.GetNATSCredentials()
	if creds == nil {
		return fmt.Errorf("no NATS credentials available")
	}

	// Use JWT callbacks so credentials are read from memory on every
	// connect/reconnect — no temp files, hot-swap on credential refresh.
	opts := []nats.Option{
		nats.UserJWT(
			func() (string, error) {
				c := r.GetNATSCredentials()
				if c == nil {
					return "", fmt.Errorf("no NATS credentials available")
				}
				return extractJWT(c.Credentials)
			},
			func(nonce []byte) ([]byte, error) {
				c := r.GetNATSCredentials()
				if c == nil {
					return nil, fmt.Errorf("no NATS credentials available")
				}
				return signNonce(c.Credentials, nonce)
			},
		),
		nats.Name(fmt.Sprintf("pd-agent-%s", r.options.AgentId)),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2 * time.Second),
		nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
			if err != nil {
				r.logHelper("WARNING", fmt.Sprintf("NATS disconnected: %v", err))
			}
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			r.logHelper("INFO", fmt.Sprintf("NATS reconnected to %s", nc.ConnectedUrl()))
		}),
		nats.ClosedHandler(func(nc *nats.Conn) {
			r.logHelper("INFO", "NATS connection closed")
		}),
	}

	if creds.InboxPrefix != "" {
		opts = append(opts, nats.CustomInboxPrefix(creds.InboxPrefix))
	}

	nc, err := nats.Connect(creds.NatsURL, opts...)
	if err != nil {
		return fmt.Errorf("failed to connect to NATS at %s: %w", creds.NatsURL, err)
	}

	// Build and subscribe routers — r.ctx propagates cancellation on shutdown
	requestRouter := natsrpc.NewRouter(r.ctx)
	requestRouter.Handle("httpx", r.handleHTTPX)
	requestRouter.Handle("port-probe", r.handlePortProbe)
	requestRouter.Handle("nuclei-retest", r.handleNucleiRetest)

	broadcastRouter := natsrpc.NewRouter(r.ctx)
	broadcastRouter.Handle("health-check", r.handleHealthCheck)

	directRouter := natsrpc.NewRouter(r.ctx)
	directRouter.Handle("health-check", r.handleHealthCheck)
	directRouter.Handle("debug", r.handleDebug)
	directRouter.Handle("stop", r.handleStop)
	directRouter.Handle("restart", r.handleRestart)
	directRouter.Handle("update", r.handleUpdate)
	directRouter.Handle("logs", r.handleLogs)
	directRouter.Handle("metrics", r.handleMetrics)
	directRouter.Handle("group-metrics", r.handleGroupMetrics)

	broadcastRouter.Handle("update", r.handleUpdate)

	queueGroup := r.options.AgentNetwork

	var subs []*nats.Subscription

	reqSub, err := requestRouter.SubscribeRequests(nc, creds.Subjects.Requests, queueGroup)
	if err != nil {
		nc.Close()
		return fmt.Errorf("failed to subscribe to requests on %s: %w", creds.Subjects.Requests, err)
	}
	subs = append(subs, reqSub)

	bcastSub, err := broadcastRouter.SubscribeBroadcast(nc, creds.Subjects.Broadcast)
	if err != nil {
		nc.Close()
		return fmt.Errorf("failed to subscribe to broadcast on %s: %w", creds.Subjects.Broadcast, err)
	}
	subs = append(subs, bcastSub)

	directSubject := creds.GroupPrefix + ".direct." + r.options.AgentId
	directSub, err := directRouter.SubscribeDirect(nc, directSubject)
	if err != nil {
		nc.Close()
		return fmt.Errorf("failed to subscribe to direct on %s: %w", directSubject, err)
	}
	subs = append(subs, directSub)

	// Swap in the new connection, unsubscribe and drain old one
	r.natsConnMu.Lock()
	old := r.natsConn
	oldSubs := r.natsSubs
	r.natsConn = nc
	r.natsSubs = subs
	r.natsStarted = true
	r.natsConnMu.Unlock()

	if old != nil {
		for _, sub := range oldSubs {
			_ = sub.Unsubscribe()
		}
		_ = old.Drain()
	}

	r.logHelper("INFO", "NATS RPC connected")
	return nil
}

// stopNATSRPC gracefully drains and closes the NATS connection.
func (r *Runner) stopNATSRPC() {
	r.natsConnMu.Lock()
	nc := r.natsConn
	r.natsConn = nil
	r.natsConnMu.Unlock()

	if nc != nil {
		r.logHelper("INFO", "draining NATS connection...")
		if err := nc.Drain(); err != nil {
			r.logHelper("WARNING", fmt.Sprintf("NATS drain error: %v", err))
		}
	}
}

// onNATSCredentialsReceived is called from inFunctionTickCallback when NATS
// credentials arrive or change. It starts or reconnects the NATS RPC layer.
func (r *Runner) onNATSCredentialsReceived(isNew bool) {
	if isNew {
		// First time — start NATS in background
		go func() {
			if err := r.startNATSRPC(); err != nil {
				r.logHelper("ERROR", fmt.Sprintf("failed to start NATS RPC: %v", err))
				return
			}
			if err := r.startJetStreamWorkers(); err != nil {
				r.logHelper("FATAL", fmt.Sprintf("JetStream workers failed to start: %v", err))
				os.Exit(1)
			}
		}()
		return
	}

	// Credentials refreshed — force reconnect to pick up new JWT via callbacks
	r.natsConnMu.Lock()
	nc := r.natsConn
	r.natsConnMu.Unlock()

	if nc != nil {
		r.logHelper("INFO", "NATS credentials refreshed, forcing reconnect...")
		if err := nc.ForceReconnect(); err != nil {
			r.logHelper("ERROR", fmt.Sprintf("failed to force NATS reconnect: %v", err))
		}
	}
}

// --- NATS RPC Handlers ---

func (r *Runner) handleHTTPX(ctx context.Context, method string, data []byte) (any, error) {
	var req natsrpc.HTTPXRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid httpx request: %w", err)
	}
	if req.Target == "" {
		return nil, fmt.Errorf("httpx: target is required")
	}

	r.logHelper("DEBUG", "NATS RPC: httpx request received")

	// Write target to temp file (httpx SDK uses InputFile)
	f, err := os.CreateTemp("", "httpx-targets-*.txt")
	if err != nil {
		return nil, fmt.Errorf("httpx: create temp file: %w", err)
	}
	defer os.Remove(f.Name())
	fmt.Fprintln(f, req.Target)
	f.Close()

	// Collect results via callback
	var mu sync.Mutex
	var results []httpxrunner.Result

	opts := httpxrunner.Options{
		Methods:         http.MethodGet,
		InputFile:       f.Name(),
		StatusCode:      true,
		ExtractTitle:    true,
		TechDetect:      true,
		OutputIP:        true,
		OutputCName:     true,
		FollowRedirects: true,
		Timeout:         10,
		Retries:         2,
		Threads:         25,
		RateLimit:       150,
		Silent:          true,
		NoColor:         true,
		OnResult: func(result httpxrunner.Result) {
			if result.Err != nil {
				return
			}
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		},
	}

	if err := opts.ValidateOptions(); err != nil {
		return nil, fmt.Errorf("httpx: validate options: %w", err)
	}

	httpxRunner, err := httpxrunner.New(&opts)
	if err != nil {
		return nil, fmt.Errorf("httpx: runner init: %w", err)
	}
	defer httpxRunner.Close()

	// RunEnumeration is blocking — completes when all targets are processed
	httpxRunner.RunEnumeration()

	return results, nil
}

func (r *Runner) handlePortProbe(ctx context.Context, method string, data []byte) (any, error) {
	var req natsrpc.PortProbeRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid port-probe request: %w", err)
	}
	if req.Host == "" {
		return nil, fmt.Errorf("port-probe: host is required")
	}
	if req.Port <= 0 || req.Port > 65535 {
		return nil, fmt.Errorf("port-probe: invalid port %d", req.Port)
	}

	r.logHelper("DEBUG", "NATS RPC: port-probe request received")

	target := net.JoinHostPort(req.Host, strconv.Itoa(req.Port))
	conn, err := net.DialTimeout("tcp", target, 5*time.Second)

	open := err == nil
	if open {
		conn.Close()
	}

	return map[string]any{
		"host":      req.Host,
		"port":      req.Port,
		"protocol":  "tcp",
		"open":      open,
		"timestamp": time.Now().UTC(),
	}, nil
}

func (r *Runner) handleNucleiRetest(ctx context.Context, method string, data []byte) (any, error) {
	var req natsrpc.NucleiRetestRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid nuclei-retest request: %w", err)
	}
	if len(req.Targets) == 0 {
		return nil, fmt.Errorf("nuclei-retest: no targets provided")
	}
	if req.TemplateID == "" && req.TemplateEncoded == "" && req.TemplateURL == "" {
		return nil, fmt.Errorf("nuclei-retest: template_id, template_encoded, or template_url required")
	}

	r.logHelper("INFO", fmt.Sprintf("NATS RPC: nuclei-retest targets=%d", len(req.Targets)))

	// Build SDK options — minimal config for fast execution
	sdkOpts := []nuclei.NucleiSDKOptions{
		nuclei.DisableUpdateCheck(),
		nuclei.WithVerbosity(nuclei.VerbosityOptions{Silent: true}),
	}

	// Handle template source — priority: encoded > url > id
	switch {
	case req.TemplateEncoded != "":
		// base64 decode → temp file (SDK only accepts file paths)
		decoded, err := base64.StdEncoding.DecodeString(req.TemplateEncoded)
		if err != nil {
			return nil, fmt.Errorf("nuclei-retest: decode template: %w", err)
		}
		f, err := os.CreateTemp("", "nuclei-retest-*.yaml")
		if err != nil {
			return nil, fmt.Errorf("nuclei-retest: create temp file: %w", err)
		}
		defer os.Remove(f.Name())
		if _, err := f.Write(decoded); err != nil {
			f.Close()
			return nil, fmt.Errorf("nuclei-retest: write template: %w", err)
		}
		f.Close()
		sdkOpts = append(sdkOpts, nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
			Templates: []string{f.Name()},
		}))

	case req.TemplateURL != "":
		// Download template from URL → temp file
		resp, err := http.Get(req.TemplateURL)
		if err != nil {
			return nil, fmt.Errorf("nuclei-retest: fetch template url: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("nuclei-retest: template url returned %d", resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("nuclei-retest: read template url body: %w", err)
		}
		f, err := os.CreateTemp("", "nuclei-retest-*.yaml")
		if err != nil {
			return nil, fmt.Errorf("nuclei-retest: create temp file: %w", err)
		}
		defer os.Remove(f.Name())
		if _, err := f.Write(body); err != nil {
			f.Close()
			return nil, fmt.Errorf("nuclei-retest: write template: %w", err)
		}
		f.Close()
		sdkOpts = append(sdkOpts, nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
			Templates: []string{f.Name()},
		}))

	default:
		// Load by template ID from installed nuclei-templates
		sdkOpts = append(sdkOpts, nuclei.WithTemplateFilters(nuclei.TemplateFilters{
			IDs: []string{req.TemplateID},
		}))
	}

	// Create engine with 5-minute timeout
	execCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	ne, err := nuclei.NewNucleiEngineCtx(execCtx, sdkOpts...)
	if err != nil {
		return nil, fmt.Errorf("nuclei-retest: engine init: %w", err)
	}

	// Load targets (no HTTP probing needed for retest)
	ne.LoadTargets(req.Targets, false)

	// Execute and collect results
	var mu sync.Mutex
	var results []*output.ResultEvent
	err = ne.ExecuteCallbackWithCtx(execCtx, func(event *output.ResultEvent) {
		mu.Lock()
		results = append(results, event)
		mu.Unlock()
	})
	if err != nil {
		ne.Close()
		return nil, fmt.Errorf("nuclei-retest: execution failed: %w", err)
	}

	// Close the engine BEFORE reading results. This triggers the interactsh
	// cooldown period — the client sleeps for CooldownPeriod (5s), does a
	// final poll, and processes any pending OOB interactions. The callback
	// is still registered, so matches found during cooldown land in results.
	ne.Close()

	// Return single ResultEvent matching platform/retest format
	var result *output.ResultEvent
	if len(results) > 0 {
		result = results[0]
	} else {
		// No match — return empty result with matcher_status=false
		result = &output.ResultEvent{
			MatcherStatus: false,
		}
	}

	// Set template source fields like platform handler does
	if req.TemplateEncoded != "" {
		result.TemplateEncoded = req.TemplateEncoded
	}

	// Clear Interaction field — it may contain raw binary data from interactsh
	// DNS responses that fails JSON marshalling with control character errors.
	result.Interaction = nil

	return result, nil
}

func (r *Runner) handleHealthCheck(ctx context.Context, method string, data []byte) (any, error) {
	memTotal, _ := resourceprofile.ReadMemory()

	hc := natsrpc.HealthCheckData{
		AgentID:    r.options.AgentId,
		AgentName:  r.options.AgentName,
		Version:    Version,
		Uptime:     time.Since(r.agentStartTime).String(),
		NumCPU:     runtime.NumCPU(),
		MemTotalMB: memTotal / (1024 * 1024),
	}

	// Active tasks from SQLite — source of truth (2s cached).
	tasks := r.getActiveTasksCached()
	for _, t := range tasks {
		switch t.Type {
		case "scan":
			hc.ActiveScans = append(hc.ActiveScans, t.TaskID)
		case "enumeration":
			hc.ActiveEnums = append(hc.ActiveEnums, t.TaskID)
		}
	}
	hc.TasksRunning = len(tasks)

	// Report idle only when no work is happening at any level.
	if hc.TasksRunning == 0 && time.Since(r.agentStartTime) > time.Minute {
		hc.Idle = true
		hc.IdleSince = r.agentStartTime.UTC().Format(time.RFC3339)
		if pool := r.jsPool.Load(); pool != nil {
			if idle := pool.IdleSince(); !idle.IsZero() {
				hc.IdleSince = idle.UTC().Format(time.RFC3339)
			}
		}
	}

	return hc, nil
}

func (r *Runner) handleDebug(ctx context.Context, method string, data []byte) (any, error) {
	uptime := time.Since(r.agentStartTime)
	hostname, _ := os.Hostname()

	// Go runtime memory stats — cross-platform, no syscall dependency
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	var lastGC string
	if mem.LastGC > 0 {
		lastGC = time.Unix(0, int64(mem.LastGC)).UTC().Format(time.RFC3339)
	}

	dd := natsrpc.DebugData{
		Agent: natsrpc.AgentInfo{
			ID:            r.options.AgentId,
			Name:          r.options.AgentName,
			Version:       Version,
			Uptime:        uptime.Round(time.Second).String(),
			UptimeSeconds: uptime.Seconds(),
			TasksRunning:  0, // populated below from SQLite active tasks
		},
		System: natsrpc.SystemInfo{
			OS:       runtime.GOOS,
			Arch:     runtime.GOARCH,
			NumCPU:   runtime.NumCPU(),
			Hostname: hostname,
		},
		Process: natsrpc.ProcessInfo{
			PID:        os.Getpid(),
			MemAllocMB: float64(mem.Sys) / (1024 * 1024),
		},
		Runtime: natsrpc.RuntimeInfo{
			GoVersion:    runtime.Version(),
			NumGoroutine: runtime.NumGoroutine(),
			HeapAllocMB:  float64(mem.HeapAlloc) / (1024 * 1024),
			HeapInuseMB:  float64(mem.HeapInuse) / (1024 * 1024),
			StackInuseMB: float64(mem.StackInuse) / (1024 * 1024),
			TotalAllocMB: float64(mem.TotalAlloc) / (1024 * 1024),
			NumGC:        mem.NumGC,
			LastGC:       lastGC,
		},
	}

	tasks := r.getActiveTasksCached()
	dd.Agent.TasksRunning = len(tasks)
	for _, t := range tasks {
		dd.ActiveTasks = append(dd.ActiveTasks, natsrpc.TaskInfo{
			Type:      t.Type,
			TaskID:    t.TaskID,
			StartedAt: t.StartedAt.UTC().Format(time.RFC3339),
		})
	}

	return dd, nil
}

func (r *Runner) handleStop(ctx context.Context, method string, data []byte) (any, error) {
	r.logHelper("INFO", "NATS RPC: received stop command, shutting down...")
	go func() {
		// Small delay to allow the NATS response to be sent before shutdown
		time.Sleep(500 * time.Millisecond)
		p, _ := os.FindProcess(os.Getpid())
		_ = p.Signal(os.Interrupt)
	}()
	return map[string]any{
		"agent_id": r.options.AgentId,
		"status":   "stopping",
	}, nil
}

func (r *Runner) handleRestart(ctx context.Context, method string, data []byte) (any, error) {
	r.logHelper("INFO", "NATS RPC: received restart command, restarting agent...")
	if r.restartRequested.CompareAndSwap(false, true) {
		go func() {
			// Small delay to allow the NATS response to be sent before restart
			time.Sleep(500 * time.Millisecond)
			r.cancelCtx()
		}()
	}
	return map[string]any{
		"agent_id": r.options.AgentId,
		"status":   "restarting",
	}, nil
}

func (r *Runner) handleUpdate(ctx context.Context, method string, data []byte) (any, error) {
	var req selfupdate.UpdateRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid update request: %w", err)
	}

	if req.Version == "" {
		req.Version = "latest"
	}

	r.logHelper("INFO", fmt.Sprintf("NATS RPC: received update command (version=%s)", req.Version))

	result := selfupdate.UpdateResult{
		AgentID:        r.options.AgentId,
		CurrentVersion: Version,
		TargetVersion:  req.Version,
	}

	// Fail fast: container or same version — return immediately, no goroutine.
	if selfupdate.IsContainer() {
		result.Status = "skipped"
		result.Message = "running in a container — update the image instead of self-updating"
		return result, nil
	}
	if req.Version == Version {
		result.Status = "skipped"
		result.Message = fmt.Sprintf("already running %s", Version)
		return result, nil
	}

	// Run update in background — we need to send the NATS response first.
	// Download and verify BEFORE draining connections, so on failure the
	// agent keeps running normally.
	// Detached ctx: the NATS handler ctx is cancelled once the response is
	// sent, so the download must not depend on it.
	go func() {
		// Small delay to let the NATS response go out.
		time.Sleep(500 * time.Millisecond)

		dlCtx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()

		// Phase 1: Download and verify (agent still fully operational).
		r.logHelper("INFO", "selfupdate: downloading and verifying new binary...")
		newBinary, err := selfupdate.DownloadAndVerify(dlCtx, Version, req.Version)
		if err != nil {
			r.logHelper("ERROR", fmt.Sprintf("selfupdate failed: %v", err))
			return // agent keeps running, NATS still connected
		}

		// Phase 1b: Preflight — run the new binary with the exact restart args
		// to confirm it accepts them before we commit to swapping. Catches the
		// "new binary doesn't recognize one of our flags" bricking failure.
		if err := selfupdate.Prevalidate(newBinary, r.options.AgentId); err != nil {
			r.logHelper("ERROR", fmt.Sprintf("selfupdate aborted at preflight: %v", err))
			_ = os.Remove(newBinary)
			return // agent keeps running on the old binary
		}

		// Phase 2: Download succeeded and preflight passed — drain and replace.
		r.logHelper("INFO", "selfupdate: binary verified, draining in-flight work...")

		if cancel := r.jsCancel.Load(); cancel != nil {
			(*cancel)()
		}
		if pool := r.jsPool.Load(); pool != nil {
			pool.Stop()
		}
		r.stopNATSRPC()

		r.logHelper("INFO", "selfupdate: applying update...")
		if err := selfupdate.Apply(newBinary, Version, r.options.AgentId); err != nil {
			r.logHelper("ERROR", fmt.Sprintf("selfupdate apply failed: %v", err))
			// Binary replace failed. NATS is drained. Restart the process
			// to reconnect — same binary, same version.
			r.logHelper("INFO", "selfupdate: restarting agent to recover NATS connection...")
			execPath, _ := os.Executable()
			_ = syscall.Exec(execPath, os.Args, os.Environ())
			return
		}
		// If Apply succeeded, syscall.Exec replaced this process.
	}()

	result.Status = "updating"
	result.Message = fmt.Sprintf("downloading %s, will restart after in-flight work completes", req.Version)
	return result, nil
}

func (r *Runner) handleLogs(ctx context.Context, method string, data []byte) (any, error) {
	var req natsrpc.LogsRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid logs request: %w", err)
	}

	if req.Limit <= 0 {
		req.Limit = 100
	}
	if req.Limit > 500 {
		req.Limit = 500
	}
	if req.Offset < 0 {
		req.Offset = 0
	}

	// All logs are persisted to SQLite — no more in-memory ring buffer.
	if r.agentDB == nil {
		return nil, fmt.Errorf("local database not available")
	}
	filter := agentdb.LogFilter{
		Offset: req.Offset,
		Limit:  req.Limit,
	}
	if req.Since != "" {
		t, err := time.Parse(time.RFC3339, req.Since)
		if err != nil {
			return nil, fmt.Errorf("invalid since: %w", err)
		}
		filter.Since = t
	}
	if req.Until != "" {
		t, err := time.Parse(time.RFC3339, req.Until)
		if err != nil {
			return nil, fmt.Errorf("invalid until: %w", err)
		}
		filter.Until = t
	}
	dbEntries, err := r.agentDB.QueryLogs(context.Background(), filter)
	if err != nil {
		return nil, fmt.Errorf("query logs: %w", err)
	}
	lines := make([]string, len(dbEntries))
	for i, e := range dbEntries {
		lines[i] = e.Line
	}
	return natsrpc.LogsResponse{
		Lines:  lines,
		Total:  len(lines),
		Offset: req.Offset,
		Limit:  req.Limit,
	}, nil
}

// handleMetrics returns time-series resource metrics for graph plotting.
func (r *Runner) handleMetrics(ctx context.Context, method string, data []byte) (any, error) {
	var req natsrpc.MetricsRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid metrics request: %w", err)
	}

	if r.agentDB == nil {
		return nil, fmt.Errorf("local database not available")
	}

	// Resolve time range.
	var since, until time.Time
	now := time.Now().UTC()

	presets := map[string]time.Duration{
		"5m":  5 * time.Minute,
		"15m": 15 * time.Minute,
		"30m": 30 * time.Minute,
		"1h":  1 * time.Hour,
		"3h":  3 * time.Hour,
		"6h":  6 * time.Hour,
		"24h": 24 * time.Hour,
	}

	if req.Range == "custom" {
		if req.Start == "" || req.End == "" {
			return nil, fmt.Errorf("custom range requires start and end")
		}
		var err error
		since, err = time.Parse(time.RFC3339, req.Start)
		if err != nil {
			return nil, fmt.Errorf("invalid start: %w", err)
		}
		until, err = time.Parse(time.RFC3339, req.End)
		if err != nil {
			return nil, fmt.Errorf("invalid end: %w", err)
		}
		if !until.After(since) {
			return nil, fmt.Errorf("end must be after start")
		}
		if until.Sub(since) > 24*time.Hour {
			return nil, fmt.Errorf("max custom range is 24h")
		}
	} else if d, ok := presets[req.Range]; ok {
		since = now.Add(-d)
		until = now
	} else {
		return nil, fmt.Errorf("invalid range %q: use 5m,15m,30m,1h,3h,6h,24h,custom", req.Range)
	}

	// Query all samples in range (no limit).
	samples, err := r.agentDB.QueryMetrics(context.Background(), since, until, 0)
	if err != nil {
		return nil, fmt.Errorf("query metrics: %w", err)
	}

	total := len(samples)

	// Downsample: target ~360 points max.
	const maxPoints = 360
	step := 1
	if total > maxPoints {
		step = total / maxPoints
	}

	points := make([]natsrpc.MetricPoint, 0, min(total, maxPoints+1))
	for i := 0; i < total; i += step {
		s := samples[i]
		points = append(points, natsrpc.MetricPoint{
			T:             s.Timestamp.UTC().Format(time.RFC3339),
			CPU:           s.CPUPercent,
			RSSMB:         s.RSSMB,
			HeapMB:        s.HeapAllocMB,
			FDUsed:        s.FDUsed,
			FDLimit:       s.FDLimit,
			MemTotalMB:    s.MemTotalMB,
			MemAvailMB:    s.MemAvailMB,
			Goroutines:    s.Goroutines,
			ActiveWorkers: s.ActiveWorkers,
			Capacity:      s.ChunkParallelism,
		})
	}

	return natsrpc.MetricsResponse{
		Range:        req.Range,
		Since:        since.UTC().Format(time.RFC3339),
		Until:        until.UTC().Format(time.RFC3339),
		TotalSamples: total,
		Returned:     len(points),
		Points:       points,
	}, nil
}

// handleGroupMetrics returns the group-level chunk backlog from JetStream
// consumer state. All agents in the same group return identical numbers
// because they share a stream — the operator (or a Prometheus HPA pipeline
// scraping any one pod) can read this off any agent and decide whether to
// scale the deployment up or down.
//
// Returns the GroupMetrics struct directly so the response Data field is
// the metrics payload as JSON.
func (r *Runner) handleGroupMetrics(ctx context.Context, method string, data []byte) (any, error) {
	collector := r.groupMetrics.Load()
	if collector == nil {
		return nil, fmt.Errorf("group metrics not initialised (NATS not yet ready)")
	}
	return collector.Get(ctx), nil
}

// --- JetStream Work Distribution ---

// startJetStreamWorkers initialises the JetStream worker pool that replaces
// HTTP polling for scan/enumeration work distribution. It uses the group-level
// stream (NATSCredentials.Stream) with a FilterSubject scoped to work
// notifications (groupPrefix.work.>).
func (r *Runner) startJetStreamWorkers() error {
	creds := r.GetNATSCredentials()
	if creds == nil || creds.Stream == "" {
		return fmt.Errorf("NATS stream not provided by server")
	}

	r.natsConnMu.Lock()
	nc := r.natsConn
	r.natsConnMu.Unlock()
	if nc == nil {
		return fmt.Errorf("NATS connection not available")
	}

	// Auto-detect chunk parallelism if not explicitly overridden.
	// 0 means auto-detect (neither env var nor CLI flag was set).
	chunkParallelism := r.options.ChunkParallelism
	source := "user-override"
	if chunkParallelism == 0 {
		result := resourceprofile.ComputeChunkParallelism(r.options.ScanParallelism)
		chunkParallelism = result.ChunkParallelism
		r.options.ChunkParallelism = chunkParallelism
		source = "auto-detect"
		resourceprofile.LogAutoDetectResult(result, source)
	} else {
		slog.Info("chunk parallelism override",
			"chunk_parallelism", chunkParallelism,
			"source", source,
		)
	}

	// Enumeration semaphore: resizable + adaptive scaler.
	chunkSem := resourceprofile.NewResizableSemaphore(chunkParallelism, resourceprofile.MaxParallelism)
	chunkScaler := resourceprofile.NewScaler(chunkSem)
	r.chunkSem.Store(chunkSem)
	r.chunkScaler.Store(chunkScaler)

	// Scan semaphore: pinned at NumCPU. Initial == max so Resize is a no-op.
	scanChunkParallelism := max(runtime.GOMAXPROCS(0), 1)
	r.scanSem.Store(resourceprofile.NewResizableSemaphore(scanChunkParallelism, scanChunkParallelism))

	consumerName := fmt.Sprintf("work-%s", r.options.AgentId)
	pool, err := natsrpc.NewWorkerPool(nc, creds.Stream, consumerName, creds.GroupPrefix, r.options.ScanParallelism, r.processWorkMessage)
	if err != nil {
		return fmt.Errorf("create worker pool: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	r.jsPool.Store(pool)
	r.jsCancel.Store(&cancel)
	pool.Run(ctx)

	// Start adaptive scaler control loop in background.
	go chunkScaler.Run(ctx)

	// Initialise group metrics collector. JetStream handle, stream, and the
	// local work consumer name are all known at this point.
	r.groupMetrics.Store(natsrpc.NewGroupMetricsCollector(pool.JS(), creds.Stream, consumerName, 5*time.Second))

	r.logHelper("INFO", fmt.Sprintf("JetStream workers started (scan_parallelism=%d, scan_chunk_parallelism=%d, enum_chunk_parallelism=%d, source=%s, stream=%s, consumer=%s, filter=%s.work.>)",
		r.options.ScanParallelism, scanChunkParallelism, chunkParallelism, source, creds.Stream, consumerName, creds.GroupPrefix))

	return nil
}

// processWorkMessage handles a single work message from the JetStream work
// stream. It sets up the chunk consumer and dispatches to the appropriate
// execution function (nuclei scan or enumeration).
func (r *Runner) processWorkMessage(ctx context.Context, msg jetstream.Msg, work *natsrpc.WorkMessage) error {
	switch work.Type {
	case "scan":
		return r.processJetStreamScan(ctx, work)
	case "enumeration":
		return r.processJetStreamEnumeration(ctx, work)
	default:
		// Bad message — terminate immediately so it's never redelivered.
		slog.Error("jetstream: skipping work message with unknown type",
			"type", work.Type,
			"id", work.ScanID,
			"chunk_subject", work.ChunkSubject,
		)
		_ = msg.Term()
		return nil // return nil so the worker doesn't Nak on top of Term
	}
}

func (r *Runner) processJetStreamScan(ctx context.Context, work *natsrpc.WorkMessage) error {
	r.logHelper("INFO", fmt.Sprintf("JetStream: processing scan %s (chunk_subject=%s)", work.ScanID, work.ChunkSubject))

	if r.agentDB != nil {
		_ = r.agentDB.InsertTask(context.Background(), &agentdb.Task{Type: "scan", TaskID: work.ScanID})
	}

	err := func() error {
		// Set up scan log batcher
		var scanBatcher *batcher.Batcher[types.ScanLogUploadEntry]
		if scanlog.IsLogUploadEnabled() {
			scanBatcher = scanlog.NewScanLogBatcher(work.ScanID, r.options.TeamID)
			defer func() {
				scanBatcher.Stop()
				scanBatcher.WaitDone()
			}()
		}

		// Consume chunks from the group stream, filtered by chunk subject
		creds := r.GetNATSCredentials()
		chunkConsumer := work.ChunkConsumer
		if chunkConsumer == "" {
			chunkConsumer = fmt.Sprintf("chunks-%s", work.ScanID)
		}
		pool := r.jsPool.Load()
		if pool == nil {
			return fmt.Errorf("jetstream pool not initialized")
		}
		scanSem := r.scanSem.Load()
		if scanSem == nil {
			return fmt.Errorf("scan semaphore not initialized")
		}
		// Nuclei runs on a fixed semaphore at NumCPU and intentionally has no
		// scaler — the warmup window confuses the pressure-based scaler.
		return natsrpc.ConsumeChunks(ctx, pool.JS(), creds.Stream, chunkConsumer, work.ChunkSubject, scanSem.Size(),
			scanSem, nil,
			func(ctx context.Context, chunk *natsrpc.ChunkMessage) error {
				r.executeNucleiScan(ctx, work.ScanID, chunk.ChunkID, work.Config, chunk.PublicTemplates, chunk.PrivateTemplates, chunk.Targets, scanBatcher)
				return nil
			},
		)
	}()

	if r.agentDB != nil {
		status := "completed"
		if err != nil {
			if errors.Is(err, context.Canceled) {
				status = "canceled"
			} else {
				status = "failed"
			}
		}
		_ = r.agentDB.FinishTask(context.Background(), work.ScanID, status)
	}
	return err
}

func (r *Runner) processJetStreamEnumeration(ctx context.Context, work *natsrpc.WorkMessage) error {
	r.logHelper("INFO", fmt.Sprintf("JetStream: processing enumeration %s (chunk_subject=%s)", work.ScanID, work.ChunkSubject))

	if r.agentDB != nil {
		_ = r.agentDB.InsertTask(context.Background(), &agentdb.Task{Type: "enumeration", TaskID: work.ScanID})
	}

	err := func() error {
		creds := r.GetNATSCredentials()
		chunkConsumer := work.ChunkConsumer
		if chunkConsumer == "" {
			chunkConsumer = fmt.Sprintf("chunks-%s", work.ScanID)
		}
		pool := r.jsPool.Load()
		if pool == nil {
			return fmt.Errorf("jetstream pool not initialized")
		}
		// Convert typed-nil *Scaler to interface-nil so the nil-guard inside
		// ConsumeChunks works correctly. A typed-nil pointer wrapped in an
		// interface is non-nil and would panic on method call.
		var scaler natsrpc.ChunkScaler
		if s := r.chunkScaler.Load(); s != nil {
			scaler = s
		}
		return natsrpc.ConsumeChunks(ctx, pool.JS(), creds.Stream, chunkConsumer, work.ChunkSubject, r.options.ChunkParallelism,
			r.chunkSem.Load(), scaler,
			func(ctx context.Context, chunk *natsrpc.ChunkMessage) error {
				// Steps can come from the work message or from the chunk's enrichment config.
				// The server puts enrichment_steps in the chunk's EnumerationConfiguration JSON.
				steps := work.Steps
				if len(steps) == 0 && chunk.EnumConfig != "" {
					enrichmentSteps := gjson.Get(chunk.EnumConfig, "enrichment_steps").String()
					if enrichmentSteps != "" {
						steps = strings.Split(enrichmentSteps, ",")
					}
				}
				r.executeEnumeration(ctx, work.ScanID, chunk.ChunkID, steps, chunk.Targets)
				return nil
			},
		)
	}()

	if r.agentDB != nil {
		status := "completed"
		if err != nil {
			if errors.Is(err, context.Canceled) {
				status = "canceled"
			} else {
				status = "failed"
			}
		}
		_ = r.agentDB.FinishTask(context.Background(), work.ScanID, status)
	}
	return err
}

// Run starts the agent
func (r *Runner) Run(ctx context.Context) error {
	for {
		var infoMessage strings.Builder
		fmt.Fprintf(&infoMessage, "pd-agent %s — running in agent mode", Version)
		if r.options.AgentId != "" {
			fmt.Fprintf(&infoMessage, " with id %s", r.options.AgentId)
		}
		if len(r.options.AgentTags) > 0 {
			fmt.Fprintf(&infoMessage, " (tags: [%s])", strings.Join(r.options.AgentTags, ", "))
		} else {
			infoMessage.WriteString(" (tags: [])")
		}
		if r.options.AgentNetwork != "" {
			fmt.Fprintf(&infoMessage, " (network: %s)", r.options.AgentNetwork)
		}

		r.logHelper("INFO", infoMessage.String())

		if err := r.agentMode(ctx); err != nil {
			return err
		}

		if !r.restartRequested.Load() {
			return nil
		}

		r.logHelper("INFO", "restart: reinitializing agent...")
		r.resetForRestart()
	}
}

func (r *Runner) resetForRestart() {
	r.restartRequested.Store(false)

	// Clear NATS state so the next credential receipt triggers a fresh startNATSRPC
	r.natsConnMu.Lock()
	r.natsConn = nil
	r.natsSubs = nil
	r.natsStarted = false
	r.natsConnMu.Unlock()

	// Force isNew=true path in inFunctionTickCallback
	r.natsCredsMu.Lock()
	r.natsCreds = nil
	r.natsCredsMu.Unlock()

	r.ctx = nil
	r.cancelCtx = nil
	r.jsPool.Store(nil)
	r.jsCancel.Store(nil)
	r.scanSem.Store(nil)
	r.chunkSem.Store(nil)
	r.chunkScaler.Store(nil)
	r.groupMetrics.Store(nil)

	isRegistered = false
}

// agentMode runs the agent in monitoring mode
func (r *Runner) agentMode(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	r.ctx = ctx
	r.cancelCtx = cancel

	var agentLogWriter *agentdb.LogWriter

	// Optional Prometheus HTTP server for HPA scraping (off unless
	// PDCP_METRICS_ADDR is set). Started early so /healthz is reachable
	// before the JS workers come up.
	promServer, err := r.startPrometheusServer(ctx)
	if err != nil {
		slog.Warn("prometheus: failed to start", "error", err)
	}

	defer func() {
		cancel()
		// Stop JetStream workers first (finish in-progress scans)
		if jsCancel := r.jsCancel.Load(); jsCancel != nil {
			(*jsCancel)()
		}
		if pool := r.jsPool.Load(); pool != nil {
			pool.Stop()
		}
		if promServer != nil {
			shutCtx, shutCancel := context.WithTimeout(context.Background(), 3*time.Second)
			_ = promServer.Shutdown(shutCtx)
			shutCancel()
		}
		// Drain NATS connection on shutdown
		r.stopNATSRPC()
		// Stop LogWriter so shutdown logs are flushed.
		// StopLogWriter clears the writer first under mutex, then stops it,
		// so late writers fall back to the synchronous store path.
		if dbWriterInstance != nil {
			dbWriterInstance.StopLogWriter()
		}
		agentLogWriter = nil
		// DB is NOT closed here — it stays open across restarts and is closed
		// in main() after Run() returns. This ensures panic recovery in main()
		// can still write to the DB.
	}()

	// Upsert agent info and start DB truncator.
	if r.agentDB != nil {
		hostname, _ := os.Hostname()
		netInfo := agentdb.DetectNetInfo()
		if err := r.agentDB.UpsertAgentInfo(ctx, &agentdb.AgentInfo{
			AgentID:      r.options.AgentId,
			AgentName:    r.options.AgentName,
			AgentNetwork: r.options.AgentNetwork,
			Version:      Version,
			OS:           runtime.GOOS,
			Arch:         runtime.GOARCH,
			NumCPU:       runtime.NumCPU(),
			Hostname:     hostname,
			PID:          os.Getpid(),
			NetworkInfo:  netInfo,
			StartupArgs:  agentdb.MaskArgs(os.Args),
			StartupEnv:   agentdb.MaskEnv(),
			StartedAt:    r.agentStartTime,
			UpdatedAt:    time.Now(),
		}); err != nil {
			slog.Warn("agentdb: failed to upsert agent info", "error", err)
		}

		caps, err := agentdb.LoadSizeCaps()
		if err != nil {
			slog.Warn("agentdb: invalid size cap env, using defaults", "error", err)
		}
		if sqlStore, ok := r.agentDB.(*agentdb.SQLiteStore); ok {
			go agentdb.NewTruncator(sqlStore, caps.LogCapBytes, caps.MetricCapBytes).Run(ctx)

			// Start async log writer. Runs independently of ctx so shutdown
			// logs are captured. Stopped explicitly in the defer above.
			agentLogWriter = agentdb.NewLogWriter(sqlStore)
			go agentLogWriter.Run()
			if dbWriterInstance != nil {
				dbWriterInstance.SetStore(sqlStore)
				dbWriterInstance.SetLogWriter(agentLogWriter)
			}
		}
	}

	// Start resource profiler — samples every 1m for calibration data.
	// The activeWorkers function is initially a no-op; it gets wired to the
	// WorkerPool once JetStream workers start (via onNATSCredentialsReceived).
	resourceprofile.LogStartupResources()
	profiler := resourceprofile.New(1*time.Minute, func() int32 {
		// Report chunk-level concurrency (active scans + enrichments), not work-message count.
		var n int32
		if sem := r.scanSem.Load(); sem != nil {
			n += int32(sem.InUse())
		}
		if sem := r.chunkSem.Load(); sem != nil {
			n += int32(sem.InUse())
		}
		return n
	}, resourceprofile.WithMetricsHook(func(snap resourceprofile.MetricSnapshot) {
		if r.agentDB == nil {
			return
		}
		_ = r.agentDB.InsertMetric(context.Background(), &agentdb.MetricSample{
			Timestamp:        time.Now(),
			CPUPercent:       snap.CPUPercent,
			RSSMB:            snap.RSSMB,
			HeapAllocMB:      snap.HeapAllocMB,
			HeapSysMB:        snap.HeapSysMB,
			FDUsed:           snap.FDUsed,
			FDLimit:          snap.FDLimit,
			MemTotalMB:       snap.MemTotalMB,
			MemAvailMB:       snap.MemAvailMB,
			Goroutines:       snap.Goroutines,
			ActiveWorkers:    snap.ActiveWorkers,
			ChunkParallelism: r.options.ChunkParallelism,
		})
	}))
	go profiler.Run(ctx)

	var wg sync.WaitGroup
	wg.Go(func() {
		if err := r.In(ctx); err != nil {
			r.logHelper("FATAL", fmt.Sprintf("error registering agent: %v", err))
			os.Exit(1)
		}
	})

	// JetStream workers are started via onNATSCredentialsReceived
	r.logHelper("INFO", "using JetStream for work distribution")

	// After 60s of healthy uptime, drop the .old self-update backup. If the
	// agent dies before this fires (panic, NATS unreachable, etc.) the backup
	// stays so an operator can revert manually.
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(60 * time.Second):
			selfupdate.CleanupOldBinary()
		}
	}()

	defer func() {
		wg.Wait()
	}()

	// Wait for context cancellation
	<-ctx.Done()
	return nil
}

// executeNucleiScan is the shared implementation for executing nuclei scans
// using the same logic as pd-agent.
// privateTemplates maps name -> base64-encoded YAML; entries are decoded and
// written to a per-chunk temp dir, with their paths appended to the templates
// list passed to nuclei. The temp dir is cleaned up before the function returns.
// If scanBatcher is nil, a new batcher will be created for this scan.
func (r *Runner) executeNucleiScan(ctx context.Context, scanID, metaID, config string, templates []string, privateTemplates map[string]string, assets []string, scanBatcher *batcher.Batcher[types.ScanLogUploadEntry]) {
	// Resource profiling: snapshot before scan
	var activeWorkers int32
	if pool := r.jsPool.Load(); pool != nil {
		activeWorkers = pool.ActiveWorkers()
	}
	startSnap := resourceprofile.TakeScanSnapshot(scanID, metaID, "start", activeWorkers)
	defer func() {
		var aw int32
		if pool := r.jsPool.Load(); pool != nil {
			aw = pool.ActiveWorkers()
		}
		endSnap := resourceprofile.TakeScanSnapshot(scanID, metaID, "end", aw)
		resourceprofile.LogScanDelta(startSnap, endSnap)
	}()

	// Create batcher for this scan if not provided (if log upload is enabled)
	if scanBatcher == nil && scanlog.IsLogUploadEnabled() {
		scanBatcher = scanlog.NewScanLogBatcher(scanID, r.options.TeamID)
		// Defer batcher stop when scan completes
		defer func() {
			if scanBatcher != nil {
				scanBatcher.Stop()
				scanBatcher.WaitDone() // Wait for any pending uploads
				slog.Debug("Stopped scan log batcher", "scan_id", scanID)
			}
		}()
	}

	// Build the template list from whatever the chunk supplied. We never fall
	// back to "scan with all default templates" - a chunk that arrives with
	// no templates of either kind is a server-side bug, not a default-scan
	// signal, so we error out instead of silently scanning thousands of
	// templates the platform never asked for.
	templatesToUse := append([]string(nil), templates...)

	// Materialize private templates to a per-chunk temp dir so the nuclei
	// binary can load them by path. Cleaned up when the scan returns.
	if len(privateTemplates) > 0 {
		paths, cleanup, err := materializePrivateTemplates(scanID, metaID, privateTemplates)
		if err != nil {
			slog.Error("Failed to materialize private templates, continuing without them",
				"scan_id", scanID, "chunk_id", metaID, "error", err)
		} else {
			defer cleanup()
			templatesToUse = append(templatesToUse, paths...)
			slog.Info("Materialized private templates",
				"scan_id", scanID, "chunk_id", metaID, "count", len(paths))
		}
	}

	if len(templatesToUse) == 0 {
		slog.Error("Refusing to run nuclei: chunk has no public or private templates",
			"scan_id", scanID, "chunk_id", metaID,
			"public_count", len(templates), "private_count", len(privateTemplates))
		return
	}

	// Set output directory if agent output is specified
	var outputDir string
	if r.options.AgentOutput != "" {
		outputDir = filepath.Join(r.options.AgentOutput, metaID)
	}

	// Create temporary files for filtering
	tmpInputFile, err := fileutil.GetTempFileName()
	if err != nil {
		slog.Error("Failed to create temp file for targets", slog.Any("error", err))
		return
	}
	defer func() {
		_ = os.RemoveAll(tmpInputFile)
	}()

	// Write targets to temp file
	targetsContent := strings.Join(assets, "\n")
	if err := os.WriteFile(tmpInputFile, []byte(targetsContent), os.ModePerm); err != nil {
		slog.Error("Failed to write targets to temp file", "error", err)
		return
	}

	tmpTemplatesFile, err := fileutil.GetTempFileName()
	if err != nil {
		slog.Error("Failed to create temp file for templates", "error", err)
		return
	}
	defer func() {
		_ = os.RemoveAll(tmpTemplatesFile)
	}()

	// Write templates to temp file
	templatesContent := strings.Join(templatesToUse, "\n")
	if err := os.WriteFile(tmpTemplatesFile, []byte(templatesContent), os.ModePerm); err != nil {
		slog.Error("Failed to write templates to temp file", "error", err)
		return
	}

	// Filter targets by template ports using naabu
	filteredTargets, extractedPorts, err := pkg.FilterTargetsByTemplatePorts(ctx, tmpInputFile, tmpTemplatesFile, scanID, metaID)
	if err != nil {
		slog.Warn("Error filtering targets by template ports, proceeding with all targets", "error", err)
		filteredTargets = assets
	}

	// If naabu found no hosts with open ports, skip nuclei execution
	if len(filteredTargets) == 0 {
		slog.Info("Skipping nuclei execution - no hosts with open ports found after naabu scan",
			"scan_id", scanID,
			"chunk_id", metaID,
			"extracted_ports", extractedPorts)
		return
	}

	// Update task with filtered targets
	task := &types.Task{
		Tool: types.Nuclei,
		Options: types.Options{
			Hosts:     filteredTargets,
			Templates: templatesToUse,
			Silent:    true,
			ScanID:    scanID,
			Config:    config,
			TeamID:    r.options.TeamID,
			Output:    outputDir,
		},
		Id: metaID,
	}

	// Execute using the same pkg.Run logic as pd-agent
	slog.Info("Starting nuclei scan",
		"scan_id", scanID,
		"chunk_id", metaID,
		"targets", len(filteredTargets),
		"templates", len(templatesToUse),
		"extracted_ports", extractedPorts,
	)

	// Hard cap: 20 minutes per chunk. If nuclei hangs or targets are slow,
	// we abort so the chunk gets nak'd and doesn't block the semaphore forever.
	scanCtx, scanCancel := context.WithTimeout(ctx, 20*time.Minute)
	defer scanCancel()

	taskResult, outputFiles, err := pkg.Run(scanCtx, task)
	if err != nil {
		if scanCtx.Err() == context.DeadlineExceeded {
			slog.Error("Nuclei scan timed out (20m hard cap)",
				"scan_id", scanID,
				"chunk_id", metaID,
				"targets", len(filteredTargets),
			)
			return
		}
		slog.Error("Nuclei scan execution failed",
			"scan_id", scanID,
			"chunk_id", metaID,
			"error", err,
		)
		return
	}

	// For scans, there should be only one output file
	var outputFile string
	if len(outputFiles) > 0 {
		outputFile = outputFiles[0]
	}

	slog.Info("Nuclei scan completed",
		"scan_id", scanID,
		"chunk_id", metaID,
		"output_files", len(outputFiles),
	)

	// Parse and add log entries to scan's batcher (process immediately at chunk completion)
	if scanBatcher != nil && taskResult != nil && outputFile != "" {
		// Pass output file path to ExtractLogEntries
		logEntries, err := scanlog.ExtractLogEntries(taskResult, scanID, outputFile)
		if err != nil {
			slog.Warn("Failed to parse log entries", "scan_id", scanID, "error", err)
		} else {
			for _, entry := range logEntries {
				scanBatcher.Append(entry)
			}
			slog.Debug("Added log entries to batcher",
				"scan_id", scanID,
				"entry_count", len(logEntries),
				"source", "output_file",
				"chunk_id", metaID)
		}
	}

	// Cleanup output file immediately after processing (unless keep-output-files flag is set)
	// This prevents file accumulation during long scans with many chunks
	if outputFile != "" {
		if !r.options.KeepOutputFiles {
			// Default behavior: delete file after processing
			if err := os.Remove(outputFile); err != nil {
				slog.Warn("Failed to delete scan output file", "file", outputFile, "error", err)
			} else {
				slog.Debug("Deleted scan output file after processing", "file", outputFile, "chunk_id", metaID)
			}
		} else {
			// Flag is set: keep file intact for debugging/analysis
			slog.Debug("Keeping scan output file (keep-output-files flag is set)", "file", outputFile, "chunk_id", metaID)
		}
	}

	if taskResult != nil {
		r.logHelper("INFO", fmt.Sprintf("Completed nuclei scan for scanID=%s, metaID=%s", scanID, metaID))
	} else {
		r.logHelper("INFO", fmt.Sprintf("Completed nuclei scan for scanID=%s, metaID=%s", scanID, metaID))
	}
}

// executeEnumeration is the shared implementation for executing enumerations
// using the same logic as pd-agent
func (r *Runner) executeEnumeration(ctx context.Context, enumID, metaID string, steps, assets []string) {
	r.logHelper("INFO", fmt.Sprintf("Starting enumeration for enumID=%s, metaID=%s, steps=%d, assets=%d", enumID, metaID, len(steps), len(assets)))

	// Set output directory if agent output is specified
	var outputDir string
	if r.options.AgentOutput != "" {
		outputDir = filepath.Join(r.options.AgentOutput, metaID)
	}

	// Create task for enumeration - this will trigger the enumeration execution logic in pkg.Run
	// which runs tools like dnsx, naabu, httpx based on the steps
	task := &types.Task{
		Tool: types.Nuclei, // Tool type doesn't matter for enumerations, pkg.Run checks EnumerationID to run enumeration tools
		Options: types.Options{
			Hosts:         assets,
			Steps:         steps,
			Silent:        true,
			EnumerationID: enumID,
			TeamID:        r.options.TeamID,
			Output:        outputDir,
		},
		Id: metaID,
	}

	// Execute using the same pkg.Run logic as pd-agent
	// When EnumerationID is set, pkg.Run will execute enumeration tools (dnsx, naabu, httpx, etc.)
	taskResult, outputFiles, err := pkg.Run(ctx, task)
	if err != nil {
		r.logHelper("ERROR", fmt.Sprintf("Enumeration execution failed: %v", err))
		return
	}

	// Cleanup all enumeration output files immediately after processing (unless keep-output-files flag is set)
	// This prevents file accumulation during long enumerations with many chunks
	if len(outputFiles) > 0 {
		if !r.options.KeepOutputFiles {
			// Default behavior: delete files after processing
			for _, outputFile := range outputFiles {
				if outputFile != "" {
					if err := os.Remove(outputFile); err != nil {
						slog.Warn("Failed to delete enumeration output file", "file", outputFile, "error", err)
					} else {
						slog.Debug("Deleted enumeration output file after processing", "file", outputFile, "chunk_id", metaID)
					}
				}
			}
		} else {
			// Flag is set: keep files intact for debugging/analysis
			slog.Debug("Keeping enumeration output files (keep-output-files flag is set)",
				"files", outputFiles,
				"count", len(outputFiles),
				"chunk_id", metaID)
		}
	}

	if taskResult != nil {
		r.logHelper("INFO", fmt.Sprintf("Completed enumeration for enumID=%s, metaID=%s", enumID, metaID))
	} else {
		r.logHelper("INFO", fmt.Sprintf("Completed enumeration for enumID=%s, metaID=%s", enumID, metaID))
	}
}

// In handles agent registration with the punch-hole server
func (r *Runner) In(ctx context.Context) error {
	ticker := time.NewTicker(5 * time.Minute)
	defer func() {
		ticker.Stop()
		if err := r.Out(context.TODO()); err != nil {
			r.logHelper("WARNING", fmt.Sprintf("error deregistering agent: %v", err))
		} else {
			r.logHelper("INFO", "deregistered agent")
		}
	}()

	// First call: register the agent. This one is fatal — we need NATS creds.
	if err := r.inFunctionTickCallback(ctx); err != nil {
		return err
	}

	// Subsequent calls are heartbeats. Failures are logged but not fatal —
	// the agent keeps scanning via NATS even if the HTTP heartbeat is down.
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := r.inFunctionTickCallback(ctx); err != nil {
				r.logHelper("WARNING", fmt.Sprintf("/in heartbeat failed (will retry in 5m): %v", err))
			}
		}
	}
}

var isRegistered bool

// inFunctionTickCallback handles the periodic registration callback
func (r *Runner) inFunctionTickCallback(ctx context.Context) error {
	r.inRequestCount++ // increment /in request counter

	// Fetch agent info from punch_hole /agents/:id
	endpoint := fmt.Sprintf("%s/v1/agents/%s?type=agent", PdcpApiServer, r.options.AgentId)
	headers := map[string]string{"x-api-key": PDCPApiKey}
	resp := r.makeRequest(ctx, http.MethodGet, endpoint, nil, headers)
	if resp.Error != nil {
		r.logHelper("ERROR", fmt.Sprintf("failed to fetch agent info: %v", resp.Error))
		// don't return, fallback to local tags
	}

	// Default to local tags and networks
	tagsToUse := r.options.AgentTags
	networksToUse := []string{r.options.AgentNetwork}
	var lastUpdate time.Time
	if resp.Error == nil && resp.StatusCode == http.StatusOK {
		var response struct {
			Agent struct {
				Id         string    `json:"id"`
				Tags       []string  `json:"tags"`
				Networks   []string  `json:"networks"`
				LastUpdate time.Time `json:"last_update"`
				Name       string    `json:"name"`
			} `json:"agent"`
		}
		if err := json.Unmarshal(resp.Body, &response); err == nil {
			agentInfo := response.Agent
			lastUpdate = agentInfo.LastUpdate

			if len(agentInfo.Tags) > 0 && !sliceutil.Equal(tagsToUse, agentInfo.Tags) {
				r.logHelper("INFO", fmt.Sprintf("Using tags from %s server: %v (was: %v)", PdcpApiServer, agentInfo.Tags, tagsToUse))
				tagsToUse = agentInfo.Tags
				r.options.AgentTags = agentInfo.Tags // Overwrite local tags with remote
			}
			if len(agentInfo.Networks) > 0 && !sliceutil.Equal(networksToUse, agentInfo.Networks) {
				r.logHelper("INFO", fmt.Sprintf("Using networks from %s server: %v (was: %v)", PdcpApiServer, agentInfo.Networks, networksToUse))
				networksToUse = agentInfo.Networks
				if len(agentInfo.Networks) > 0 {
					r.options.AgentNetwork = agentInfo.Networks[0] // Use first network from remote
				}
			}
			// Handle agent name
			if agentInfo.Name != "" && r.options.AgentName != agentInfo.Name {
				r.logHelper("INFO", fmt.Sprintf("Using agent name from %s server: %s (was: %s)", PdcpApiServer, agentInfo.Name, r.options.AgentName))
				r.options.AgentName = agentInfo.Name
			}
			r.logHelper("DEBUG", fmt.Sprintf("Agent last updated at: %s", lastUpdate.Format(time.RFC3339)))
		}
	}

	// Build /in endpoint with query parameters.
	// Use a 30s timeout — heartbeat should be fast, don't hold up the agent.
	inCtx, inCancel := context.WithTimeout(ctx, 30*time.Second)
	defer inCancel()

	inURL := fmt.Sprintf("%s/v1/agents/in", PdcpApiServer)
	req, err := http.NewRequestWithContext(inCtx, http.MethodPost, inURL, nil)
	if err != nil {
		r.logHelper("ERROR", fmt.Sprintf("failed to create /in request: %v", err))
		return err
	}

	q := req.URL.Query()
	q.Add("os", runtime.GOOS)
	q.Add("arch", runtime.GOARCH)
	q.Add("id", r.options.AgentId)
	q.Add("name", r.options.AgentName)
	q.Add("type", "agent")
	q.Add("agent_network", r.options.AgentNetwork)

	// Only add tags if not empty
	if len(tagsToUse) > 0 {
		tagsStr := strings.Join(tagsToUse, ",")
		if tagsStr != "" {
			q.Add("tags", tagsStr)
		}
	}

	// Only add networks if not empty
	if len(networksToUse) > 0 {
		networksStr := strings.Join(networksToUse, ",")
		if networksStr != "" {
			q.Add("networks", networksStr)
		}
	}

	// Get auto-discovered network subnets and add to query parameters
	// This is fault-tolerant - if getAutoDiscoveredTargets() returns empty or nil,
	// we simply send an empty string
	networkSubnets := r.getAutoDiscoveredTargets()
	if len(networkSubnets) > 0 {
		r.logHelper("DEBUG", fmt.Sprintf("Discovered network subnets: %v", networkSubnets))
		q.Add("network_subnets", strings.Join(networkSubnets, ","))
	} else {
		r.logHelper("INFO", "No network subnets discovered")
	}

	req.URL.RawQuery = q.Encode()

	inResp := r.makeRequest(inCtx, http.MethodPost, req.URL.String(), nil, headers)
	if inResp.Error != nil {
		r.logHelper("ERROR", fmt.Sprintf("failed to call /in endpoint: %v", inResp.Error))
		return inResp.Error
	}

	if inResp.StatusCode != http.StatusOK {
		r.logHelper("ERROR", fmt.Sprintf("unexpected status code from /in endpoint: %d", inResp.StatusCode))
		return fmt.Errorf("unexpected status code from /in endpoint: %d", inResp.StatusCode)
	}

	// Parse the /in response to extract NATS credentials (if present)
	var agentInResp AgentInResponse
	if err := json.Unmarshal(inResp.Body, &agentInResp); err != nil {
		r.logHelper("WARNING", fmt.Sprintf("failed to parse /in response body: %v", err))
	} else if agentInResp.Nats == nil && r.natsCreds == nil {
		return fmt.Errorf("/in response did not include NATS credentials; agent cannot start without JetStream connectivity")
	}
	if agentInResp.Nats != nil {
		r.natsCredsMu.Lock()
		prev := r.natsCreds
		r.natsCreds = agentInResp.Nats
		r.natsCredsMu.Unlock()

		if prev == nil {
			r.logHelper("INFO", fmt.Sprintf("received NATS credentials (expires_at=%s)",
				agentInResp.Nats.ExpiresAt.Format(time.RFC3339)))
			r.onNATSCredentialsReceived(true)
		} else if !prev.ExpiresAt.Equal(agentInResp.Nats.ExpiresAt) {
			r.logHelper("INFO", fmt.Sprintf("NATS credentials refreshed (expires_at=%s)",
				agentInResp.Nats.ExpiresAt.Format(time.RFC3339)))
			r.onNATSCredentialsReceived(false)
		}
	}

	if !isRegistered {
		r.logHelper("INFO", "agent registered successfully")
		isRegistered = true
	}

	r.logHelper("DEBUG", fmt.Sprintf("/in requests sent: %d, agent up since: %s", r.inRequestCount, r.agentStartTime.Format(time.RFC3339)))
	return nil
}

// Out handles agent deregistration
func (r *Runner) Out(ctx context.Context) error {
	endpoint := fmt.Sprintf("%s/v1/agents/out?id=%s&type=agent", PdcpApiServer, r.options.AgentId)
	resp := r.makeRequest(ctx, http.MethodPost, endpoint, nil, nil)
	if resp.Error != nil {
		r.logHelper("ERROR", fmt.Sprintf("failed to call /out endpoint: %v", resp.Error))
		return resp.Error
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code from /out endpoint: %v, body: %s", resp.StatusCode, string(resp.Body))
	}

	if isRegistered {
		r.logHelper("INFO", "agent deregistered successfully")
		isRegistered = false
	}

	return nil
}

// getAutoDiscoveredTargets gets the auto discovered targets from the system (only ipv4)
func (r *Runner) getAutoDiscoveredTargets() []string {
	var targets []string
	seen := make(map[string]struct{})

	// Helper function to add CIDR if it's a private IP
	addPrivateCIDR := func(ip net.IP) {
		if ip == nil {
			return
		}
		// Convert to IPv4 if it's an IPv4-mapped IPv6 address
		if ip.To4() != nil {
			ip = ip.To4()
		}
		// Check if it's a private IP
		if ip.IsPrivate() {
			// Create /24 CIDR
			mask := net.CIDRMask(24, 32)
			maskedIP := ip.Mask(mask)
			if maskedIP == nil {
				return
			}
			cidr := &net.IPNet{
				IP:   maskedIP,
				Mask: mask,
			}
			cidrStr := cidr.String()
			// Additional safety check to prevent "<nil>" or empty strings
			if cidrStr == "" || cidrStr == "<nil>" || !strings.Contains(cidrStr, "/") {
				return
			}
			if _, exists := seen[cidrStr]; !exists {
				seen[cidrStr] = struct{}{}
				targets = append(targets, cidrStr)
			}
		}
	}

	// Get network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		r.logHelper("ERROR", fmt.Sprintf("Error getting network interfaces: %v", err))
	} else {
		for _, iface := range interfaces {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				switch v := addr.(type) {
				case *net.IPNet:
					addPrivateCIDR(v.IP)
				case *net.IPAddr:
					addPrivateCIDR(v.IP)
				}
			}
		}
	}

	// Read hosts file
	hostsFile := "/etc/hosts"
	if runtime.GOOS == "windows" {
		systemRoot := os.Getenv("SystemRoot")
		if systemRoot == "" {
			systemRoot = "C:\\Windows" // fallback
		}
		hostsFile = filepath.Join(systemRoot, "System32", "drivers", "etc", "hosts")
	}

	content, err := os.ReadFile(hostsFile)
	if err != nil {
		r.logHelper("ERROR", fmt.Sprintf("Error reading hosts file: %v", err))
	} else {
		for line := range strings.SplitSeq(string(content), "\n") {
			// Skip comments and empty lines
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			// Split line into IP and hostnames
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}

			// Parse IP address
			ip := net.ParseIP(fields[0])
			if ip != nil {
				addPrivateCIDR(ip)
			}
		}
	}

	// Detect Kubernetes environment: allow LOCAL_K8S override or auto-detect in-cluster
	_, err = os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err == nil {
		// if kubernetes environment is detected, get the subnets from the cluster (cached)
		if k8sSubnets := getCachedK8sSubnets(); len(k8sSubnets) > 0 {
			targets = appendUniqueStrings(targets, k8sSubnets)
		}
	}

	return targets
}

// appendUniqueStrings appends only strings from src that are not already present in dst.
func appendUniqueStrings(dst []string, src []string) []string {
	if len(src) == 0 {
		return dst
	}
	existing := make(map[string]struct{}, len(dst))
	for _, s := range dst {
		existing[s] = struct{}{}
	}
	for _, s := range src {
		if _, ok := existing[s]; ok {
			continue
		}
		existing[s] = struct{}{}
		dst = append(dst, s)
	}
	return dst
}

// getCachedK8sSubnets returns the cached K8s subnets, fetching them only once
func getCachedK8sSubnets() []string {
	k8sSubnetsCacheOnce.Do(func() {
		k8sSubnetsCache = getK8sSubnets()
		if len(k8sSubnetsCache) > 0 {
			slog.Debug("cached Kubernetes subnets for reuse", "count", len(k8sSubnetsCache))
		}
	})
	return k8sSubnetsCache
}

func getK8sSubnets() []string {
	var config *rest.Config
	var err error

	// Build kubeconfig based on environment
	if os.Getenv("LOCAL_K8S") == "true" {
		config, err = clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
		if err != nil {
			slog.Error("Error building kubeconfig", "error", err)
			return []string{}
		}
	} else {
		config, err = rest.InClusterConfig()
		if err != nil {
			slog.Error("Error getting in-cluster config", "error", err)
			return []string{}
		}
	}

	kubeapiClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		slog.Error("Error getting kubeapi client", "error", err)
		return []string{}
	}

	assets := make([]string, 0)

	// Get Service CIDRs
	var serviceCidrs []string
	// Try GA first
	if svcCIDRListV1, err := kubeapiClient.NetworkingV1().ServiceCIDRs().List(context.Background(), v1.ListOptions{}); err == nil {
		for _, item := range svcCIDRListV1.Items {
			serviceCidrs = append(serviceCidrs, item.Spec.CIDRs...)
		}
	} else {
		// Fallback to v1beta1
		if svcCIDRListBeta, errBeta := kubeapiClient.NetworkingV1beta1().ServiceCIDRs().List(context.Background(), v1.ListOptions{}); errBeta == nil {
			for _, item := range svcCIDRListBeta.Items {
				serviceCidrs = append(serviceCidrs, item.Spec.CIDRs...)
			}
		} else {
			slog.Debug("ServiceCIDR list failed", "v1_error", err, "v1beta1_error", errBeta)
		}
	}

	if len(serviceCidrs) > 0 {
		slog.Debug("Found service CIDRs", "count", len(serviceCidrs))
		assets = append(assets, serviceCidrs...)
	}

	// Get Cluster CIDRs (Node IPs and Pod CIDRs)
	nodes, err := kubeapiClient.CoreV1().Nodes().List(context.Background(), v1.ListOptions{})
	if err != nil {
		slog.Error("Error listing nodes to derive cluster CIDRs", "error", err)
		return assets
	}

	var nodeIPs []string
	var podCidrs []string
	seen := make(map[string]struct{})

	for _, n := range nodes.Items {
		// Collect node internal IPs as /24 CIDRs
		if len(n.Status.Addresses) > 0 {
			for _, a := range n.Status.Addresses {
				if a.Type == "InternalIP" {
					ip := net.ParseIP(a.Address)
					if ip != nil {
						ip = ip.To4()
						ipnet := &net.IPNet{
							IP:   ip,
							Mask: net.CIDRMask(24, 32),
						}
						nodeIPs = append(nodeIPs, ipnet.String())

						if _, ok := seen[a.Address]; !ok {
							seen[a.Address] = struct{}{}
						}
					}
				}
			}
		}

		// Collect pod CIDRs (prefer multi-CIDR if present)
		if len(n.Spec.PodCIDRs) > 0 {
			for _, c := range n.Spec.PodCIDRs {
				if _, ok := seen[c]; !ok && c != "" {
					seen[c] = struct{}{}
					podCidrs = append(podCidrs, c)
				}
			}
			continue
		}

		// Fallback to single PodCIDR
		if n.Spec.PodCIDR != "" {
			if _, ok := seen[n.Spec.PodCIDR]; !ok {
				seen[n.Spec.PodCIDR] = struct{}{}
				podCidrs = append(podCidrs, n.Spec.PodCIDR)
			}
		}
	}

	// Calculate supernets for node IPs and pod CIDRs
	if len(nodeIPs) > 0 {
		nodeSupernets := supernetMultiple(nodeIPs)
		slog.Debug("Aggregated node IPs into supernets", "node_count", len(nodeIPs), "supernet_count", len(nodeSupernets))
		assets = append(assets, nodeSupernets...)
	}

	if len(podCidrs) > 0 {
		podSupernets := supernetMultiple(podCidrs)
		slog.Debug("Aggregated pod CIDRs into supernets", "pod_count", len(podCidrs), "supernet_count", len(podSupernets))
		assets = append(assets, podSupernets...)
	}

	return assets
}

// supernetMultiple returns multiple supernets, avoiding wasteful large ranges
// Groups CIDRs by second octet (10.X.*.*/Y) to avoid massive supernets
func supernetMultiple(cidrs []string) []string {
	if len(cidrs) == 0 {
		return []string{}
	}
	if len(cidrs) == 1 {
		return cidrs
	}

	// Parse all CIDRs and group by second octet
	type cidrRange struct {
		cidr  string
		minIP net.IP
		maxIP net.IP
	}

	// Group by "10.X.*.*" pattern (first two octets)
	groups := make(map[string][]cidrRange)

	for _, cidr := range cidrs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}

		lastIP := make(net.IP, len(ipnet.IP))
		copy(lastIP, ipnet.IP)
		for i := range lastIP {
			lastIP[i] |= ^ipnet.Mask[i]
		}

		// Group key based on first two octets (e.g., "10.60", "10.68", "10.80")
		ip4 := ipnet.IP.To4()
		groupKey := fmt.Sprintf("%d.%d", ip4[0], ip4[1])

		groups[groupKey] = append(groups[groupKey], cidrRange{
			cidr:  cidr,
			minIP: ipnet.IP,
			maxIP: lastIP,
		})
	}

	// Calculate supernet for each group
	result := make([]string, 0, len(groups))
	for _, group := range groups {
		if len(group) == 0 {
			continue
		}

		minIP := group[0].minIP
		maxIP := group[0].maxIP

		for _, r := range group[1:] {
			if compareIP(r.minIP, minIP) < 0 {
				minIP = r.minIP
			}
			if compareIP(r.maxIP, maxIP) > 0 {
				maxIP = r.maxIP
			}
		}

		result = append(result, calculateSupernet(minIP, maxIP))
	}

	// Sort for consistent output
	sort.Strings(result)

	return result
}

func compareIP(ip1, ip2 net.IP) int {
	ip1 = ip1.To4()
	ip2 = ip2.To4()
	for i := 0; i < len(ip1); i++ {
		if ip1[i] < ip2[i] {
			return -1
		}
		if ip1[i] > ip2[i] {
			return 1
		}
	}
	return 0
}

func calculateSupernet(minIP, maxIP net.IP) string {
	minIP = minIP.To4()
	maxIP = maxIP.To4()

	// XOR to find differing bits
	var diff uint32
	for i := range 4 {
		diff = (diff << 8) | uint32(minIP[i]^maxIP[i])
	}

	// Count leading zeros to find common prefix length
	prefixLen := 32
	for diff > 0 {
		diff >>= 1
		prefixLen--
	}

	// Create mask and apply to minIP
	mask := net.CIDRMask(prefixLen, 32)
	network := minIP.Mask(mask)

	return fmt.Sprintf("%s/%d", network, prefixLen)
}

// parseOptions parses command line options (simplified for agent mode only)
func parseOptions() *Options {
	options := &Options{
		TeamID: TeamIDEnv,
	}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`pd-agent is an agent for ProjectDiscovery Cloud Platform`)

	agentTags := strings.Split(AgentTagsEnv, ",")

	// Parse default parallelism values from environment.
	// 0 means auto-detect at startup (based on available resources).
	defaultChunkParallelism := 0
	if val, err := strconv.Atoi(ChunkParallelismEnv); err == nil && val > 0 {
		defaultChunkParallelism = val
	}

	defaultScanParallelism := 1
	if val, err := strconv.Atoi(ScanParallelismEnv); err == nil && val > 0 {
		defaultScanParallelism = val
	}

	flagSet.CreateGroup("agent", "Agent",
		flagSet.BoolVar(&options.Verbose, "verbose", false, "show verbose output"),
		flagSet.BoolVar(&options.KeepOutputFiles, "keep-output-files", false, "keep output files after processing (default: false, files are deleted immediately after processing)"),
		flagSet.StringVar(&options.AgentOutput, "agent-output", "", "agent output folder"),
		flagSet.StringSliceVarP(&options.AgentTags, "agent-tags", "at", agentTags, "specify the tags for the agent", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringVarP(&options.AgentNetwork, "agent-network", "an", AgentNetworkEnv, "specify the network for the agent"),
		flagSet.StringVar(&options.AgentName, "agent-name", "", "specify the name for the agent"),
		flagSet.StringVar(&options.AgentId, "agent-id", "", "specify the agent ID (auto-generated if empty, persisted across self-updates)"),
		flagSet.BoolVar(&options.PassiveDiscovery, "passive-discovery", false, "enable passive discovery via libpcap/gopacket"),
		flagSet.IntVarP(&options.ChunkParallelism, "chunk-parallelism", "c", defaultChunkParallelism, "number of chunks to process in parallel"),
		flagSet.IntVarP(&options.ScanParallelism, "scan-parallelism", "s", defaultScanParallelism, "number of scans to process in parallel"),
	)

	if err := flagSet.Parse(); err != nil {
		slog.Error("error", "error", err)
	}

	// Parse environment variables (env vars take precedence as defaults)
	if agentTags := os.Getenv("PDCP_AGENT_TAGS"); agentTags != "" && len(options.AgentTags) == 0 {
		options.AgentTags = goflags.StringSlice(strings.Split(agentTags, ","))
	}
	if agentNetwork := os.Getenv("PDCP_AGENT_NETWORK"); agentNetwork != "" && options.AgentNetwork == "" {
		options.AgentNetwork = agentNetwork
	}
	if agentOutput := os.Getenv("PDCP_AGENT_OUTPUT"); agentOutput != "" && options.AgentOutput == "" {
		options.AgentOutput = agentOutput
	}
	if agentName := os.Getenv("PDCP_AGENT_NAME"); agentName != "" && options.AgentName == "" {
		options.AgentName = agentName
	}
	if agentNetwork := os.Getenv("AGENT_NETWORK"); agentNetwork != "" && options.AgentNetwork == "" {
		options.AgentNetwork = agentNetwork
	}
	if verbose := os.Getenv("PDCP_VERBOSE"); (verbose == "true" || verbose == "1") && !options.Verbose {
		options.Verbose = true
	}

	// Parse keep-output-files from environment variable
	if keepOutputFiles := os.Getenv("PDCP_KEEP_OUTPUT_FILES"); keepOutputFiles == "true" || keepOutputFiles == "1" {
		options.KeepOutputFiles = true
	}

	// Note: AgentName initialization moved to NewRunner() after AgentId generation

	configureLogging(options)

	// Also support env variable PASSIVE_DISCOVERY
	if os.Getenv("PASSIVE_DISCOVERY") == "1" || os.Getenv("PASSIVE_DISCOVERY") == "true" {
		options.PassiveDiscovery = true
	}

	// Ensure agent network has a default value
	if options.AgentNetwork == "" {
		options.AgentNetwork = "default"
	}

	// Ensure parallelism values are valid (0 = auto-detect for chunks).
	if options.ChunkParallelism < 0 {
		options.ChunkParallelism = 0
	}
	if options.ScanParallelism < 1 {
		options.ScanParallelism = 1
	}

	return options
}

func configureLogging(options *Options) {
	initLogging(options.Verbose)
	if options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
}

func main() {
	// Capture panics into slog (and therefore SQLite) before the process dies.
	var pdcpRunner *Runner
	defer func() {
		if r := recover(); r != nil {
			msg := fmt.Sprintf("panic: %v\n%s", r, debug.Stack())
			slog.Error(msg)
			// Synchronous direct insert — async channel won't flush in time.
			if dbWriterInstance != nil && pdcpRunner != nil && pdcpRunner.agentDB != nil {
				dbWriterInstance.DirectWrite(pdcpRunner.agentDB, msg)
			}
			if dbWriterInstance != nil {
				dbWriterInstance.StopLogWriter()
			}
			os.Exit(2)
		}
	}()

	// Handle -version flag before anything else.
	for _, arg := range os.Args[1:] {
		if arg == "-version" || arg == "--version" {
			fmt.Println(Version)
			os.Exit(0)
		}
	}

	// Set GOMAXPROCS from cgroup CPU quota (containers). No-op on bare metal.
	_, _ = maxprocs.Set(maxprocs.Logger(func(format string, args ...any) {
		slog.Info(fmt.Sprintf(format, args...))
	}))

	options := parseOptions()

	// Self-update preflight: a parent process is probing this binary with the
	// exact restart args before swapping. Exit 0 cleanly here so the parent
	// knows the binary accepts these args. Stay above any code that touches
	// shared state (DB, NATS) to avoid conflicting with the still-running agent.
	if os.Getenv(selfupdate.PreflightEnvVar) == "1" {
		fmt.Println("preflight ok")
		os.Exit(0)
	}

	// Check prerequisites — auto-install missing tools (idempotent: fast on restart)
	if failed := prereq.EnsureAll(); len(failed) > 0 {
		slog.Error("Could not install required tools", "tools", strings.Join(failed, ", "))
		os.Exit(1)
	}

	// Ensure nuclei templates are downloaded or updated before starting the agent
	ensureNucleiTemplates()

	var err error
	pdcpRunner, err = NewRunner(options)
	if err != nil {
		slog.Error("Could not create runner", "error", err)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown: on SIGTERM/SIGINT, cancel contexts and let
	// agentMode's defer handle the blocking wait and cleanup.
	// k8s sends SIGTERM once, then SIGKILL after terminationGracePeriodSeconds.
	go func() {
		<-c
		slog.Info("shutdown signal received, draining in-flight work...")
		if jsCancel := pdcpRunner.jsCancel.Load(); jsCancel != nil {
			(*jsCancel)()
		}
		// Cancel the main context — agentMode's defer will call jsPool.Stop()
		// and wait for in-flight work before cleaning up NATS/batchers.
		cancel()
	}()

	err = pdcpRunner.Run(ctx)

	// Upload debug DB to GCS (best-effort), then close.
	// All writers are stopped (agentMode defer ran), so WAL checkpoint is safe.
	if pdcpRunner.agentDB != nil {
		pdcpRunner.uploadDebugDB()
		pdcpRunner.agentDB.Close()
		pdcpRunner.agentDB = nil
	}

	if err != nil {
		pdcpRunner.logHelper("FATAL", fmt.Sprintf("Could not run pd-agent: %s", err))
		os.Exit(1)
	}
}

// uploadDebugDB uploads the local SQLite DB to GCS using the pre-generated
// presigned URL from the last /in response. Best-effort: logs errors but
// never blocks shutdown. Must be called after all DB writers have stopped.
//
// Set PDCP_DISABLE_DIAGNOSTIC_UPLOAD=1 (or true) to opt out.
func (r *Runner) uploadDebugDB() {
	if v := os.Getenv("PDCP_DISABLE_DIAGNOSTIC_UPLOAD"); v == "1" || v == "true" {
		slog.Info("agentdb: diagnostic upload disabled via PDCP_DISABLE_DIAGNOSTIC_UPLOAD")
		return
	}

	r.natsCredsMu.RLock()
	creds := r.natsCreds
	r.natsCredsMu.RUnlock()

	if creds == nil || creds.DebugUploadURL == "" {
		slog.Debug("agentdb: no debug upload URL, skipping DB upload")
		return
	}
	if time.Now().After(creds.DebugUploadExpiresAt) {
		slog.Warn("agentdb: debug upload URL expired, skipping",
			"expired_at", creds.DebugUploadExpiresAt.Format(time.RFC3339))
		return
	}

	sqlStore, ok := r.agentDB.(*agentdb.SQLiteStore)
	if !ok {
		return
	}

	if err := sqlStore.CheckpointWAL(); err != nil {
		slog.Warn("agentdb: WAL checkpoint failed, skipping upload", "error", err)
		return
	}

	f, err := os.Open(sqlStore.DBPath())
	if err != nil {
		slog.Warn("agentdb: failed to open DB for upload", "error", err)
		return
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		slog.Warn("agentdb: failed to stat DB", "error", err)
		return
	}

	uploadCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(uploadCtx, http.MethodPut, creds.DebugUploadURL, f)
	if err != nil {
		slog.Warn("agentdb: failed to create upload request", "error", err)
		return
	}
	req.ContentLength = fi.Size()
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Goog-Content-Length-Range", "0,52428800")

	slog.Info("agentdb: uploading debug DB", "size_bytes", fi.Size())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		slog.Warn("agentdb: debug DB upload failed", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		slog.Warn("agentdb: debug DB upload non-200",
			"status", resp.StatusCode, "body", string(body))
		return
	}

	slog.Info("agentdb: debug DB uploaded successfully", "size_bytes", fi.Size())
}

// warnOrphanDBs logs a warning if other pd-agent DB files exist in the directory
// and deletes orphan DBs (plus WAL/SHM sidecars) older than 7 days.
func warnOrphanDBs(dir, myAgentID string) {
	matches, err := filepath.Glob(filepath.Join(dir, "pd-agent-*.db"))
	if err != nil {
		return
	}
	myFile := fmt.Sprintf("pd-agent-%s.db", myAgentID)
	var orphans []string
	for _, m := range matches {
		base := filepath.Base(m)
		if base == myFile {
			continue
		}
		orphans = append(orphans, base)

		fi, err := os.Stat(m)
		if err != nil {
			continue
		}
		if time.Since(fi.ModTime()) > 7*24*time.Hour {
			for _, suffix := range []string{"", "-wal", "-shm"} {
				os.Remove(m + suffix)
			}
			slog.Info("agentdb: deleted orphan DB", "file", base,
				"age", time.Since(fi.ModTime()).Round(time.Hour))
		}
	}
	if len(orphans) > 0 {
		slog.Warn("agentdb: found other agent DB files", "count", len(orphans), "files", orphans)
	}
}
