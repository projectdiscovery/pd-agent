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
	"github.com/projectdiscovery/pd-agent/pkg/envconfig"
	"github.com/projectdiscovery/pd-agent/pkg/natsrpc"
	"github.com/projectdiscovery/pd-agent/pkg/prereq"
	"github.com/projectdiscovery/pd-agent/pkg/resourceprofile"
	"github.com/projectdiscovery/pd-agent/pkg/runtools"
	"github.com/projectdiscovery/pd-agent/pkg/selfupdate"
	"github.com/projectdiscovery/pd-agent/pkg/types"
	fileutil "github.com/projectdiscovery/utils/file"
	sliceutil "github.com/projectdiscovery/utils/slice"
	"github.com/rs/xid"
	"github.com/tidwall/gjson"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// ensureNucleiTemplates installs or updates nuclei templates. Stale templates
// cause "file not found" errors when the cloud sends paths missing locally.
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

// Version is set at build time via -ldflags "-X main.Version=v1.0.0".
var Version = "dev"

// Options holds the agent's runtime configuration.
type Options struct {
	TeamID           string
	AgentId          string
	AgentTags        goflags.StringSlice
	AgentNetwork     string
	AgentOutput      string
	AgentName        string
	Verbose          bool
	ChunkParallelism int
	ScanParallelism  int
	KeepOutputFiles  bool
}

// Response is a minimal HTTP response.
type Response struct {
	StatusCode int
	Body       []byte
	Error      error
}

// makeRequest sends an HTTP request with up to 5 retries on transient errors.
func (r *Runner) makeRequest(ctx context.Context, method, url string, body io.Reader, headers map[string]string) *Response {
	// Buffer body so it can be replayed on retry.
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
		client, err := client.CreateAuthenticatedClient(r.options.TeamID, envconfig.APIKey())
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

// NATSCredentials is the connection metadata returned by the /in endpoint.
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

// AgentInResponse is the response body from POST /v1/agents/in.
type AgentInResponse struct {
	Message string           `json:"message"`
	Nats    *NATSCredentials `json:"nats,omitempty"`
}

// Runner is the agent's stateful core.
type Runner struct {
	options        *Options
	inRequestCount int
	agentStartTime time.Time

	natsCreds   *NATSCredentials
	natsCredsMu sync.RWMutex

	// Lifecycle context, cancelled on shutdown.
	ctx       context.Context
	cancelCtx context.CancelFunc

	natsConn    *nats.Conn
	natsSubs    []*nats.Subscription
	natsConnMu  sync.Mutex
	natsStarted bool

	jsPool   atomic.Pointer[natsrpc.WorkerPool]
	jsCancel atomic.Pointer[context.CancelFunc]

	// scanSem is fixed at NumCPU: nuclei is heavy and warms up slowly, so
	// letting the adaptive scaler ramp before steady-state causes
	// oversubscription. chunkSem (enumeration) is adaptive since discovery
	// work is short and resource-light.
	scanSem     atomic.Pointer[resourceprofile.ResizableSemaphore]
	chunkSem    atomic.Pointer[resourceprofile.ResizableSemaphore]
	chunkScaler atomic.Pointer[resourceprofile.Scaler]

	groupMetrics atomic.Pointer[natsrpc.GroupMetricsCollector]

	// ActiveTasks cache absorbs bursty health-check/debug RPCs.
	activeTasksCache atomic.Pointer[activeTasksCacheEntry]

	// agentDB is nil when local persistence failed to initialise.
	agentDB agentdb.Store

	restartRequested atomic.Bool
}

var (
	k8sSubnetsCache     []string
	k8sSubnetsCacheOnce sync.Once
)

type activeTasksCacheEntry struct {
	tasks     []agentdb.Task
	expiresAt time.Time
}

// getActiveTasksCached returns ActiveTasks cached for 2s to absorb burst RPCs.
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

// logHelper routes a tagged level string to slog. agentLogHandler tees output
// to console, ring buffer, and SQLite.
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

// NewRunner builds a Runner and opens local persistence.
func NewRunner(options *Options) (*Runner, error) {
	r := &Runner{
		options:        options,
		agentStartTime: time.Now(),
	}

	if r.options.AgentId == "" {
		r.options.AgentId = xid.New().String()
	} else {
		if _, err := xid.FromString(r.options.AgentId); err != nil {
			slog.Error("invalid agent ID (must be a valid xid)", "agent_id", r.options.AgentId, "error", err)
			os.Exit(1)
		}
	}

	if r.options.AgentName == "" {
		if hostname, err := os.Hostname(); err == nil && hostname != "" {
			r.options.AgentName = hostname
		} else {
			r.options.AgentName = r.options.AgentId
		}
	}

	// agentdb is opened best-effort: agent keeps running without persistence
	// if every fallback fails. Order: PDCP_AGENTDB_DIR, ~/.pd-agent, binary dir.
	dbDir := envconfig.AgentDBDir()
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

	return r, nil
}

// GetNATSCredentials returns the current NATS credentials, or nil if none.
func (r *Runner) GetNATSCredentials() *NATSCredentials {
	r.natsCredsMu.RLock()
	defer r.natsCredsMu.RUnlock()
	return r.natsCreds
}

// extractJWT parses the JWT from a NATS .creds string.
func extractJWT(credsContent string) (string, error) {
	return nkeys.ParseDecoratedJWT([]byte(credsContent))
}

// signNonce signs nonce with the NKey seed from a NATS .creds string and wipes the seed.
func signNonce(credsContent string, nonce []byte) ([]byte, error) {
	kp, err := nkeys.ParseDecoratedNKey([]byte(credsContent))
	if err != nil {
		return nil, fmt.Errorf("failed to parse nkey seed: %w", err)
	}
	defer kp.Wipe()
	return kp.Sign(nonce)
}

// startNATSRPC connects, wires routers, and subscribes; replaces any existing connection.
func (r *Runner) startNATSRPC() error {
	creds := r.GetNATSCredentials()
	if creds == nil {
		return fmt.Errorf("no NATS credentials available")
	}

	// JWT callbacks read from memory on every connect/reconnect: no temp
	// files, hot-swap on refresh.
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

// stopNATSRPC drains and closes the NATS connection.
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

// onNATSCredentialsReceived starts or reconnects the NATS RPC layer when
// credentials arrive or change.
func (r *Runner) onNATSCredentialsReceived(isNew bool) {
	if isNew {
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

	// Force reconnect so the JWT callbacks fire and pick up the refreshed creds.
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

	// httpx SDK only reads targets from a file.
	f, err := os.CreateTemp("", "httpx-targets-*.txt")
	if err != nil {
		return nil, fmt.Errorf("httpx: create temp file: %w", err)
	}
	defer os.Remove(f.Name())
	fmt.Fprintln(f, req.Target)
	f.Close()

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

	sdkOpts := []nuclei.NucleiSDKOptions{
		nuclei.DisableUpdateCheck(),
		nuclei.WithVerbosity(nuclei.VerbosityOptions{Silent: true}),
	}

	// Template source priority: encoded > url > id.
	switch {
	case req.TemplateEncoded != "":
		// SDK only accepts file paths, not bytes.
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
		sdkOpts = append(sdkOpts, nuclei.WithTemplateFilters(nuclei.TemplateFilters{
			IDs: []string{req.TemplateID},
		}))
	}

	execCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	ne, err := nuclei.NewNucleiEngineCtx(execCtx, sdkOpts...)
	if err != nil {
		return nil, fmt.Errorf("nuclei-retest: engine init: %w", err)
	}

	ne.LoadTargets(req.Targets, false)

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

	// Close before reading results: triggers the interactsh cooldown (final
	// poll for OOB interactions). The callback is still registered, so
	// late matches land in results.
	ne.Close()

	var result *output.ResultEvent
	if len(results) > 0 {
		result = results[0]
	} else {
		result = &output.ResultEvent{
			MatcherStatus: false,
		}
	}

	if req.TemplateEncoded != "" {
		result.TemplateEncoded = req.TemplateEncoded
	}

	// Interaction may carry raw bytes from interactsh DNS responses that fail
	// JSON marshal with control-char errors.
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
			TasksRunning:  0,
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
		// Let the NATS response flush before SIGINT.
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
			// Let the NATS response flush before tearing down.
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

	if selfupdate.IsContainer() {
		result.Status = "skipped"
		result.Message = "running in a container, update the image instead of self-updating"
		return result, nil
	}
	if req.Version == Version {
		result.Status = "skipped"
		result.Message = fmt.Sprintf("already running %s", Version)
		return result, nil
	}

	// Run in a detached goroutine: handler ctx is cancelled once the response
	// is sent, but the download must keep running. Download + verify happen
	// before drain, so any failure leaves the agent fully operational.
	go func() {
		time.Sleep(500 * time.Millisecond)

		dlCtx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()

		r.logHelper("INFO", "selfupdate: downloading and verifying new binary...")
		newBinary, err := selfupdate.DownloadAndVerify(dlCtx, Version, req.Version)
		if err != nil {
			r.logHelper("ERROR", fmt.Sprintf("selfupdate failed: %v", err))
			return
		}

		// Preflight catches "new binary doesn't recognize an existing flag"
		// before we drain and commit to swapping.
		if err := selfupdate.Prevalidate(newBinary, r.options.AgentId); err != nil {
			r.logHelper("ERROR", fmt.Sprintf("selfupdate aborted at preflight: %v", err))
			_ = os.Remove(newBinary)
			return
		}

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
			// NATS is already drained; restart in place to reconnect on the
			// same (old) binary.
			r.logHelper("INFO", "selfupdate: restarting agent to recover NATS connection...")
			execPath, _ := os.Executable()
			_ = syscall.Exec(execPath, os.Args, os.Environ())
			return
		}
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

// handleMetrics returns time-series resource metrics for graphing.
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

	samples, err := r.agentDB.QueryMetrics(context.Background(), since, until, 0)
	if err != nil {
		return nil, fmt.Errorf("query metrics: %w", err)
	}

	total := len(samples)

	// Downsample to ~360 points.
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

// handleGroupMetrics returns the JetStream chunk backlog. All agents in the
// same group share a stream and return identical numbers, so any one agent
// can drive an HPA-style scaling decision.
func (r *Runner) handleGroupMetrics(ctx context.Context, method string, data []byte) (any, error) {
	collector := r.groupMetrics.Load()
	if collector == nil {
		return nil, fmt.Errorf("group metrics not initialised (NATS not yet ready)")
	}
	return collector.Get(ctx), nil
}

// --- JetStream Work Distribution ---

// startJetStreamWorkers binds the JetStream worker pool to the group stream
// with a FilterSubject of groupPrefix.work.>.
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

	chunkSem := resourceprofile.NewResizableSemaphore(chunkParallelism, resourceprofile.MaxParallelism)
	chunkScaler := resourceprofile.NewScaler(chunkSem)
	r.chunkSem.Store(chunkSem)
	r.chunkScaler.Store(chunkScaler)

	// Initial == max so the scaler can't grow the scan semaphore.
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

	go chunkScaler.Run(ctx)

	r.groupMetrics.Store(natsrpc.NewGroupMetricsCollector(pool.JS(), creds.Stream, consumerName, 5*time.Second))

	r.logHelper("INFO", fmt.Sprintf("JetStream workers started (scan_parallelism=%d, scan_chunk_parallelism=%d, enum_chunk_parallelism=%d, source=%s, stream=%s, consumer=%s, filter=%s.work.>)",
		r.options.ScanParallelism, scanChunkParallelism, chunkParallelism, source, creds.Stream, consumerName, creds.GroupPrefix))

	return nil
}

// processWorkMessage dispatches a work message to scan or enumeration.
func (r *Runner) processWorkMessage(ctx context.Context, msg jetstream.Msg, work *natsrpc.WorkMessage) error {
	switch work.Type {
	case "scan":
		return r.processJetStreamScan(ctx, work)
	case "enumeration":
		return r.processJetStreamEnumeration(ctx, work)
	default:
		slog.Error("jetstream: skipping work message with unknown type",
			"type", work.Type,
			"id", work.ScanID,
			"chunk_subject", work.ChunkSubject,
		)
		// Term so the bad message isn't redelivered; nil so the worker
		// doesn't Nak on top of it.
		_ = msg.Term()
		return nil
	}
}

func (r *Runner) processJetStreamScan(ctx context.Context, work *natsrpc.WorkMessage) error {
	r.logHelper("INFO", fmt.Sprintf("JetStream: processing scan %s (chunk_subject=%s)", work.ScanID, work.ChunkSubject))

	if r.agentDB != nil {
		_ = r.agentDB.InsertTask(context.Background(), &agentdb.Task{Type: "scan", TaskID: work.ScanID})
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
		scanSem := r.scanSem.Load()
		if scanSem == nil {
			return fmt.Errorf("scan semaphore not initialized")
		}
		// Scan path has no scaler: nuclei warmup confuses pressure measurement.
		return natsrpc.ConsumeChunks(ctx, pool.JS(), creds.Stream, chunkConsumer, work.ChunkSubject, scanSem.Size(),
			scanSem, nil,
			func(ctx context.Context, chunk *natsrpc.ChunkMessage) error {
				r.executeNucleiScan(ctx, work.ScanID, chunk.ChunkID, work.Config, work.ReportConfig, work.HistoryID, chunk.PublicTemplates, chunk.PrivateTemplates, chunk.Targets)
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
		// A typed-nil *Scaler in an interface is non-nil; convert explicitly
		// so ConsumeChunks's nil-guard works.
		var scaler natsrpc.ChunkScaler
		if s := r.chunkScaler.Load(); s != nil {
			scaler = s
		}
		return natsrpc.ConsumeChunks(ctx, pool.JS(), creds.Stream, chunkConsumer, work.ChunkSubject, r.options.ChunkParallelism,
			r.chunkSem.Load(), scaler,
			func(ctx context.Context, chunk *natsrpc.ChunkMessage) error {
				// Steps live either on the work message or inside the chunk's
				// enrichment_steps JSON field.
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

// Run starts the agent.
func (r *Runner) Run(ctx context.Context) error {
	for {
		var infoMessage strings.Builder
		fmt.Fprintf(&infoMessage, "pd-agent %s, running in agent mode", Version)
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

	// Clear NATS state so the next credential receipt triggers a fresh startNATSRPC.
	r.natsConnMu.Lock()
	r.natsConn = nil
	r.natsSubs = nil
	r.natsStarted = false
	r.natsConnMu.Unlock()

	// Force the isNew=true path in inFunctionTickCallback.
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

// agentMode runs the agent in monitoring mode.
func (r *Runner) agentMode(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	r.ctx = ctx
	r.cancelCtx = cancel

	var agentLogWriter *agentdb.LogWriter

	// Prometheus is opt-in via PDCP_METRICS_ADDR; start it early so /healthz
	// is reachable before JS workers come up.
	promServer, err := r.startPrometheusServer(ctx)
	if err != nil {
		slog.Warn("prometheus: failed to start", "error", err)
	}

	defer func() {
		cancel()
		// Drain JetStream workers before NATS so in-progress scans finish.
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
		r.stopNATSRPC()
		// StopLogWriter clears the writer under mutex first, so late writers
		// fall back to the synchronous store path.
		if dbWriterInstance != nil {
			dbWriterInstance.StopLogWriter()
		}
		agentLogWriter = nil
		// DB stays open across restarts; main() closes it after Run returns
		// so panic recovery can still write.
	}()

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

			// Async log writer runs independently of ctx so shutdown logs are
			// captured; the defer above stops it explicitly.
			agentLogWriter = agentdb.NewLogWriter(sqlStore)
			go agentLogWriter.Run()
			if dbWriterInstance != nil {
				dbWriterInstance.SetStore(sqlStore)
				dbWriterInstance.SetLogWriter(agentLogWriter)
			}
		}
	}

	// Resource profiler samples every minute. activeWorkers is a no-op until
	// JetStream workers start and wire up to scanSem/chunkSem.
	resourceprofile.LogStartupResources()
	profiler := resourceprofile.New(1*time.Minute, func() int32 {
		// Report chunk-level concurrency (active scans + enrichments).
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

	r.logHelper("INFO", "using JetStream for work distribution")

	// Drop the .old self-update backup after 60s of healthy uptime. If the
	// agent dies before then the backup stays for manual rollback.
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

	<-ctx.Done()
	return nil
}

// executeNucleiScan runs a single nuclei chunk. privateTemplates entries
// (base64 YAML keyed by name) are written to a per-chunk temp dir, appended
// to the template list, and cleaned up on return.
func (r *Runner) executeNucleiScan(ctx context.Context, scanID, metaID, config, reportConfig string, historyID int64, templates []string, privateTemplates map[string]string, assets []string) {
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

	// Use only templates the chunk supplied. A chunk with neither public nor
	// private templates is a server-side bug; refuse rather than fall back
	// to "all default templates".
	templatesToUse := append([]string(nil), templates...)

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

	var outputDir string
	if r.options.AgentOutput != "" {
		outputDir = filepath.Join(r.options.AgentOutput, metaID)
	}

	tmpInputFile, err := fileutil.GetTempFileName()
	if err != nil {
		slog.Error("Failed to create temp file for targets", slog.Any("error", err))
		return
	}
	defer func() {
		_ = os.RemoveAll(tmpInputFile)
	}()

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

	templatesContent := strings.Join(templatesToUse, "\n")
	if err := os.WriteFile(tmpTemplatesFile, []byte(templatesContent), os.ModePerm); err != nil {
		slog.Error("Failed to write templates to temp file", "error", err)
		return
	}

	filteredTargets, extractedPorts, err := pkg.FilterTargetsByTemplatePorts(ctx, tmpInputFile, tmpTemplatesFile, scanID, metaID)
	if err != nil {
		slog.Warn("Error filtering targets by template ports, proceeding with all targets", "error", err)
		filteredTargets = assets
	}

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
			Hosts:        filteredTargets,
			Templates:    templatesToUse,
			Silent:       true,
			ScanID:       scanID,
			Config:       config,
			ReportConfig: reportConfig,
			HistoryID:    historyID,
			TeamID:       r.options.TeamID,
			Output:       outputDir,
		},
		Id: metaID,
	}

	slog.Info("Starting nuclei scan",
		"scan_id", scanID,
		"chunk_id", metaID,
		"targets", len(filteredTargets),
		"templates", len(templatesToUse),
		"extracted_ports", extractedPorts,
	)

	// Hard cap so a hanging nuclei doesn't block the semaphore forever; the
	// chunk is nak'd on timeout.
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

	var outputFile string
	if len(outputFiles) > 0 {
		outputFile = outputFiles[0]
	}

	slog.Info("Nuclei scan completed",
		"scan_id", scanID,
		"chunk_id", metaID,
		"output_files", len(outputFiles),
	)

	if outputFile != "" {
		if !r.options.KeepOutputFiles {
			if err := os.Remove(outputFile); err != nil {
				slog.Warn("Failed to delete scan output file", "file", outputFile, "error", err)
			} else {
				slog.Debug("Deleted scan output file after processing", "file", outputFile, "chunk_id", metaID)
			}
		} else {
			slog.Debug("Keeping scan output file (keep-output-files flag is set)", "file", outputFile, "chunk_id", metaID)
		}
	}

	if taskResult != nil {
		r.logHelper("INFO", fmt.Sprintf("Completed nuclei scan for scanID=%s, metaID=%s", scanID, metaID))
	} else {
		r.logHelper("INFO", fmt.Sprintf("Completed nuclei scan for scanID=%s, metaID=%s", scanID, metaID))
	}
}

// executeEnumeration runs an enumeration chunk through pkg.Run.
func (r *Runner) executeEnumeration(ctx context.Context, enumID, metaID string, steps, assets []string) {
	r.logHelper("INFO", fmt.Sprintf("Starting enumeration for enumID=%s, metaID=%s, steps=%d, assets=%d", enumID, metaID, len(steps), len(assets)))

	var outputDir string
	if r.options.AgentOutput != "" {
		outputDir = filepath.Join(r.options.AgentOutput, metaID)
	}

	// pkg.Run dispatches on EnumerationID, so the Tool field is irrelevant.
	task := &types.Task{
		Tool: types.Nuclei,
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

	taskResult, outputFiles, err := pkg.Run(ctx, task)
	if err != nil {
		r.logHelper("ERROR", fmt.Sprintf("Enumeration execution failed: %v", err))
		return
	}

	if len(outputFiles) > 0 {
		if !r.options.KeepOutputFiles {
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

// In registers the agent and runs the heartbeat loop.
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

	// First call is fatal: NATS creds come from /in.
	if err := r.inFunctionTickCallback(ctx); err != nil {
		return err
	}

	// Subsequent calls are heartbeats; failures are logged but not fatal.
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

// inFunctionTickCallback runs one /in registration cycle.
func (r *Runner) inFunctionTickCallback(ctx context.Context) error {
	r.inRequestCount++

	endpoint := fmt.Sprintf("%s/v1/agents/%s?type=agent", envconfig.APIServer(), r.options.AgentId)
	headers := map[string]string{"x-api-key": envconfig.APIKey()}
	resp := r.makeRequest(ctx, http.MethodGet, endpoint, nil, headers)
	if resp.Error != nil {
		// Non-fatal: fall back to local tags below.
		r.logHelper("ERROR", fmt.Sprintf("failed to fetch agent info: %v", resp.Error))
	}

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
				r.logHelper("INFO", fmt.Sprintf("Using tags from %s server: %v (was: %v)", envconfig.APIServer(), agentInfo.Tags, tagsToUse))
				tagsToUse = agentInfo.Tags
				r.options.AgentTags = agentInfo.Tags
			}
			if len(agentInfo.Networks) > 0 && !sliceutil.Equal(networksToUse, agentInfo.Networks) {
				r.logHelper("INFO", fmt.Sprintf("Using networks from %s server: %v (was: %v)", envconfig.APIServer(), agentInfo.Networks, networksToUse))
				networksToUse = agentInfo.Networks
				if len(agentInfo.Networks) > 0 {
					r.options.AgentNetwork = agentInfo.Networks[0]
				}
			}
			if agentInfo.Name != "" && r.options.AgentName != agentInfo.Name {
				r.logHelper("INFO", fmt.Sprintf("Using agent name from %s server: %s (was: %s)", envconfig.APIServer(), agentInfo.Name, r.options.AgentName))
				r.options.AgentName = agentInfo.Name
			}
			r.logHelper("DEBUG", fmt.Sprintf("Agent last updated at: %s", lastUpdate.Format(time.RFC3339)))
		}
	}

	// Heartbeat must be fast: 30s cap so it doesn't stall the agent.
	inCtx, inCancel := context.WithTimeout(ctx, 30*time.Second)
	defer inCancel()

	inURL := fmt.Sprintf("%s/v1/agents/in", envconfig.APIServer())
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

	if len(tagsToUse) > 0 {
		tagsStr := strings.Join(tagsToUse, ",")
		if tagsStr != "" {
			q.Add("tags", tagsStr)
		}
	}

	if len(networksToUse) > 0 {
		networksStr := strings.Join(networksToUse, ",")
		if networksStr != "" {
			q.Add("networks", networksStr)
		}
	}

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

// Out deregisters the agent.
func (r *Runner) Out(ctx context.Context) error {
	endpoint := fmt.Sprintf("%s/v1/agents/out?id=%s&type=agent", envconfig.APIServer(), r.options.AgentId)
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

// getAutoDiscoveredTargets returns IPv4 private CIDRs detected on local interfaces.
func (r *Runner) getAutoDiscoveredTargets() []string {
	var targets []string
	seen := make(map[string]struct{})

	addPrivateCIDR := func(ip net.IP) {
		if ip == nil {
			return
		}
		if ip.To4() != nil {
			ip = ip.To4()
		}
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

	hostsFile := "/etc/hosts"
	if runtime.GOOS == "windows" {
		systemRoot := os.Getenv("SystemRoot")
		if systemRoot == "" {
			systemRoot = "C:\\Windows"
		}
		hostsFile = filepath.Join(systemRoot, "System32", "drivers", "etc", "hosts")
	}

	content, err := os.ReadFile(hostsFile)
	if err != nil {
		r.logHelper("ERROR", fmt.Sprintf("Error reading hosts file: %v", err))
	} else {
		for line := range strings.SplitSeq(string(content), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}

			ip := net.ParseIP(fields[0])
			if ip != nil {
				addPrivateCIDR(ip)
			}
		}
	}

	// In-cluster service-account token signals a Kubernetes environment.
	_, err = os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err == nil {
		if k8sSubnets := getCachedK8sSubnets(); len(k8sSubnets) > 0 {
			targets = appendUniqueStrings(targets, k8sSubnets)
		}
	}

	return targets
}

// appendUniqueStrings appends entries from src not already in dst.
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

// getCachedK8sSubnets returns the K8s subnets, fetching them once.
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

	if envconfig.LocalK8s() {
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

	var serviceCidrs []string
	if svcCIDRListV1, err := kubeapiClient.NetworkingV1().ServiceCIDRs().List(context.Background(), v1.ListOptions{}); err == nil {
		for _, item := range svcCIDRListV1.Items {
			serviceCidrs = append(serviceCidrs, item.Spec.CIDRs...)
		}
	} else {
		// v1beta1 fallback for older clusters.
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

	nodes, err := kubeapiClient.CoreV1().Nodes().List(context.Background(), v1.ListOptions{})
	if err != nil {
		slog.Error("Error listing nodes to derive cluster CIDRs", "error", err)
		return assets
	}

	var nodeIPs []string
	var podCidrs []string
	seen := make(map[string]struct{})

	for _, n := range nodes.Items {
		// Use node internal IPs as /24 CIDRs.
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

		// Prefer multi-CIDR over the legacy single PodCIDR field.
		if len(n.Spec.PodCIDRs) > 0 {
			for _, c := range n.Spec.PodCIDRs {
				if _, ok := seen[c]; !ok && c != "" {
					seen[c] = struct{}{}
					podCidrs = append(podCidrs, c)
				}
			}
			continue
		}

		if n.Spec.PodCIDR != "" {
			if _, ok := seen[n.Spec.PodCIDR]; !ok {
				seen[n.Spec.PodCIDR] = struct{}{}
				podCidrs = append(podCidrs, n.Spec.PodCIDR)
			}
		}
	}

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

// supernetMultiple groups CIDRs by the first two octets and supernets each
// group separately, avoiding one wastefully large aggregate.
func supernetMultiple(cidrs []string) []string {
	if len(cidrs) == 0 {
		return []string{}
	}
	if len(cidrs) == 1 {
		return cidrs
	}

	type cidrRange struct {
		cidr  string
		minIP net.IP
		maxIP net.IP
	}

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

		ip4 := ipnet.IP.To4()
		groupKey := fmt.Sprintf("%d.%d", ip4[0], ip4[1])

		groups[groupKey] = append(groups[groupKey], cidrRange{
			cidr:  cidr,
			minIP: ipnet.IP,
			maxIP: lastIP,
		})
	}

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

	var diff uint32
	for i := range 4 {
		diff = (diff << 8) | uint32(minIP[i]^maxIP[i])
	}

	prefixLen := 32
	for diff > 0 {
		diff >>= 1
		prefixLen--
	}

	mask := net.CIDRMask(prefixLen, 32)
	network := minIP.Mask(mask)

	return fmt.Sprintf("%s/%d", network, prefixLen)
}

// parseOptions builds the runtime Options from flags and env.
func parseOptions() *Options {
	options := &Options{
		TeamID: envconfig.TeamID(),
	}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`pd-agent is an agent for ProjectDiscovery Cloud Platform`)

	agentTags := strings.Split(envconfig.AgentTagsOrDefault(), ",")

	// 0 means auto-detect at startup based on available resources.
	defaultChunkParallelism := 0
	if val, err := strconv.Atoi(envconfig.ChunkParallelism()); err == nil && val > 0 {
		defaultChunkParallelism = val
	}

	defaultScanParallelism := 1
	if val, err := strconv.Atoi(envconfig.ScanParallelism()); err == nil && val > 0 {
		defaultScanParallelism = val
	}

	flagSet.CreateGroup("agent", "Agent",
		flagSet.BoolVar(&options.Verbose, "verbose", false, "show verbose output"),
		flagSet.BoolVar(&options.KeepOutputFiles, "keep-output-files", false, "keep output files after processing (default: false, files are deleted immediately after processing)"),
		flagSet.StringVar(&options.AgentOutput, "agent-output", "", "agent output folder"),
		flagSet.StringSliceVarP(&options.AgentTags, "agent-tags", "at", agentTags, "specify the tags for the agent", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringVarP(&options.AgentNetwork, "agent-network", "an", envconfig.AgentNetworkLegacyOrDefault(), "specify the network for the agent"),
		flagSet.StringVar(&options.AgentName, "agent-name", "", "specify the name for the agent"),
		flagSet.StringVar(&options.AgentId, "agent-id", "", "specify the agent ID (auto-generated if empty, persisted across self-updates)"),
		flagSet.IntVarP(&options.ChunkParallelism, "chunk-parallelism", "c", defaultChunkParallelism, "number of chunks to process in parallel"),
		flagSet.IntVarP(&options.ScanParallelism, "scan-parallelism", "s", defaultScanParallelism, "number of scans to process in parallel"),
	)

	if err := flagSet.Parse(); err != nil {
		slog.Error("error", "error", err)
	}

	if agentTags := envconfig.AgentTags(); agentTags != "" && len(options.AgentTags) == 0 {
		options.AgentTags = goflags.StringSlice(strings.Split(agentTags, ","))
	}
	if agentNetwork := envconfig.AgentNetwork(); agentNetwork != "" && options.AgentNetwork == "" {
		options.AgentNetwork = agentNetwork
	}
	if agentOutput := envconfig.AgentOutput(); agentOutput != "" && options.AgentOutput == "" {
		options.AgentOutput = agentOutput
	}
	if agentName := envconfig.AgentName(); agentName != "" && options.AgentName == "" {
		options.AgentName = agentName
	}
	if agentNetwork := envconfig.AgentNetworkLegacy(); agentNetwork != "" && options.AgentNetwork == "" {
		options.AgentNetwork = agentNetwork
	}
	if envconfig.Verbose() && !options.Verbose {
		options.Verbose = true
	}

	if envconfig.KeepOutputFiles() {
		options.KeepOutputFiles = true
	}

	configureLogging(options)

	if options.AgentNetwork == "" {
		options.AgentNetwork = "default"
	}

	// 0 = auto-detect for chunks.
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
			// Synchronous insert: the async channel won't flush before exit.
			if dbWriterInstance != nil && pdcpRunner != nil && pdcpRunner.agentDB != nil {
				dbWriterInstance.DirectWrite(pdcpRunner.agentDB, msg)
			}
			if dbWriterInstance != nil {
				dbWriterInstance.StopLogWriter()
			}
			os.Exit(2)
		}
	}()

	for _, arg := range os.Args[1:] {
		if arg == "-version" || arg == "--version" {
			fmt.Println(Version)
			os.Exit(0)
		}
	}

	// GOMAXPROCS from cgroup CPU quota; no-op on bare metal.
	_, _ = maxprocs.Set(maxprocs.Logger(func(format string, args ...any) {
		slog.Info(fmt.Sprintf(format, args...))
	}))

	runtools.RaiseFileLimit()
	runtools.SilenceSDKLoggers()

	options := parseOptions()

	// Self-update preflight: parent process is probing the new binary with the
	// restart args. Exit 0 before touching shared state (DB, NATS) so the
	// still-running agent isn't disturbed.
	if os.Getenv(selfupdate.PreflightEnvVar) == "1" {
		fmt.Println("preflight ok")
		os.Exit(0)
	}

	if failed := prereq.EnsureAll(); len(failed) > 0 {
		slog.Error("Could not install required tools", "tools", strings.Join(failed, ", "))
		os.Exit(1)
	}

	ensureNucleiTemplates()

	runtools.InitNucleiProcess()

	var err error
	pdcpRunner, err = NewRunner(options)
	if err != nil {
		slog.Error("Could not create runner", "error", err)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// SIGTERM/SIGINT cancels contexts; agentMode's defer waits for in-flight
	// work and cleans up NATS/batchers. k8s sends SIGTERM, then SIGKILL after
	// terminationGracePeriodSeconds.
	go func() {
		<-c
		slog.Info("shutdown signal received, draining in-flight work...")
		if jsCancel := pdcpRunner.jsCancel.Load(); jsCancel != nil {
			(*jsCancel)()
		}
		cancel()
	}()

	err = pdcpRunner.Run(ctx)

	// All writers are stopped here (agentMode defer ran), so a WAL checkpoint
	// is safe before upload.
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

// uploadDebugDB ships the SQLite DB to GCS via the presigned URL from /in.
// Best-effort; must be called after all DB writers stop. Opt out via
// PDCP_DISABLE_DIAGNOSTIC_UPLOAD.
func (r *Runner) uploadDebugDB() {
	if envconfig.DisableDiagnosticUpload() {
		slog.Info("agentdb: diagnostic upload disabled via " + envconfig.KeyDisableDiagnosticUpload)
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

// warnOrphanDBs warns on stray pd-agent DBs and deletes those older than 7
// days (plus WAL/SHM sidecars).
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
		slog.Warn("agentdb: found other agent DB files", "count", len(orphans), "dir", dir)
	}
}
