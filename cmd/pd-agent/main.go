package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/projectdiscovery/gcache"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/pd-agent/pkg"
	"github.com/projectdiscovery/pd-agent/pkg/client"
	"github.com/projectdiscovery/pd-agent/pkg/scanlog"
	"github.com/projectdiscovery/pd-agent/pkg/supervisor"
	"github.com/projectdiscovery/pd-agent/pkg/types"
	"github.com/projectdiscovery/utils/batcher"
	envutil "github.com/projectdiscovery/utils/env"
	fileutil "github.com/projectdiscovery/utils/file"
	mapsutil "github.com/projectdiscovery/utils/maps"
	sliceutil "github.com/projectdiscovery/utils/slice"
	syncutil "github.com/projectdiscovery/utils/sync"
	"github.com/rs/xid"
	"github.com/tidwall/gjson"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// getAllNucleiTemplates recursively finds all .yaml and .yml files in the nuclei template directory
func getAllNucleiTemplates(templateDir string) ([]string, error) {
	var templates []string
	err := filepath.Walk(templateDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			ext := filepath.Ext(path)
			if ext == ".yaml" || ext == ".yml" {
				// Get relative path from template directory
				relPath, err := filepath.Rel(templateDir, path)
				if err == nil {
					templates = append(templates, relPath)
				}
			}
		}
		return nil
	})
	return templates, err
}

var (
	PDCPApiKey                = envutil.GetEnvOrDefault("PDCP_API_KEY", "")
	TeamIDEnv                 = envutil.GetEnvOrDefault("PDCP_TEAM_ID", "")
	AgentTagsEnv              = envutil.GetEnvOrDefault("PDCP_AGENT_TAGS", "")
	PdcpApiServer             = envutil.GetEnvOrDefault("PDCP_API_SERVER", "https://api.projectdiscovery.io")
	ChunkParallelismEnv       = envutil.GetEnvOrDefault("PDCP_CHUNK_PARALLELISM", "1")
	ScanParallelismEnv        = envutil.GetEnvOrDefault("PDCP_SCAN_PARALLELISM", "1")
	EnumerationParallelismEnv = envutil.GetEnvOrDefault("PDCP_ENUMERATION_PARALLELISM", "1")
)

// Options contains the configuration options for the agent
type Options struct {
	TeamID                 string
	AgentId                string
	AgentTags              goflags.StringSlice
	AgentNetworks          goflags.StringSlice
	AgentOutput            string
	AgentName              string
	Verbose                bool
	PassiveDiscovery       bool // Enable passive discovery
	ChunkParallelism       int  // Number of chunks to process in parallel
	ScanParallelism        int  // Number of scans to process in parallel
	EnumerationParallelism int  // Number of enumerations to process in parallel
	KeepOutputFiles        bool // If true, don't delete output files after processing
	SupervisorMode         string // Supervisor mode: "docker" or "kubernetes" (default: empty, disabled)
}

// ScanCache represents cached scan execution information
type ScanCache struct {
	LastExecuted time.Time `json:"last_executed"`
	ConfigHash   string    `json:"config_hash"`
}

// LocalCache manages local execution cache
type LocalCache struct {
	Scans        map[string]ScanCache `json:"scans"`
	Enumerations map[string]ScanCache `json:"enumerations"`
	mutex        sync.RWMutex
}

// NewLocalCache creates a new local cache instance
func NewLocalCache() *LocalCache {
	return &LocalCache{
		Scans:        make(map[string]ScanCache),
		Enumerations: make(map[string]ScanCache),
	}
}

// Save saves the cache to disk
func (c *LocalCache) Save() error {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	data, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("error marshaling cache: %v", err)
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("error getting home directory: %v", err)
	}

	cacheDir := filepath.Join(homeDir, ".pd-agent")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return fmt.Errorf("error creating cache directory: %v", err)
	}

	cacheFile := filepath.Join(cacheDir, "execution-cache.json")
	return os.WriteFile(cacheFile, data, 0644)
}

// Load loads the cache from disk
func (c *LocalCache) Load() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("error getting home directory: %v", err)
	}

	cacheFile := filepath.Join(homeDir, ".pd-agent", "execution-cache.json")
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No cache file yet, that's ok
		}
		return fmt.Errorf("error reading cache file: %v", err)
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	return json.Unmarshal(data, c)
}

// HasScanBeenExecuted checks if a scan has been executed with the same config
func (c *LocalCache) HasScanBeenExecuted(id string, configHash string) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if cache, exists := c.Scans[id]; exists {
		return cache.ConfigHash == configHash
	}
	return false
}

// HasEnumerationBeenExecuted checks if an enumeration has been executed with the same config
func (c *LocalCache) HasEnumerationBeenExecuted(id string, configHash string) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if cache, exists := c.Enumerations[id]; exists {
		return cache.ConfigHash == configHash
	}
	return false
}

// MarkScanExecuted marks a scan as executed
func (c *LocalCache) MarkScanExecuted(id string, configHash string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.Scans[id] = ScanCache{
		LastExecuted: time.Now().UTC(),
		ConfigHash:   configHash,
	}
	// Async save
	go func() {
		if err := c.Save(); err != nil {
			slog.Warn("error saving cache", "error", err)
		}
	}()
}

// MarkEnumerationExecuted marks an enumeration as executed
func (c *LocalCache) MarkEnumerationExecuted(id string, configHash string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.Enumerations[id] = ScanCache{
		LastExecuted: time.Now().UTC(),
		ConfigHash:   configHash,
	}
	// Async save
	go func() {
		if err := c.Save(); err != nil {
			slog.Warn("error saving cache", "error", err)
		}
	}()
}

// TaskChunk represents a chunk of scan data from the API
type TaskChunk struct {
	ScanID               string   `json:"scan_id"`
	TemplateRequestCount int      `json:"template_request_count"`
	Targets              []string `json:"targets"`
	PublicTemplates      []string `json:"public_templates"`
	PrivateTemplates     []string `json:"private_templates"`
	UserID               int64    `json:"user_id"`
	ChunkID              string   `json:"chunk_id"`
	ScanConfiguration    string   `json:"scan_configuration"`
	PublicWorkflows      []string `json:"public_workflows"`
	PrivateWorkflows     []string `json:"private_workflows"`
	WorkflowsURLs        []string `json:"workflows_urls"`
	Status               string   `json:"status"`
}

// TaskChunkStatus represents the possible status values for a task chunk
type TaskChunkStatus string

const (
	TaskChunkStatusAck        TaskChunkStatus = "ack"
	TaskChunkStatusNack       TaskChunkStatus = "nack"
	TaskChunkStatusInProgress TaskChunkStatus = "in_progress"
)

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

// Runner contains the internal logic of the agent
type Runner struct {
	options        *Options
	localCache     *LocalCache
	inRequestCount int       // Number of /in requests sent
	agentStartTime time.Time // When the agent started
	logBatcher     *batcher.Batcher[string]
}

var (
	completedTasks = gcache.New[string, struct{}](1024).
			LRU().
			Expiration(time.Hour).
			Build()
	pendingTasks = mapsutil.NewSyncLockMap[string, struct{}]()
	// passiveDiscoveredIPs *mapsutil.SyncLockMap[string, struct{}]

	// K8s subnets cache
	k8sSubnetsCache     []string
	k8sSubnetsCacheOnce sync.Once
)

// shouldSkipTask checks if a task (scan or enumeration) should be skipped based on
// agent assignment, tags, and networks. Logs each check in verbose mode.
// Returns true if the task should be skipped (no matching conditions), false if it should continue.
func (r *Runner) shouldSkipTask(taskType, id, name, taskAgentId string, agentTags, agentNetworks gjson.Result) bool {
	r.logHelper("VERBOSE", fmt.Sprintf("checking %s (%s - %s)", taskType, id, name))

	// Check if agent ID matches (case-insensitive)
	isAssignedToAgent := strings.EqualFold(taskAgentId, r.options.AgentId)
	result := "✗"
	if isAssignedToAgent {
		result = "✓"
	}
	if taskAgentId == "" {
		r.logHelper("VERBOSE", fmt.Sprintf("  checking id: %s (task: <empty>, agent: %s)", result, r.options.AgentId))
	} else {
		r.logHelper("VERBOSE", fmt.Sprintf("  checking id: %s (task: %s, agent: %s)", result, taskAgentId, r.options.AgentId))
	}

	// Check if task's agent_tags match any of the runner's agent tags (case-insensitive)
	var hasAgentTag bool
	var taskAgentTags []string
	if agentTags.Exists() {
		agentTags.ForEach(func(key, value gjson.Result) bool {
			tagValue := value.String()
			taskAgentTags = append(taskAgentTags, tagValue)
			// Case-insensitive comparison
			for _, agentTag := range r.options.AgentTags {
				if strings.EqualFold(tagValue, agentTag) {
					hasAgentTag = true
					return false // Stop iteration
				}
			}
			return true
		})
	}
	result = "✗"
	if hasAgentTag {
		result = "✓"
	}
	if len(taskAgentTags) > 0 {
		r.logHelper("VERBOSE", fmt.Sprintf("  checking tags: %s (task agent_tags: %v, agent tags: %v)", result, taskAgentTags, r.options.AgentTags))
	} else {
		r.logHelper("VERBOSE", fmt.Sprintf("  checking tags: %s (task agent_tags: <none>, agent tags: %v)", result, r.options.AgentTags))
	}

	// Check if task's agent_networks match any of the runner's agent networks (case-insensitive)
	var hasAgentNetwork bool
	var taskAgentNetworks []string
	if agentNetworks.Exists() {
		agentNetworks.ForEach(func(key, value gjson.Result) bool {
			networkValue := value.String()
			taskAgentNetworks = append(taskAgentNetworks, networkValue)
			// Case-insensitive comparison
			for _, agentNetwork := range r.options.AgentNetworks {
				if strings.EqualFold(networkValue, agentNetwork) {
					hasAgentNetwork = true
					return false // Stop iteration
				}
			}
			return true
		})
	}
	result = "✗"
	if hasAgentNetwork {
		result = "✓"
	}
	if len(taskAgentNetworks) > 0 {
		r.logHelper("VERBOSE", fmt.Sprintf("  checking networks: %s (task agent_networks: %v, agent networks: %v)", result, taskAgentNetworks, r.options.AgentNetworks))
	} else {
		r.logHelper("VERBOSE", fmt.Sprintf("  checking networks: %s (task agent_networks: <none>, agent networks: %v)", result, r.options.AgentNetworks))
	}

	// If any condition matches, don't skip
	shouldContinue := isAssignedToAgent || hasAgentTag || hasAgentNetwork

	if shouldContinue {
		r.logHelper("VERBOSE", fmt.Sprintf("  %s (%s - %s) is being enqueued (matching conditions found)", taskType, id, name))
		return false // Don't skip
	}

	r.logHelper("VERBOSE", fmt.Sprintf("  %s (%s - %s) is being skipped (no matching conditions)", taskType, id, name))
	return true // Skip
}

// LogEntry represents a log entry structure
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
}

// AgentLogUploadRequest represents the request payload for log upload
type AgentLogUploadRequest struct {
	OS             string   `json:"os,omitempty"`
	Arch           string   `json:"arch,omitempty"`
	ID             string   `json:"id,omitempty"`
	Name           string   `json:"name,omitempty"`
	Tags           []string `json:"tags,omitempty"`
	Networks       []string `json:"networks,omitempty"`
	NetworkSubnets []string `json:"network_subnets,omitempty"`
	Type           string   `json:"type,omitempty"`
	Logs           []string `json:"logs"`
}

// AgentLogUploadResponse represents the response from log upload endpoint
type AgentLogUploadResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// logHelper prints the log to console and appends JSON marshalled string to the batcher
func (r *Runner) logHelper(level, message string) {
	entry := LogEntry{
		Timestamp: time.Now().UTC(),
		Level:     level,
		Message:   message,
	}

	// Print to console
	fmt.Printf("[%s] %s: %s\n", entry.Timestamp.Format(time.RFC3339), entry.Level, entry.Message)

	// Marshal to JSON
	jsonData, err := json.Marshal(entry)
	if err != nil {
		r.logHelper("WARNING", fmt.Sprintf("error marshaling log entry: %v", err))
		return
	}

	// Append to batcher
	if r.logBatcher != nil {
		r.logBatcher.Append(string(jsonData))
	}
}

// uploadLogs sends batched logs to the /v1/agents/{id}/log endpoint
func (r *Runner) uploadLogs(logs []string) {
	if len(logs) == 0 {
		return
	}

	// Get metadata same as /in endpoint
	tagsToUse := r.options.AgentTags
	networksToUse := r.options.AgentNetworks
	networkSubnets := r.getAutoDiscoveredTargets()

	// Build request payload
	payload := AgentLogUploadRequest{
		OS:             runtime.GOOS,
		Arch:           runtime.GOARCH,
		ID:             r.options.AgentId,
		Name:           r.options.AgentName,
		Tags:           tagsToUse,
		Networks:       networksToUse,
		NetworkSubnets: networkSubnets,
		Type:           "agent",
		Logs:           logs,
	}

	// Marshal payload to JSON
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		r.logHelper("WARNING", fmt.Sprintf("error marshaling log upload payload: %v", err))
		return
	}

	// Create request
	apiURL := fmt.Sprintf("%s/v1/agents/%s/log", PdcpApiServer, r.options.AgentId)
	headers := map[string]string{
		"x-api-key":    PDCPApiKey,
		"Content-Type": "application/json",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp := r.makeRequest(ctx, http.MethodPost, apiURL, bytes.NewReader(jsonPayload), headers)
	if resp.Error != nil {
		r.logHelper("WARNING", fmt.Sprintf("error uploading logs: %v", resp.Error))
		return
	}

	if resp.StatusCode != http.StatusOK {
		r.logHelper("WARNING", fmt.Sprintf("unexpected status code from log upload endpoint: %d, body: %s", resp.StatusCode, string(resp.Body)))
		return
	}

	// Parse response
	var uploadResp AgentLogUploadResponse
	if err := json.Unmarshal(resp.Body, &uploadResp); err != nil {
		r.logHelper("WARNING", fmt.Sprintf("error unmarshaling log upload response: %v", err))
		return
	}

	r.logHelper("VERBOSE", fmt.Sprintf("uploaded %d log entries: %s", len(logs), uploadResp.Message))
}

// NewRunner creates a new runner instance
func NewRunner(options *Options) (*Runner, error) {
	r := &Runner{
		options:        options,
		localCache:     NewLocalCache(),
		agentStartTime: time.Now(),
	}

	if err := r.localCache.Load(); err != nil {
		r.logHelper("WARNING", fmt.Sprintf("error loading cache: %v", err))
	}

	// Generate a unique agent ID using xid (similar to tunnelx)
	// This creates a globally unique ID like "c5s8v3k0h0ql5r2g0000"
	if r.options.AgentId == "" {
		r.options.AgentId = xid.New().String()
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

	// Initialize log batcher
	r.logBatcher = batcher.New[string](
		batcher.WithMaxCapacity[string](100),              // Max 100 logs per batch
		batcher.WithFlushInterval[string](30*time.Second), // Flush every 30 seconds
		batcher.WithFlushCallback[string](r.uploadLogs),   // Upload callback
	)

	// Start the batcher
	go r.logBatcher.Run()

	// Start passive discovery if enabled
	// if r.options.PassiveDiscovery {
	// 	go r.startPassiveDiscovery()
	// }

	return r, nil
}

// Run starts the agent
func (r *Runner) Run(ctx context.Context) error {
	// Recommend the time to use on platform dashboard to schedule the scans
	r.logHelper("INFO", "platform dashboard uses UTC timezone")
	now := time.Now().UTC()
	recommendedTime := now.Add(5 * time.Minute)
	r.logHelper("INFO", fmt.Sprintf("recommended time to schedule scans (UTC): %s", recommendedTime.Format("2006-01-02 03:04:05 PM MST")))

	var infoMessage strings.Builder
	infoMessage.WriteString("running in agent mode")
	if r.options.AgentId != "" {
		infoMessage.WriteString(fmt.Sprintf(" with id %s", r.options.AgentId))
	}
	if len(r.options.AgentTags) > 0 {
		infoMessage.WriteString(fmt.Sprintf(" (tags: [%s])", strings.Join(r.options.AgentTags, ", ")))
	} else {
		infoMessage.WriteString(" (tags: [])")
	}
	if len(r.options.AgentNetworks) > 0 {
		infoMessage.WriteString(fmt.Sprintf(" (networks: [%s])", strings.Join(r.options.AgentNetworks, ", ")))
	} else {
		infoMessage.WriteString(" (networks: [])")
	}

	r.logHelper("INFO", infoMessage.String())

	return r.agentMode(ctx)
}

// agentMode runs the agent in monitoring mode
func (r *Runner) agentMode(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer func() {
		cancel()
		// Ensure batcher is stopped on shutdown
		if r.logBatcher != nil {
			r.logBatcher.Stop()
			r.logBatcher.WaitDone()
		}
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		if err := r.In(ctx); err != nil {
			r.logHelper("FATAL", fmt.Sprintf("error registering agent: %v", err))
			os.Exit(1)
		}
	}()

	go r.monitorScans(ctx)
	go r.monitorEnumerations(ctx)

	defer func() {
		wg.Wait()
	}()

	// Wait for context cancellation
	<-ctx.Done()
	return nil
}

// monitorScans periodically monitors and processes scans
func (r *Runner) monitorScans(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if err := r.getScans(ctx); err != nil {
				r.logHelper("ERROR", fmt.Sprintf("Error getting scans: %v", err))
			}
			time.Sleep(time.Minute)
		}
	}
}

// monitorEnumerations periodically monitors and processes enumerations
func (r *Runner) monitorEnumerations(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if err := r.getEnumerations(ctx); err != nil {
				r.logHelper("ERROR", fmt.Sprintf("Error getting enumerations: %v", err))
			}
			time.Sleep(time.Minute)
		}
	}
}

// getScans fetches and processes scans from the API
func (r *Runner) getScans(ctx context.Context) error {
	r.logHelper("VERBOSE", "Retrieving scans...")
	apiURL := fmt.Sprintf("%s/v1/scans", pkg.PCDPApiServer)

	awg, err := syncutil.New(syncutil.WithSize(r.options.ScanParallelism))
	if err != nil {
		r.logHelper("ERROR", fmt.Sprintf("Error creating syncutil: %v", err))
		return err
	}

	limit := 100
	offset := 0
	totalPages := 1
	currentPage := 1

	for currentPage <= totalPages {
		paginatedURL := fmt.Sprintf("%s?limit=%d&offset=%d&is_internal=true", apiURL, limit, offset)
		resp := r.makeRequest(ctx, http.MethodGet, paginatedURL, nil, nil)
		if resp.Error != nil {
			return resp.Error
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(resp.Body))
		}

		result := gjson.ParseBytes(resp.Body)

		// Update totalPages on the first iteration
		if currentPage == 1 {
			totalPages = int(result.Get("total_pages").Int())
			r.logHelper("VERBOSE", fmt.Sprintf("Total pages: %d", totalPages))
		}

		r.logHelper("VERBOSE", fmt.Sprintf("Processing page %d of %d\n", currentPage, totalPages))

		// Process scans in parallel
		result.Get("data").ForEach(func(key, value gjson.Result) bool {
			id := value.Get("scan_id").String()
			if id == "" {
				return true
			}

			// Skip scans in finished state
			status := value.Get("status").String()
			if strings.EqualFold(status, "finished") {
				return true
			}

			// Capture all data from gjson.Result before passing to goroutine
			scanName := value.Get("name").String()
			agentId := value.Get("agent_id").String()
			agentTags := value.Get("agent_tags")
			agentNetworks := value.Get("agent_networks")
			startTime := value.Get("start_time").String()
			scheduleData := value.Get("schedule")

			var templates []string
			value.Get("public_templates").ForEach(func(key, value gjson.Result) bool {
				templates = append(templates, value.String())
				return true
			})

			// If no templates specified, use all default nuclei templates
			if len(templates) == 0 {
				defaultTemplateDir := pkg.GetNucleiDefaultTemplateDir()
				if defaultTemplateDir != "" {
					allTemplates, err := getAllNucleiTemplates(defaultTemplateDir)
					if err == nil && len(allTemplates) > 0 {
						templates = allTemplates
						slog.Info("No templates specified, using all default nuclei templates", "scan_id", id, "template_count", len(allTemplates), "template_dir", defaultTemplateDir)
					} else if err != nil {
						slog.Warn("Failed to get default nuclei templates", "scan_id", id, "template_dir", defaultTemplateDir, "error", err)
					}
				}
			}

			agentBehavior := value.Get("agent_behavior").String()

			// Early skip checks that don't require API calls
			if r.shouldSkipTask("scan", id, scanName, agentId, agentTags, agentNetworks) {
				return true
			}

			// Add to wait group and process in parallel
			awg.Add()
			go func(scanID, name, agentID string, tags, networks gjson.Result, startTimeStr string, schedule gjson.Result, tmpls []string, behavior string) {
				defer awg.Done()

				// Parse schedule and start time
				var targetExecutionTime time.Time
				if startTimeStr != "" {
					parsedStartTime, err := time.Parse(time.RFC3339, startTimeStr)
					if err != nil {
						r.logHelper("ERROR", fmt.Sprintf("Error parsing start time: %v", err))
						return
					}
					targetExecutionTime = parsedStartTime
				}

				if schedule.Exists() {
					nextRun := schedule.Get("schedule_next_run").String()
					if nextRun != "" {
						nextRunTime, err := time.Parse(time.RFC3339, nextRun)
						if err != nil {
							r.logHelper("ERROR", fmt.Sprintf("Error parsing next run time: %v", err))
							return
						}
						if !targetExecutionTime.IsZero() {
							targetExecutionTime = targetExecutionTime.Add(nextRunTime.Sub(nextRunTime.Truncate(24 * time.Hour)))
						} else {
							targetExecutionTime = nextRunTime
						}
					}

					now := time.Now().UTC()

					// Skip if the combined execution time is in the future
					// we accept up to 10 minutes before/after the scheduled time
					isInRange := targetExecutionTime.After(now.Add(-10*time.Minute)) && targetExecutionTime.Before(now.Add(10*time.Minute))

					if !targetExecutionTime.IsZero() && !isInRange {
						r.logHelper("VERBOSE", fmt.Sprintf("skipping scan \"%s\" as it's scheduled for %s (current time: %s)\n", name, targetExecutionTime, now))
						return
					}
				}

				metaId := fmt.Sprintf("%s-%s", scanID, targetExecutionTime)

				// First check completed and pending tasks
				if completedTasks.Has(metaId) {
					r.logHelper("VERBOSE", fmt.Sprintf("skipping scan \"%s\" as it's already completed recently\n", name))
					return
				}

				if pendingTasks.Has(metaId) {
					r.logHelper("VERBOSE", fmt.Sprintf("skipping scan \"%s\" as it's already in progress\n", name))
					return
				}

				// Fetch minimal config first to compute hash
				scanConfig, err := r.fetchScanConfig(scanID)
				if err != nil {
					r.logHelper("ERROR", fmt.Sprintf("Error fetching scan config for ID %s: %v", scanID, err))
					return
				}

				// Continue with full config processing
				scanConfigIds := make(map[string]string)
				gjson.Parse(scanConfig).Get("scan_config_ids").ForEach(func(key, value gjson.Result) bool {
					id := value.Get("id").String()
					if id != "" {
						scanConfigIds[id] = ""
					}
					return true
				})

				for id := range scanConfigIds {
					scanConfig, err := r.fetchSingleConfig(id)
					if err != nil {
						r.logHelper("ERROR", fmt.Sprintf("Error fetching scan config for ID %s: %v", id, err))
					}
					scanConfigIds[id] = scanConfig
				}

				// Merge all configs into one
				var finalConfig string
				if len(scanConfigIds) > 0 {
					var mergedConfig strings.Builder
					for _, scanConfig := range scanConfigIds {
						// Parse the JSON to get the config field
						configValue := gjson.Get(scanConfig, "config").String()
						if configValue != "" {
							// Decode base64
							decoded, err := base64.StdEncoding.DecodeString(configValue)
							if err != nil {
								r.logHelper("ERROR", fmt.Sprintf("Error decoding base64 config: %v", err))
								continue
							}
							mergedConfig.Write(decoded)
							mergedConfig.WriteString("\n")
						}
					}
					finalConfig = mergedConfig.String()
				}

				// Fetch assets if enumeration ID is defined
				var enumerationIDs []string
				gjson.Parse(scanConfig).Get("enumeration_ids").ForEach(func(key, value gjson.Result) bool {
					id := value.Get("id").String()
					if id != "" {
						enumerationIDs = append(enumerationIDs, id)
					}
					return true
				})

				// Get assets from enumeration id
				var assets []string
				for _, enumerationID := range enumerationIDs {
					asset, err := r.fetchAssets(enumerationID)
					if err != nil {
						r.logHelper("ERROR", fmt.Sprintf("Error fetching assets for enumeration ID %s: %v", enumerationID, err))
					}
					assets = append(assets, strings.Split(string(asset), "\n")...)
				}

				// Get assets from scan config
				gjson.Parse(scanConfig).Get("targets").ForEach(func(key, value gjson.Result) bool {
					assets = append(assets, value.String())
					return true
				})

				isDistributed := behavior == "distribute"

				// Compute hash of the entire configuration
				configHash := computeScanConfigHash(finalConfig, tmpls, assets)

				// Skip if this exact configuration was already executed
				if r.localCache.HasScanBeenExecuted(scanID, configHash) && !schedule.Exists() {
					slog.Debug("skipping scan as it was already executed with same configuration", "name", name)
					return
				}

				slog.Info("scan enqueued", "scan_name", name, "scan_id", scanID)

				// DEBUG: Print scan configuration and naabu results, then exit
				fmt.Println("=== DEBUG: Scan Configuration ===")
				fmt.Printf("Scan ID: %s\n", scanID)
				fmt.Printf("Scan Name: %s\n", name)
				fmt.Printf("\nTargets (%d):\n", len(assets))
				for i, target := range assets {
					fmt.Printf("  [%d] %s\n", i+1, target)
				}

				// If no templates specified, get all default nuclei templates
				templatesToUse := tmpls
				if len(tmpls) == 0 {
					fmt.Printf("\nTemplates: NONE SPECIFIED - Using all default nuclei templates\n")
					// Get all templates from nuclei template directory
					defaultTemplateDir := pkg.GetNucleiDefaultTemplateDir()
					if defaultTemplateDir != "" {
						allTemplates, err := getAllNucleiTemplates(defaultTemplateDir)
						if err == nil {
							templatesToUse = allTemplates
							fmt.Printf("Found %d default templates in %s\n", len(allTemplates), defaultTemplateDir)
						} else {
							fmt.Printf("Error getting default templates: %v\n", err)
						}
					} else {
						fmt.Printf("Warning: Could not determine nuclei template directory\n")
					}
				} else {
					fmt.Printf("\nTemplates (%d):\n", len(tmpls))
					for i, tmpl := range tmpls {
						fmt.Printf("  [%d] %s\n", i+1, tmpl)
					}
				}

				// Perform naabu scan for debugging
				if len(assets) > 0 && len(templatesToUse) > 0 {
					tmpInputFile, err := fileutil.GetTempFileName()
					if err == nil {
						defer func() {
							_ = os.RemoveAll(tmpInputFile)
						}()
						targetsContent := strings.Join(assets, "\n")
						_ = os.WriteFile(tmpInputFile, []byte(targetsContent), os.ModePerm)

						tmpTemplatesFile, err := fileutil.GetTempFileName()
						if err == nil {
							defer func() {
								_ = os.RemoveAll(tmpTemplatesFile)
							}()
							templatesContent := strings.Join(templatesToUse, "\n")
							_ = os.WriteFile(tmpTemplatesFile, []byte(templatesContent), os.ModePerm)

							filteredTargets, extractedPorts, err := pkg.FilterTargetsByTemplatePorts(ctx, tmpInputFile, tmpTemplatesFile, scanID, "debug")
							fmt.Println("\n=== DEBUG: Naabu Results ===")
							if err != nil {
								fmt.Printf("Error: %v\n", err)
							} else {
								fmt.Printf("Extracted Ports: %v\n", extractedPorts)
								fmt.Printf("\nTargets with Open Ports (%d):\n", len(filteredTargets))
								for i, target := range filteredTargets {
									fmt.Printf("  [%d] %s\n", i+1, target)
								}
								fmt.Printf("\nTargets without Open Ports (%d):\n", len(assets)-len(filteredTargets))
								targetsWithPorts := make(map[string]struct{})
								for _, t := range filteredTargets {
									targetsWithPorts[t] = struct{}{}
								}
								count := 0
								for _, target := range assets {
									if _, has := targetsWithPorts[target]; !has {
										count++
										fmt.Printf("  [%d] %s\n", count, target)
									}
								}
							}
						}
					}
				} else {
					fmt.Println("\n=== DEBUG: Skipping naabu scan (no targets or templates) ===")
				}
				fmt.Println("\n=== DEBUG: Scan analysis complete, continuing with normal processing ===")
				// END DEBUG CODE

				_ = pendingTasks.Set(metaId, struct{}{})

				if isDistributed {
					// Process distributed scan chunks
					r.elaborateScanChunks(ctx, scanID, metaId, finalConfig, tmpls, assets)
				} else {
					// Process non-distributed scan
					r.elaborateScan(ctx, scanID, metaId, finalConfig, tmpls, assets)
				}

				// After queueing the task, mark it as executed
				r.localCache.MarkScanExecuted(scanID, configHash)
			}(id, scanName, agentId, agentTags, agentNetworks, startTime, scheduleData, templates, agentBehavior)

			return true
		})

		currentPage++
		offset += limit
	}

	// Wait for all scans to complete
	r.logHelper("VERBOSE", "Waiting for all scans to complete...")
	awg.Wait()

	return nil
}

// getEnumerations fetches and processes enumerations from the API
func (r *Runner) getEnumerations(ctx context.Context) error {
	r.logHelper("VERBOSE", "Retrieving enumerations...")
	apiURL := fmt.Sprintf("%s/v1/asset/enumerate", pkg.PCDPApiServer)

	awg, err := syncutil.New(syncutil.WithSize(r.options.EnumerationParallelism))
	if err != nil {
		r.logHelper("ERROR", fmt.Sprintf("Error creating syncutil: %v", err))
		return err
	}

	limit := 100
	offset := 0
	totalPages := 1
	currentPage := 1

	for currentPage <= totalPages {
		paginatedURL := fmt.Sprintf("%s?limit=%d&offset=%d&is_internal=true", apiURL, limit, offset)
		resp := r.makeRequest(ctx, http.MethodGet, paginatedURL, nil, nil)
		if resp.Error != nil {
			return resp.Error
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(resp.Body))
		}

		result := gjson.ParseBytes(resp.Body)

		// Update totalPages on the first iteration
		if currentPage == 1 {
			totalPages = int(result.Get("total_pages").Int())
			r.logHelper("VERBOSE", fmt.Sprintf("Total pages: %d", totalPages))
		}

		r.logHelper("VERBOSE", fmt.Sprintf("Processing page %d of %d\n", currentPage, totalPages))

		// Process enumerations in parallel
		result.Get("data").ForEach(func(key, value gjson.Result) bool {
			id := value.Get("id").String()
			if id == "" {
				return true
			}

			// Skip enumerations in finished state
			status := value.Get("status").String()
			if strings.EqualFold(status, "finished") {
				return true
			}

			// Capture all data from gjson.Result before passing to goroutine
			enumName := value.Get("name").String()
			agentId := value.Get("agent_id").String()
			agentTags := value.Get("agent_tags")
			agentNetworks := value.Get("agent_networks")
			startTime := value.Get("start_time").String()
			scheduleData := value.Get("schedule")
			agentBehavior := value.Get("agent_behavior").String()

			// Early skip checks that don't require API calls
			if r.shouldSkipTask("enumeration", id, enumName, agentId, agentTags, agentNetworks) {
				return true
			}

			// Add to wait group and process in parallel
			awg.Add()
			go func(enumID, name, agentID string, tags, networks gjson.Result, startTimeStr string, schedule gjson.Result, behavior string) {
				defer awg.Done()

				// Parse schedule and start time
				var targetExecutionTime time.Time
				if startTimeStr != "" {
					parsedStartTime, err := time.Parse(time.RFC3339, startTimeStr)
					if err != nil {
						r.logHelper("ERROR", fmt.Sprintf("Error parsing start time: %v", err))
						return
					}
					targetExecutionTime = parsedStartTime
				}

				if schedule.Exists() {
					nextRun := schedule.Get("schedule_next_run").String()
					if nextRun != "" {
						nextRunTime, err := time.Parse(time.RFC3339, nextRun)
						if err != nil {
							r.logHelper("ERROR", fmt.Sprintf("Error parsing next run time: %v", err))
							return
						}
						if !targetExecutionTime.IsZero() {
							targetExecutionTime = targetExecutionTime.Add(nextRunTime.Sub(nextRunTime.Truncate(24 * time.Hour)))
						} else {
							targetExecutionTime = nextRunTime
						}
					}

					now := time.Now().UTC()

					// Skip if the combined execution time is in the future
					// we accept up to 10 minutes before/after the scheduled time
					isInRange := targetExecutionTime.After(now.Add(-10*time.Minute)) && targetExecutionTime.Before(now.Add(10*time.Minute))

					if !targetExecutionTime.IsZero() && !isInRange {
						r.logHelper("VERBOSE", fmt.Sprintf("skipping enumeration \"%s\" as it's scheduled for %s (current time: %s)\n", name, targetExecutionTime, now))
						return
					}
				}

				metaId := fmt.Sprintf("%s-%s", enumID, targetExecutionTime)

				// First check completed and pending tasks
				if completedTasks.Has(metaId) {
					r.logHelper("VERBOSE", fmt.Sprintf("skipping enumeration \"%s\" as it's already completed recently\n", name))
					return
				}

				if pendingTasks.Has(metaId) {
					r.logHelper("VERBOSE", fmt.Sprintf("skipping enumeration \"%s\" as it's already in progress\n", name))
					return
				}

				// Fetch minimal config first
				enumerationConfig, err := r.fetchEnumerationConfig(enumID)
				if err != nil {
					r.logHelper("ERROR", fmt.Sprintf("Error fetching enumeration config for ID %s: %v", enumID, err))
					return
				}

				r.logHelper("VERBOSE", fmt.Sprintf("Before sanitization: %s", enumerationConfig))

				// Sanitize enumeration config (remove unsupported steps)
				enumerationConfig = r.sanitizeEnumerationConfig(enumerationConfig, name)

				// Get basic info needed for hash
				var assets []string
				gjson.Parse(enumerationConfig).Get("enrichment_inputs").ForEach(func(key, value gjson.Result) bool {
					assets = append(assets, value.String())
					return true
				})
				gjson.Parse(enumerationConfig).Get("root_domains").ForEach(func(key, value gjson.Result) bool {
					assets = append(assets, value.String())
					return true
				})

				var steps []string
				gjson.Parse(enumerationConfig).Get("steps").ForEach(func(key, value gjson.Result) bool {
					steps = append(steps, value.String())
					return true
				})

				configHash := computeEnumerationConfigHash(steps, assets)

				// Check cache before proceeding
				if r.localCache.HasEnumerationBeenExecuted(enumID, configHash) && !schedule.Exists() {
					r.logHelper("VERBOSE", fmt.Sprintf("skipping enumeration \"%s\" as it was already executed with same configuration\n", name))
					return
				}

				r.logHelper("INFO", fmt.Sprintf("enumeration \"%s\" enqueued...\n", name))

				isDistributed := behavior == "distribute"

				// Check if passive discovery is enabled for this enumeration
				// hasPassiveDiscovery := value.Get("worker_passive_discover").Bool()
				// if hasPassiveDiscovery && r.options.PassiveDiscovery {
				// 	discoveredIPs := PopAllPassiveDiscoveredIPs()
				// 	if len(discoveredIPs) > 0 {
				// 		slog.Info("Adding %d passively discovered IPs to enumeration %s: %s", len(discoveredIPs), scanName, strings.Join(discoveredIPs, ","))
				// 		assets = append(assets, discoveredIPs...)
				// 	}
				// }

				_ = pendingTasks.Set(metaId, struct{}{})

				if isDistributed {
					// Process distributed enumeration chunks
					r.elaborateEnumerationChunks(ctx, enumID, metaId, steps, assets)
				} else {
					// Process non-distributed enumeration
					r.elaborateEnumeration(ctx, enumID, metaId, steps, assets)
				}

				// After queueing the task, mark it as executed
				r.localCache.MarkEnumerationExecuted(enumID, configHash)
			}(id, enumName, agentId, agentTags, agentNetworks, startTime, scheduleData, agentBehavior)

			return true
		})

		currentPage++
		offset += limit
	}

	// Wait for all enumerations to complete
	r.logHelper("VERBOSE", "Waiting for all enumerations to complete...")
	awg.Wait()

	return nil
}

// executeNucleiScan is the shared implementation for executing nuclei scans
// using the same logic as pd-agent
// If scanBatcher is nil, a new batcher will be created for this scan
func (r *Runner) executeNucleiScan(ctx context.Context, scanID, metaID, config string, templates, assets []string, scanBatcher *batcher.Batcher[types.ScanLogUploadEntry]) {
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

	// If templates are empty, use all default nuclei templates
	templatesToUse := templates
	if len(templates) == 0 {
		defaultTemplateDir := pkg.GetNucleiDefaultTemplateDir()
		if defaultTemplateDir != "" {
			allTemplates, err := getAllNucleiTemplates(defaultTemplateDir)
			if err == nil && len(allTemplates) > 0 {
				templatesToUse = allTemplates
				slog.Info("No templates specified, using all default nuclei templates",
					"scan_id", scanID,
					"chunk_id", metaID,
					"template_count", len(allTemplates))
			}
		}
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
	r.logHelper("INFO", fmt.Sprintf("Starting nuclei scan for scanID=%s, metaID=%s", scanID, metaID))
	taskResult, outputFiles, err := pkg.Run(ctx, task)
	if err != nil {
		r.logHelper("ERROR", fmt.Sprintf("Nuclei scan execution failed: %v", err))
		return
	}

	// For scans, there should be only one output file
	var outputFile string
	if len(outputFiles) > 0 {
		outputFile = outputFiles[0]
	}

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
		r.logHelper("INFO", fmt.Sprintf("Completed nuclei scan for scanID=%s, metaID=%s\nStdout: %s\nStderr: %s", scanID, metaID, taskResult.Stdout, taskResult.Stderr))
	} else {
		r.logHelper("INFO", fmt.Sprintf("Completed nuclei scan for scanID=%s, metaID=%s", scanID, metaID))
	}
}

// processChunks is a generic chunk processing method that handles the common logic
// for pulling chunks, updating status, and executing them
func (r *Runner) processChunks(ctx context.Context, taskID, taskType string, executeChunk func(ctx context.Context, chunk *TaskChunk) error) {
	r.logHelper("INFO", fmt.Sprintf("Starting distributed %s processing for %s ID: %s", taskType, taskType, taskID))

	awg, err := syncutil.New(syncutil.WithSize(r.options.ChunkParallelism))
	if err != nil {
		r.logHelper("ERROR", fmt.Sprintf("Error creating syncutil: %v", err))
		return
	}

	chunkCount := 0
	for {
		chunkCount++
		r.logHelper("INFO", fmt.Sprintf("Fetching chunk #%d for %s ID: %s", chunkCount, taskType, taskID))

		var chunk *TaskChunk
		var err error
		maxRetries := 5
		retryCount := 0
		lastErr := ""

		// Retry logic for getting chunks
		for retryCount < maxRetries {
			chunk, err = r.getTaskChunk(ctx, taskID, false)
			if err == nil {
				break
			}
			// If we get "no more chunks", terminate immediately without retrying
			if err != nil && err.Error() == "no more chunks" {
				r.logHelper("INFO", fmt.Sprintf("No more chunks available for %s ID: %s", taskType, taskID))
				goto Complete
			}
			currentErr := err.Error()
			if currentErr == lastErr {
				// If we get the same error multiple times, likely the task is complete
				r.logHelper("INFO", fmt.Sprintf("%s ID %s completed successfully", taskType, taskID))
				goto Complete
			}
			lastErr = currentErr
			retryCount++
			if retryCount < maxRetries {
				time.Sleep(time.Second * 3)
			}
		}

		if err != nil {
			r.logHelper("ERROR", fmt.Sprintf("Failed to get chunk after %d retries: %v", maxRetries, err))
			break
		}

		if chunk == nil {
			r.logHelper("INFO", fmt.Sprintf("No more chunks available for %s ID: %s", taskType, taskID))
			break
		}

		currentChunkCount := chunkCount
		currentChunk := chunk

		// Add chunk to wait group and process in parallel
		awg.Add()
		go func(chunkNum int, chunk *TaskChunk) {
			defer awg.Done()

			r.logHelper("INFO", fmt.Sprintf("Processing chunk #%d (ID: %s) with %d targets",
				chunkNum,
				chunk.ChunkID,
				len(chunk.Targets)))

			// Set initial status to in_progress
			if err := r.UpdateTaskChunkStatus(ctx, taskID, chunk.ChunkID, TaskChunkStatusInProgress); err != nil {
				r.logHelper("ERROR", fmt.Sprintf("Error updating %s chunk status: %v", taskType, err))
			} else {
				r.logHelper("INFO", fmt.Sprintf("Updated chunk %s status to in_progress", chunk.ChunkID))
			}

			// Start a goroutine to periodically update status (heartbeat)
			timerCtx, timerCtxCancel := context.WithCancel(context.TODO())
			go func(ctx context.Context, taskID, chunkID string) {
				ticker := time.NewTicker(10 * time.Second)
				defer ticker.Stop()

				for {
					select {
					case <-ctx.Done():
						return
					case <-ticker.C:
						if err := r.UpdateTaskChunkStatus(ctx, taskID, chunkID, TaskChunkStatusInProgress); err != nil {
							r.logHelper("ERROR", fmt.Sprintf("Error updating %s chunk status: %v", taskType, err))
						} else {
							r.logHelper("DEBUG", fmt.Sprintf("Updated chunk %s status to in_progress (heartbeat)", chunkID))
						}
					}
				}
			}(timerCtx, taskID, chunk.ChunkID)

			// Execute the chunk using the provided callback
			executionErr := executeChunk(ctx, chunk)
			if executionErr != nil {
				r.logHelper("ERROR", fmt.Sprintf("Error executing %s chunk: %v", taskType, err))
			}

			// Stop the heartbeat timer
			timerCtxCancel()
			r.logHelper("DEBUG", fmt.Sprintf("Stopped status update timer for chunk %s", chunk.ChunkID))

			// Wait 1 second before marking as complete
			time.Sleep(time.Second)

			status := TaskChunkStatusAck
			if executionErr != nil {
				status = TaskChunkStatusNack
			}

			// Mark the chunk as completed with ACK
			if err := r.UpdateTaskChunkStatus(ctx, taskID, chunk.ChunkID, status); err != nil {
				r.logHelper("ERROR", fmt.Sprintf("Error updating %s chunk status to %s: %v", taskType, status, err))
			} else {
				r.logHelper("INFO", fmt.Sprintf("Successfully completed chunk #%d (ID: %s)", chunkNum, chunk.ChunkID))
			}
		}(currentChunkCount, currentChunk)
	}

Complete:
	// Wait for all chunks to complete
	r.logHelper("INFO", fmt.Sprintf("Waiting for all chunks to complete for %s ID: %s", taskType, taskID))
	awg.Wait()
	r.logHelper("INFO", fmt.Sprintf("Completed processing all chunks for %s ID: %s (total chunks: %d)", taskType, taskID, chunkCount))

	// Mark the task as done
	_, _ = r.getTaskChunk(ctx, taskID, true)
}

// elaborateScanChunks processes distributed scan chunks with optimized port scanning
// Uses the scan configuration (templates and assets) to perform a single port scan upfront,
// then processes chunks normally, filtering targets based on port scan results
func (r *Runner) elaborateScanChunks(ctx context.Context, scanID, metaID, config string, templates, assets []string) {
	slog.Info("Starting distributed scan processing",
		"scan_id", scanID,
		"meta_id", metaID)

	// Create batcher for this scan (if log upload is enabled)
	var scanBatcher *batcher.Batcher[types.ScanLogUploadEntry]
	if scanlog.IsLogUploadEnabled() {
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

	// Step 1: Perform single port scan on all targets from scan configuration
	targetsWithOpenPorts := make(map[string]struct{})
	// If templates are empty, try to get all default nuclei templates
	templatesToUse := templates
	if len(templates) == 0 {
		defaultTemplateDir := pkg.GetNucleiDefaultTemplateDir()
		if defaultTemplateDir != "" {
			allTemplates, err := getAllNucleiTemplates(defaultTemplateDir)
			if err == nil && len(allTemplates) > 0 {
				templatesToUse = allTemplates
				slog.Info("No templates specified, using all default nuclei templates for port scan",
					slog.String("scan_id", scanID),
					slog.Int("template_count", len(allTemplates)))
			}
		}
	}
	if len(assets) > 0 && len(templatesToUse) > 0 {
		// Create temporary files for port filtering
		tmpInputFile, err := fileutil.GetTempFileName()
		if err != nil {
			slog.Error("Failed to create temp file for targets",
				slog.String("scan_id", scanID),
				slog.Any("error", err))
			return
		}
		defer func() {
			_ = os.RemoveAll(tmpInputFile)
		}()

		targetsContent := strings.Join(assets, "\n")
		if err := os.WriteFile(tmpInputFile, []byte(targetsContent), os.ModePerm); err != nil {
			slog.Error("Failed to write targets to temp file",
				slog.String("scan_id", scanID),
				slog.Any("error", err))
			return
		}

		tmpTemplatesFile, err := fileutil.GetTempFileName()
		if err != nil {
			slog.Error("Failed to create temp file for templates",
				slog.String("scan_id", scanID),
				slog.Any("error", err))
			return
		}
		defer func() {
			_ = os.RemoveAll(tmpTemplatesFile)
		}()

		templatesContent := strings.Join(templatesToUse, "\n")
		if err := os.WriteFile(tmpTemplatesFile, []byte(templatesContent), os.ModePerm); err != nil {
			slog.Error("Failed to write templates to temp file",
				slog.String("scan_id", scanID),
				slog.Any("error", err))
			return
		}

		// Perform port scan on all targets
		filteredTargets, _, err := pkg.FilterTargetsByTemplatePorts(ctx, tmpInputFile, tmpTemplatesFile, scanID, "pre-scan")
		if err != nil {
			slog.Warn("Error filtering targets by template ports, proceeding with all targets", "scan_id", scanID, "error", err)
			// If port scan fails, proceed with all targets
			for _, target := range assets {
				targetsWithOpenPorts[target] = struct{}{}
			}
		} else {
			// Create map of targets with open ports
			for _, target := range filteredTargets {
				targetsWithOpenPorts[target] = struct{}{}
			}
		}
	} else {
		// No targets or templates, all targets will be skipped
		if len(assets) == 0 {
			slog.Info("No targets found", "scan_id", scanID)
		} else if len(templatesToUse) == 0 {
			slog.Info("No templates found (including default templates)", "scan_id", scanID)
		}
	}

	slog.Info("Port scan completed", "scan_id", scanID, "targets_with_open_ports", len(targetsWithOpenPorts), "total_targets", len(assets))

	// Step 2: Use processChunks with a custom executeChunk callback that filters targets
	// Note: We need to capture targetsWithOpenPorts and config in the closure
	r.processChunks(ctx, scanID, "scan", func(ctx context.Context, chunk *TaskChunk) error {
		// Filter chunk targets to only include those with open ports
		filteredChunkTargets := []string{}
		for _, target := range chunk.Targets {
			if _, hasOpenPorts := targetsWithOpenPorts[target]; hasOpenPorts {
				filteredChunkTargets = append(filteredChunkTargets, target)
			}
		}

		// If no targets have open ports, skip nuclei execution
		// Note: processChunks will have already set status to in_progress, so we'll ACK it
		if len(filteredChunkTargets) == 0 {
			slog.Info("Skipping chunk - all targets are unresponsive (no open ports)", "scan_id", scanID, "chunk_id", chunk.ChunkID, "original_target_count", len(chunk.Targets))
			// Return nil to indicate success (chunk is skipped, not failed)
			// processChunks will mark it as ACK
			return nil
		}

		slog.Info("Processing chunk with filtered targets", "scan_id", scanID, "chunk_id", chunk.ChunkID, "filtered_target_count", len(filteredChunkTargets), "original_target_count", len(chunk.Targets))

		// Execute nuclei scan with filtered targets and shared batcher
		r.executeNucleiScan(ctx, scanID, chunk.ChunkID, config, chunk.PublicTemplates, filteredChunkTargets, scanBatcher)
		return nil
	})
}

// elaborateScan processes a non-distributed scan using the same logic as pd-agent
func (r *Runner) elaborateScan(ctx context.Context, scanID, metaID, config string, templates, assets []string) {
	r.logHelper("INFO", fmt.Sprintf("elaborateScan: scanID=%s, metaID=%s, templates=%d, assets=%d", scanID, metaID, len(templates), len(assets)))
	r.executeNucleiScan(ctx, scanID, metaID, config, templates, assets, nil)
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
		r.logHelper("INFO", fmt.Sprintf("Completed enumeration for enumID=%s, metaID=%s\nStdout: %s\nStderr: %s", enumID, metaID, taskResult.Stdout, taskResult.Stderr))
	} else {
		r.logHelper("INFO", fmt.Sprintf("Completed enumeration for enumID=%s, metaID=%s", enumID, metaID))
	}
}

// elaborateEnumerationChunks processes distributed enumeration chunks using the same logic as pd-agent
func (r *Runner) elaborateEnumerationChunks(ctx context.Context, enumID, metaID string, steps, assets []string) {
	r.processChunks(ctx, enumID, "enumeration", func(ctx context.Context, chunk *TaskChunk) error {
		// Execute the chunk using the shared enumeration execution logic
		r.executeEnumeration(ctx, enumID, chunk.ChunkID, steps, chunk.Targets)
		return nil
	})
}

// elaborateEnumeration processes a non-distributed enumeration
func (r *Runner) elaborateEnumeration(ctx context.Context, enumID, metaID string, steps, assets []string) {
	r.logHelper("INFO", fmt.Sprintf("elaborateEnumeration: enumID=%s, metaID=%s, steps=%d, assets=%d", enumID, metaID, len(steps), len(assets)))
	r.executeEnumeration(ctx, enumID, metaID, steps, assets)
}

// fetchScanConfig fetches scan configuration
func (r *Runner) fetchScanConfig(scanID string) (string, error) {
	apiURL := fmt.Sprintf("%s/v1/scans/%s/config", pkg.PCDPApiServer, scanID)
	resp := r.makeRequest(context.Background(), http.MethodGet, apiURL, nil, nil)
	if resp.Error != nil {
		return "", resp.Error
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(resp.Body))
	}

	return string(resp.Body), nil
}

// fetchSingleConfig fetches a single scan configuration
func (r *Runner) fetchSingleConfig(scanConfigId string) (string, error) {
	apiURL := fmt.Sprintf("%s/v1/scans/config/%s", pkg.PCDPApiServer, scanConfigId)
	resp := r.makeRequest(context.Background(), http.MethodGet, apiURL, nil, nil)
	if resp.Error != nil {
		return "", resp.Error
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(resp.Body))
	}

	return string(resp.Body), nil
}

// fetchAssets fetches assets for an enumeration
func (r *Runner) fetchAssets(enumerationID string) ([]byte, error) {
	apiURL := fmt.Sprintf("%s/v1/asset/enumerate/%s/export", pkg.PCDPApiServer, enumerationID)
	resp := r.makeRequest(context.Background(), http.MethodGet, apiURL, nil, nil)
	if resp.Error != nil {
		return nil, resp.Error
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(resp.Body))
	}

	return resp.Body, nil
}

// fetchEnumerationConfig fetches enumeration configuration
func (r *Runner) fetchEnumerationConfig(enumerationId string) (string, error) {
	apiURL := fmt.Sprintf("%s/v1/asset/enumerate/%s/config", pkg.PCDPApiServer, enumerationId)
	resp := r.makeRequest(context.Background(), http.MethodGet, apiURL, nil, nil)
	if resp.Error != nil {
		return "", resp.Error
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(resp.Body))
	}

	return string(resp.Body), nil
}

// UpdateTaskChunkStatus updates the status of a task chunk (ACK, NACK, or in_progress)
func (r *Runner) UpdateTaskChunkStatus(ctx context.Context, taskID, chunkID string, status TaskChunkStatus) error {
	apiURL := fmt.Sprintf("%s/v1/tasks/%s/chunk/%s", pkg.PCDPApiServer, taskID, chunkID)

	client, err := client.CreateAuthenticatedClient(r.options.TeamID, PDCPApiKey)
	if err != nil {
		return fmt.Errorf("error creating authenticated client: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, nil)
	if err != nil {
		return fmt.Errorf("error creating request: %v", err)
	}

	// Add status query parameter
	q := req.URL.Query()
	q.Add("status", string(status))
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %v", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	// Parse response to check if ok is true
	var response struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("error unmarshaling response: %v", err)
	}

	if !response.OK {
		return fmt.Errorf("server returned ok=false")
	}

	return nil
}

// getTaskChunk fetches a task chunk from the API
func (r *Runner) getTaskChunk(ctx context.Context, taskID string, done bool) (*TaskChunk, error) {
	apiURL := fmt.Sprintf("%s/v1/tasks/%s/chunk", pkg.PCDPApiServer, taskID)

	client, err := client.CreateAuthenticatedClient(r.options.TeamID, PDCPApiKey)
	if err != nil {
		return nil, fmt.Errorf("error creating authenticated client: %v", err)
	}

	if done {
		apiURL = fmt.Sprintf("%s?done=true", apiURL)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %v", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var taskChunk TaskChunk
	if err := json.Unmarshal(body, &taskChunk); err != nil {
		return nil, fmt.Errorf("error unmarshaling response: %v", err)
	}

	// Check if the unmarshaled struct is empty (no more chunks)
	if taskChunk.ChunkID == "" {
		return nil, fmt.Errorf("no more chunks")
	}

	return &taskChunk, nil
}

// In handles agent registration with the punch-hole server
func (r *Runner) In(ctx context.Context) error {
	ticker := time.NewTicker(time.Minute)
	defer func() {
		ticker.Stop()
		if err := r.Out(context.TODO()); err != nil {
			r.logHelper("WARNING", fmt.Sprintf("error deregistering agent: %v", err))
		} else {
			r.logHelper("INFO", "deregistered agent")
		}
	}()

	// Run first time to register
	if err := r.inFunctionTickCallback(ctx); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := r.inFunctionTickCallback(ctx); err != nil {
				return err
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
	networksToUse := r.options.AgentNetworks
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
				r.options.AgentNetworks = agentInfo.Networks // Overwrite local networks with remote
			}
			// Handle agent name
			if agentInfo.Name != "" && r.options.AgentName != agentInfo.Name {
				r.logHelper("INFO", fmt.Sprintf("Using agent name from %s server: %s (was: %s)", PdcpApiServer, agentInfo.Name, r.options.AgentName))
				r.options.AgentName = agentInfo.Name
			}
			r.logHelper("INFO", fmt.Sprintf("Agent last updated at: %s", lastUpdate.Format(time.RFC3339)))
		}
	}

	// Build /in endpoint with query parameters
	inURL := fmt.Sprintf("%s/v1/agents/in", PdcpApiServer)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, inURL, nil)
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
		r.logHelper("INFO", fmt.Sprintf("Discovered network subnets: %v", networkSubnets))
		q.Add("network_subnets", strings.Join(networkSubnets, ","))
	} else {
		r.logHelper("INFO", "No network subnets discovered")
	}

	req.URL.RawQuery = q.Encode()

	inResp := r.makeRequest(ctx, http.MethodPost, req.URL.String(), nil, headers)
	if inResp.Error != nil {
		r.logHelper("ERROR", fmt.Sprintf("failed to call /in endpoint: %v", inResp.Error))
		return inResp.Error
	}

	if inResp.StatusCode != http.StatusOK {
		r.logHelper("ERROR", fmt.Sprintf("unexpected status code from /in endpoint: %d, body: %s", inResp.StatusCode, string(inResp.Body)))
		return fmt.Errorf("unexpected status code from /in endpoint: %v, body: %s", inResp.StatusCode, string(inResp.Body))
	}

	if !isRegistered {
		r.logHelper("INFO", "agent registered successfully")
		isRegistered = true
	}

	r.logHelper("INFO", fmt.Sprintf("/in requests sent: %d, agent up since: %s", r.inRequestCount, r.agentStartTime.Format(time.RFC3339)))
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
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
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
			fmt.Printf("[INFO] Cached %d Kubernetes subnets for reuse\n", len(k8sSubnetsCache))
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
		slog.Info("Found service CIDRs", "count", len(serviceCidrs), "cidrs", serviceCidrs)
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
		slog.Info("Aggregated node IPs into supernets", "node_count", len(nodeIPs), "supernet_count", len(nodeSupernets), "supernets", nodeSupernets)
		assets = append(assets, nodeSupernets...)
	}

	if len(podCidrs) > 0 {
		podSupernets := supernetMultiple(podCidrs)
		slog.Info("Aggregated pod CIDRs into supernets", "pod_count", len(podCidrs), "supernet_count", len(podSupernets), "supernets", podSupernets)
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
	for i := 0; i < 4; i++ {
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

// startPassiveDiscovery starts passive discovery on all network interfaces using libpcap/gopacket
// func (r *Runner) startPassiveDiscovery() {
// 	passiveDiscoveredIPs = mapsutil.NewSyncLockMap[string, struct{}]()
// 	ifs, err := pcap.FindAllDevs()
// 	if err != nil {
// 		slog.Error("Could not list interfaces for passive discovery: %v", err)
// 		return
// 	}
// 	for _, iface := range ifs {
// 		go func(iface pcap.Interface) {
// 			handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
// 			if err != nil {
// 				slog.Error("Could not open interface %s: %v", iface.Name, err)
// 				return
// 			}
// 			defer handle.Close()
// 			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
// 			for packet := range packetSource.Packets() {
// 				if netLayer := packet.NetworkLayer(); netLayer != nil {
// 					src, dst := netLayer.NetworkFlow().Endpoints()
// 					for _, ep := range []gopacket.Endpoint{src, dst} {
// 						ip := net.ParseIP(ep.String())
// 						if ip != nil && ip.IsPrivate() {
// 							_ = passiveDiscoveredIPs.Set(ip.String(), struct{}{})
// 						}
// 					}
// 				}
// 			}
// 		}(iface)
// 	}
// 	slog.Info("Started passive discovery on all interfaces")
// }

// PopAllPassiveDiscoveredIPs retrieves all passively discovered IPs and clears the map
// func PopAllPassiveDiscoveredIPs() []string {
// 	if passiveDiscoveredIPs == nil {
// 		return nil
// 	}
// 	var ips []string
// 	_ = passiveDiscoveredIPs.Iterate(func(k string, v struct{}) error {
// 		ips = append(ips, k)
// 		return nil
// 	})
// 	for _, k := range ips {
// 		passiveDiscoveredIPs.Delete(k)
// 	}
// 	return ips
// }

// computeScanConfigHash computes a hash of the scan configuration
func computeScanConfigHash(scanConfig string, templates []string, assets []string) string {
	h := sha256.New()

	// Sort arrays to ensure consistent hashing
	sort.Strings(templates)
	sort.Strings(assets)

	h.Write([]byte(scanConfig))
	h.Write([]byte(strings.Join(templates, ",")))
	h.Write([]byte(strings.Join(assets, ",")))

	return fmt.Sprintf("%x", h.Sum(nil))
}

// sanitizeEnumerationConfig removes unsupported steps from the enumeration config.
// Steps "uncover_assets", "dns_passive", "dns_bruteforce", and "dns_permute" are not supported for internal scans and will be removed.
// Returns the sanitized configuration as a JSON string.
func (r *Runner) sanitizeEnumerationConfig(enumerationConfig string, enumerationName string) string {
	var unsupportedSteps []string
	var supportedSteps []string

	// Extract all steps from the enumeration config
	gjson.Parse(enumerationConfig).Get("steps").ForEach(func(key, value gjson.Result) bool {
		step := value.String()
		if step == "uncover_assets" || step == "dns_passive" || step == "dns_bruteforce" || step == "dns_permute" {
			unsupportedSteps = append(unsupportedSteps, step)
		} else {
			supportedSteps = append(supportedSteps, step)
		}
		return true
	})

	// If no unsupported steps found, return the original config
	if len(unsupportedSteps) == 0 {
		return enumerationConfig
	}

	// Log info about removed steps
	r.logHelper("INFO", fmt.Sprintf("Removing unsupported steps from enumeration \"%s\": %s", enumerationName, strings.Join(unsupportedSteps, ", ")))

	// Parse the entire config as JSON to properly reconstruct it
	var configMap map[string]interface{}
	if err := json.Unmarshal([]byte(enumerationConfig), &configMap); err != nil {
		// If parsing fails, return original config
		r.logHelper("WARNING", fmt.Sprintf("Failed to parse enumeration config for sanitization: %v", err))
		return enumerationConfig
	}

	// Update the steps array with only supported steps
	configMap["steps"] = supportedSteps

	// Reconstruct the JSON
	sanitizedConfig, err := json.Marshal(configMap)
	if err != nil {
		// If marshaling fails, return original config
		r.logHelper("WARNING", fmt.Sprintf("Failed to marshal sanitized enumeration config: %v", err))
		return enumerationConfig
	}

	return string(sanitizedConfig)
}

// computeEnumerationConfigHash computes a hash of the enumeration configuration
func computeEnumerationConfigHash(steps []string, assets []string) string {
	h := sha256.New()

	// Sort arrays to ensure consistent hashing
	sort.Strings(steps)
	sort.Strings(assets)

	h.Write([]byte(strings.Join(steps, ",")))
	h.Write([]byte(strings.Join(assets, ",")))

	return fmt.Sprintf("%x", h.Sum(nil))
}

// parseOptions parses command line options (simplified for agent mode only)
func parseOptions() *Options {
	options := &Options{
		TeamID: TeamIDEnv,
	}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`pd-agent is an agent for ProjectDiscovery Cloud Platform`)

	agentTags := strings.Split(AgentTagsEnv, ",")

	// Parse default parallelism values from environment
	defaultChunkParallelism := runtime.NumCPU()
	if defaultChunkParallelism <= 0 {
		defaultChunkParallelism = 1
	}
	if val, err := strconv.Atoi(ChunkParallelismEnv); err == nil && val > 0 {
		defaultChunkParallelism = val
	}

	defaultScanParallelism := 1
	if val, err := strconv.Atoi(ScanParallelismEnv); err == nil && val > 0 {
		defaultScanParallelism = val
	}

	defaultEnumerationParallelism := 1
	if val, err := strconv.Atoi(EnumerationParallelismEnv); err == nil && val > 0 {
		defaultEnumerationParallelism = val
	}

	flagSet.CreateGroup("agent", "Agent",
		flagSet.BoolVar(&options.Verbose, "verbose", false, "show verbose output"),
		flagSet.BoolVar(&options.KeepOutputFiles, "keep-output-files", false, "keep output files after processing (default: false, files are deleted immediately after processing)"),
		flagSet.StringVar(&options.AgentOutput, "agent-output", "", "agent output folder"),
		flagSet.StringSliceVarP(&options.AgentTags, "agent-tags", "at", agentTags, "specify the tags for the agent", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&options.AgentNetworks, "agent-networks", "an", nil, "specify the networks for the agent", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringVar(&options.AgentName, "agent-name", "", "specify the name for the agent"),
		flagSet.BoolVar(&options.PassiveDiscovery, "passive-discovery", false, "enable passive discovery via libpcap/gopacket"),
		flagSet.IntVarP(&options.ChunkParallelism, "chunk-parallelism", "c", defaultChunkParallelism, "number of chunks to process in parallel"),
		flagSet.IntVarP(&options.ScanParallelism, "scan-parallelism", "s", defaultScanParallelism, "number of scans to process in parallel"),
		flagSet.IntVarP(&options.EnumerationParallelism, "enumeration-parallelism", "e", defaultEnumerationParallelism, "number of enumerations to process in parallel"),
		flagSet.StringVar(&options.SupervisorMode, "supervisor-mode", "", "run as supervisor: \"docker\" or \"kubernetes\" (default: empty, disabled)"),
	)

	if err := flagSet.Parse(); err != nil {
		slog.Error("error", "error", err)
	}

	// Validate supervisor mode
	if options.SupervisorMode != "" {
		if options.SupervisorMode != "docker" && options.SupervisorMode != "kubernetes" {
			slog.Error("Invalid supervisor mode", "mode", options.SupervisorMode, "valid", "docker or kubernetes")
			options.SupervisorMode = "" // disable supervisor mode if invalid
		}
	}

	// Parse environment variables (env vars take precedence as defaults)
	if agentTags := os.Getenv("PDCP_AGENT_TAGS"); agentTags != "" && len(options.AgentTags) == 0 {
		options.AgentTags = goflags.StringSlice(strings.Split(agentTags, ","))
	}
	if agentNetworks := os.Getenv("PDCP_AGENT_NETWORKS"); agentNetworks != "" && len(options.AgentNetworks) == 0 {
		options.AgentNetworks = goflags.StringSlice(strings.Split(agentNetworks, ","))
	}
	if agentOutput := os.Getenv("PDCP_AGENT_OUTPUT"); agentOutput != "" && options.AgentOutput == "" {
		options.AgentOutput = agentOutput
	}
	if agentName := os.Getenv("PDCP_AGENT_NAME"); agentName != "" && options.AgentName == "" {
		options.AgentName = agentName
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

	// Ensure parallelism values are at least 1
	if options.ChunkParallelism < 1 {
		options.ChunkParallelism = 1
	}
	if options.ScanParallelism < 1 {
		options.ScanParallelism = 1
	}
	if options.EnumerationParallelism < 1 {
		options.EnumerationParallelism = 1
	}

	return options
}

func configureLogging(options *Options) {
	if options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
}

// deleteCacheFileForTesting deletes the execution cache file on startup.
// This is FOR TESTING PURPOSES ONLY to ensure scans and enumerations are not skipped
// due to cached execution history.
// func deleteCacheFileForTesting() {
// 	homeDir, err := os.UserHomeDir()
// 	if err != nil {
// 		slog.Warn("Could not get home directory to delete cache file: %v", err)
// 		return
// 	}

// 	cacheFile := filepath.Join(homeDir, ".pd-agent", "execution-cache.json")
// 	if err := os.Remove(cacheFile); err != nil {
// 		if !os.IsNotExist(err) {
// 			slog.Warn("Could not delete cache file (this is ok if it doesn't exist): %v", err)
// 		}
// 	} else {
// 		slog.Info("Deleted execution cache file (FOR TESTING PURPOSES ONLY)")
// 	}
// }

func main() {
	// FOR TESTING PURPOSES ONLY: Delete the cache file containing executed scans and enumerations
	// This ensures that scans/enumerations are not skipped due to cached execution history during testing
	// deleteCacheFileForTesting()

	options := parseOptions()

	// If supervisor mode is enabled, run supervisor instead of direct agent
	if options.SupervisorMode != "" {
		runSupervisorMode(options)
		return
	}

	// Check prerequisites before starting the agent
	prerequisites := pkg.CheckAllPrerequisites()
	var missingTools []string
	for toolName, result := range prerequisites {
		if !result.Found {
			missingTools = append(missingTools, toolName)
		}
	}

	if len(missingTools) > 0 {
		slog.Error("Missing required prerequisites", "tools", strings.Join(missingTools, ", "))
	}

	pdcpRunner, err := NewRunner(options)
	if err != nil {
		slog.Error("Could not create runner", "error", err)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup close handler
	go func() {
		<-c
		fmt.Println("\r- Ctrl+C pressed in Terminal, Exiting...")
		cancel()
	}()

	err = pdcpRunner.Run(ctx)
	if err != nil {
		pdcpRunner.logHelper("FATAL", fmt.Sprintf("Could not run pd-agent: %s\n", err))
		os.Exit(1)
	}
}

// runSupervisorMode runs the agent in supervisor mode
func runSupervisorMode(options *Options) {
	// Convert Options to supervisor.AgentOptions
	agentOptions := &supervisor.AgentOptions{
		TeamID:                 options.TeamID,
		AgentID:                options.AgentId,
		AgentTags:              []string(options.AgentTags),
		AgentNetworks:          []string(options.AgentNetworks),
		AgentOutput:            options.AgentOutput,
		AgentName:              options.AgentName,
		Verbose:                options.Verbose,
		PassiveDiscovery:       options.PassiveDiscovery,
		ChunkParallelism:       options.ChunkParallelism,
		ScanParallelism:        options.ScanParallelism,
		EnumerationParallelism: options.EnumerationParallelism,
		KeepOutputFiles:        options.KeepOutputFiles,
	}

	// Generate agent ID if not set
	if agentOptions.AgentID == "" {
		agentOptions.AgentID = xid.New().String()
	}

	// Create supervisor with specified provider
	sup, err := supervisor.NewSupervisorWithProvider(agentOptions, options.SupervisorMode)
	if err != nil {
		gologger.Fatal().Msgf("Could not create supervisor: %v", err)
		os.Exit(1)
	}

	// Setup signal handlers
	ctx := sup.SetupSignalHandlers(context.Background())

	// Run supervisor
	if err := sup.Run(ctx); err != nil {
		gologger.Fatal().Msgf("Supervisor error: %v", err)
		os.Exit(1)
	}
	gologger.Info().Msg("Supervisor terminated")
}
