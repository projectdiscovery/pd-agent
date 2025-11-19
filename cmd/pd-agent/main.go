package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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
	"github.com/projectdiscovery/pd-agent/pkg/types"
	envutil "github.com/projectdiscovery/utils/env"
	mapsutil "github.com/projectdiscovery/utils/maps"
	sliceutil "github.com/projectdiscovery/utils/slice"
	syncutil "github.com/projectdiscovery/utils/sync"
	"github.com/rs/xid"
	"github.com/tidwall/gjson"
)

var (
	PDCPApiKey                = envutil.GetEnvOrDefault("PDCP_API_KEY", "")
	TeamIDEnv                 = envutil.GetEnvOrDefault("PDCP_TEAM_ID", "")
	AgentTagsEnv              = envutil.GetEnvOrDefault("PDCP_AGENT_TAGS", "default")
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
			gologger.Warning().Msgf("error saving cache: %v", err)
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
			gologger.Warning().Msgf("error saving cache: %v", err)
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
				gologger.Warning().Msgf("error creating authenticated client (attempt %d/%d): %v, retrying...", attempt, maxRetries, err)
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
				gologger.Warning().Msgf("error creating request (attempt %d/%d): %v, retrying...", attempt, maxRetries, err)
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
				gologger.Warning().Msgf("error sending request (attempt %d/%d): %v, retrying...", attempt, maxRetries, err)
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
		resp.Body.Close()
		if err != nil {
			if attempt < maxRetries {
				gologger.Warning().Msgf("error reading response (attempt %d/%d): %v, retrying...", attempt, maxRetries, err)
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
}

var (
	completedTasks = gcache.New[string, struct{}](1024).
			LRU().
			Expiration(time.Hour).
			Build()
	pendingTasks = mapsutil.NewSyncLockMap[string, struct{}]()
	// passiveDiscoveredIPs *mapsutil.SyncLockMap[string, struct{}]
)

// shouldSkipTask checks if a task (scan or enumeration) should be skipped based on
// agent assignment, tags, and networks. Logs each check in verbose mode.
// Returns true if the task should be skipped (no matching conditions), false if it should continue.
func (r *Runner) shouldSkipTask(taskType, id, name, taskAgentId string, agentTags, agentNetworks gjson.Result) bool {
	gologger.Verbose().Msgf("checking %s (%s - %s)", taskType, id, name)

	// Check if agent ID matches (case-insensitive)
	isAssignedToAgent := strings.EqualFold(taskAgentId, r.options.AgentId)
	result := "✗"
	if isAssignedToAgent {
		result = "✓"
	}
	if taskAgentId == "" {
		gologger.Verbose().Msgf("  checking id: %s (task: <empty>, agent: %s)", result, r.options.AgentId)
	} else {
		gologger.Verbose().Msgf("  checking id: %s (task: %s, agent: %s)", result, taskAgentId, r.options.AgentId)
	}

	// Check if name contains agent ID tag (case-insensitive)
	nameLower := strings.ToLower(name)
	agentIdTag := strings.ToLower("[" + r.options.AgentId + "]")
	hasAgentIdInName := strings.Contains(nameLower, agentIdTag)
	result = "✗"
	if hasAgentIdInName {
		result = "✓"
	}
	gologger.Verbose().Msgf("  checking id in name: %s (name: %s, looking for: %s)", result, name, "["+r.options.AgentId+"]")

	// Check if name contains any agent tag (case-insensitive)
	var hasTagInName bool
	var taskTagsInName []string
	for _, tag := range r.options.AgentTags {
		tagLower := strings.ToLower("[" + tag + "]")
		if strings.Contains(nameLower, tagLower) {
			hasTagInName = true
			break
		}
	}
	// Extract all tags from name for logging
	if strings.Contains(name, "[") && strings.Contains(name, "]") {
		parts := strings.Split(name, "[")
		for _, part := range parts {
			if idx := strings.Index(part, "]"); idx > 0 {
				taskTagsInName = append(taskTagsInName, part[:idx])
			}
		}
	}
	result = "✗"
	if hasTagInName {
		result = "✓"
	}
	if len(taskTagsInName) > 0 {
		gologger.Verbose().Msgf("  checking tags in name: %s (task tags in name: %v, agent tags: %v)", result, taskTagsInName, r.options.AgentTags)
	} else {
		gologger.Verbose().Msgf("  checking tags in name: %s (task tags in name: <none>, agent tags: %v)", result, r.options.AgentTags)
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
		gologger.Verbose().Msgf("  checking tags: %s (task agent_tags: %v, agent tags: %v)", result, taskAgentTags, r.options.AgentTags)
	} else {
		gologger.Verbose().Msgf("  checking tags: %s (task agent_tags: <none>, agent tags: %v)", result, r.options.AgentTags)
	}

	// Check if name contains any agent network (case-insensitive)
	var hasNetworkInName bool
	var taskNetworksInName []string
	for _, network := range r.options.AgentNetworks {
		networkLower := strings.ToLower("[" + network + "]")
		if strings.Contains(nameLower, networkLower) {
			hasNetworkInName = true
			break
		}
	}
	// Extract all networks from name for logging (same logic as tags)
	if strings.Contains(name, "[") && strings.Contains(name, "]") {
		parts := strings.Split(name, "[")
		for _, part := range parts {
			if idx := strings.Index(part, "]"); idx > 0 {
				taskNetworksInName = append(taskNetworksInName, part[:idx])
			}
		}
	}
	result = "✗"
	if hasNetworkInName {
		result = "✓"
	}
	if len(taskNetworksInName) > 0 {
		gologger.Verbose().Msgf("  checking networks in name: %s (task networks in name: %v, agent networks: %v)", result, taskNetworksInName, r.options.AgentNetworks)
	} else {
		gologger.Verbose().Msgf("  checking networks in name: %s (task networks in name: <none>, agent networks: %v)", result, r.options.AgentNetworks)
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
		gologger.Verbose().Msgf("  checking networks: %s (task agent_networks: %v, agent networks: %v)", result, taskAgentNetworks, r.options.AgentNetworks)
	} else {
		gologger.Verbose().Msgf("  checking networks: %s (task agent_networks: <none>, agent networks: %v)", result, r.options.AgentNetworks)
	}

	// If any condition matches, don't skip
	shouldContinue := isAssignedToAgent || hasAgentIdInName || hasTagInName || hasAgentTag || hasNetworkInName || hasAgentNetwork

	if shouldContinue {
		gologger.Verbose().Msgf("  %s (%s - %s) is being enqueued (matching conditions found)", taskType, id, name)
		return false // Don't skip
	}

	gologger.Verbose().Msgf("  %s (%s - %s) is being skipped (no matching conditions)", taskType, id, name)
	return true // Skip
}

// NewRunner creates a new runner instance
func NewRunner(options *Options) (*Runner, error) {
	r := &Runner{
		options:        options,
		localCache:     NewLocalCache(),
		agentStartTime: time.Now(),
	}

	if err := r.localCache.Load(); err != nil {
		gologger.Warning().Msgf("error loading cache: %v", err)
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

	// Start passive discovery if enabled
	// if r.options.PassiveDiscovery {
	// 	go r.startPassiveDiscovery()
	// }

	return r, nil
}

// Run starts the agent
func (r *Runner) Run(ctx context.Context) error {
	// Recommend the time to use on platform dashboard to schedule the scans
	gologger.Info().Msg("platform dashboard uses UTC timezone")
	now := time.Now().UTC()
	recommendedTime := now.Add(5 * time.Minute)
	gologger.Info().Msgf("recommended time to schedule scans (UTC): %s", recommendedTime.Format("2006-01-02 03:04:05 PM MST"))

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

	gologger.Info().Msg(infoMessage.String())

	return r.agentMode(ctx)
}

// agentMode runs the agent in monitoring mode
func (r *Runner) agentMode(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		if err := r.In(ctx); err != nil {
			gologger.Fatal().Msgf("error registering agent: %v", err)
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
				gologger.Error().Msgf("Error getting scans: %v", err)
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
				gologger.Error().Msgf("Error getting enumerations: %v", err)
			}
			time.Sleep(time.Minute)
		}
	}
}

// getScans fetches and processes scans from the API
func (r *Runner) getScans(ctx context.Context) error {
	gologger.Verbose().Msg("Retrieving scans...")
	apiURL := fmt.Sprintf("%s/v1/scans", pkg.PCDPApiServer)

	awg, err := syncutil.New(syncutil.WithSize(r.options.ScanParallelism))
	if err != nil {
		gologger.Error().Msgf("Error creating syncutil: %v", err)
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
			gologger.Verbose().Msgf("Total pages: %d", totalPages)
		}

		gologger.Verbose().Msgf("Processing page %d of %d\n", currentPage, totalPages)

		// Process scans in parallel
		result.Get("data").ForEach(func(key, value gjson.Result) bool {
			id := value.Get("scan_id").String()
			if id == "" {
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
						gologger.Error().Msgf("Error parsing start time: %v", err)
						return
					}
					targetExecutionTime = parsedStartTime
				}

				if schedule.Exists() {
					nextRun := schedule.Get("schedule_next_run").String()
					if nextRun != "" {
						nextRunTime, err := time.Parse(time.RFC3339, nextRun)
						if err != nil {
							gologger.Error().Msgf("Error parsing next run time: %v", err)
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
						gologger.Verbose().Msgf("skipping scan \"%s\" as it's scheduled for %s (current time: %s)\n", name, targetExecutionTime, now)
						return
					}
				}

				metaId := fmt.Sprintf("%s-%s", scanID, targetExecutionTime)

				// First check completed and pending tasks
				if completedTasks.Has(metaId) {
					gologger.Verbose().Msgf("skipping scan \"%s\" as it's already completed recently\n", name)
					return
				}

				if pendingTasks.Has(metaId) {
					gologger.Verbose().Msgf("skipping scan \"%s\" as it's already in progress\n", name)
					return
				}

				// Fetch minimal config first to compute hash
				scanConfig, err := r.fetchScanConfig(scanID)
				if err != nil {
					gologger.Error().Msgf("Error fetching scan config for ID %s: %v", scanID, err)
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
						gologger.Error().Msgf("Error fetching scan config for ID %s: %v", id, err)
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
								gologger.Error().Msgf("Error decoding base64 config: %v", err)
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
						gologger.Error().Msgf("Error fetching assets for enumeration ID %s: %v", enumerationID, err)
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
					gologger.Verbose().Msgf("skipping scan \"%s\" as it was already executed with same configuration\n", name)
					return
				}

				gologger.Info().Msgf("scan \"%s\" enqueued...\n", name)

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
	gologger.Verbose().Msg("Waiting for all scans to complete...")
	awg.Wait()

	return nil
}

// getEnumerations fetches and processes enumerations from the API
func (r *Runner) getEnumerations(ctx context.Context) error {
	gologger.Verbose().Msg("Retrieving enumerations...")
	apiURL := fmt.Sprintf("%s/v1/asset/enumerate", pkg.PCDPApiServer)

	awg, err := syncutil.New(syncutil.WithSize(r.options.EnumerationParallelism))
	if err != nil {
		gologger.Error().Msgf("Error creating syncutil: %v", err)
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
			gologger.Verbose().Msgf("Total pages: %d", totalPages)
		}

		gologger.Verbose().Msgf("Processing page %d of %d\n", currentPage, totalPages)

		// Process enumerations in parallel
		result.Get("data").ForEach(func(key, value gjson.Result) bool {
			id := value.Get("id").String()
			if id == "" {
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
						gologger.Error().Msgf("Error parsing start time: %v", err)
						return
					}
					targetExecutionTime = parsedStartTime
				}

				if schedule.Exists() {
					nextRun := schedule.Get("schedule_next_run").String()
					if nextRun != "" {
						nextRunTime, err := time.Parse(time.RFC3339, nextRun)
						if err != nil {
							gologger.Error().Msgf("Error parsing next run time: %v", err)
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
						gologger.Verbose().Msgf("skipping enumeration \"%s\" as it's scheduled for %s (current time: %s)\n", name, targetExecutionTime, now)
						return
					}
				}

				metaId := fmt.Sprintf("%s-%s", enumID, targetExecutionTime)

				// First check completed and pending tasks
				if completedTasks.Has(metaId) {
					gologger.Verbose().Msgf("skipping enumeration \"%s\" as it's already completed recently\n", name)
					return
				}

				if pendingTasks.Has(metaId) {
					gologger.Verbose().Msgf("skipping enumeration \"%s\" as it's already in progress\n", name)
					return
				}

				// Fetch minimal config first
				enumerationConfig, err := r.fetchEnumerationConfig(enumID)
				if err != nil {
					gologger.Error().Msgf("Error fetching enumeration config for ID %s: %v", enumID, err)
					return
				}

				gologger.Verbose().Msgf("Before sanitization: %s", enumerationConfig)

				// Sanitize enumeration config (remove unsupported steps)
				enumerationConfig = sanitizeEnumerationConfig(enumerationConfig, name)

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
					gologger.Verbose().Msgf("skipping enumeration \"%s\" as it was already executed with same configuration\n", name)
					return
				}

				gologger.Info().Msgf("enumeration \"%s\" enqueued...\n", name)

				isDistributed := behavior == "distribute"

				// Check if passive discovery is enabled for this enumeration
				// hasPassiveDiscovery := value.Get("worker_passive_discover").Bool()
				// if hasPassiveDiscovery && r.options.PassiveDiscovery {
				// 	discoveredIPs := PopAllPassiveDiscoveredIPs()
				// 	if len(discoveredIPs) > 0 {
				// 		gologger.Info().Msgf("Adding %d passively discovered IPs to enumeration %s: %s", len(discoveredIPs), scanName, strings.Join(discoveredIPs, ","))
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
	gologger.Verbose().Msg("Waiting for all enumerations to complete...")
	awg.Wait()

	return nil
}

// executeNucleiScan is the shared implementation for executing nuclei scans
// using the same logic as pd-agent
func (r *Runner) executeNucleiScan(ctx context.Context, scanID, metaID, config string, templates, assets []string) {
	// Set output directory if agent output is specified
	var outputDir string
	if r.options.AgentOutput != "" {
		outputDir = filepath.Join(r.options.AgentOutput, metaID)
	}

	// Create task similar to pd-agent
	task := &types.Task{
		Tool: types.Nuclei,
		Options: types.Options{
			Hosts:     assets,
			Templates: templates,
			Silent:    true,
			ScanID:    scanID,
			Config:    config,
			TeamID:    r.options.TeamID,
			Output:    outputDir,
		},
		Id: metaID,
	}

	// Execute using the same pkg.Run logic as pd-agent
	gologger.Info().Msgf("Starting nuclei scan for scanID=%s, metaID=%s", scanID, metaID)
	taskResult, err := pkg.Run(ctx, task)
	if err != nil {
		gologger.Error().Msgf("Nuclei scan execution failed: %v", err)
		return
	}

	if taskResult != nil {
		gologger.Info().Msgf("Completed nuclei scan for scanID=%s, metaID=%s\nStdout: %s\nStderr: %s", scanID, metaID, taskResult.Stdout, taskResult.Stderr)
	} else {
		gologger.Info().Msgf("Completed nuclei scan for scanID=%s, metaID=%s", scanID, metaID)
	}
}

// processChunks is a generic chunk processing method that handles the common logic
// for pulling chunks, updating status, and executing them
func (r *Runner) processChunks(ctx context.Context, taskID, taskType string, executeChunk func(ctx context.Context, chunk *TaskChunk) error) {
	gologger.Info().Msgf("Starting distributed %s processing for %s ID: %s", taskType, taskType, taskID)

	awg, err := syncutil.New(syncutil.WithSize(r.options.ChunkParallelism))
	if err != nil {
		gologger.Error().Msgf("Error creating syncutil: %v", err)
		return
	}

	chunkCount := 0
	for {
		chunkCount++
		gologger.Info().Msgf("Fetching chunk #%d for %s ID: %s", chunkCount, taskType, taskID)

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
			currentErr := err.Error()
			if currentErr == lastErr {
				// If we get the same error multiple times, likely the task is complete
				gologger.Info().Msgf("%s ID %s completed successfully", taskType, taskID)
				goto Complete
			}
			lastErr = currentErr
			retryCount++
			if retryCount < maxRetries {
				time.Sleep(time.Second * 3)
			}
		}

		if err != nil {
			gologger.Error().Msgf("Failed to get chunk after %d retries: %v", maxRetries, err)
			break
		}

		if chunk == nil {
			gologger.Info().Msgf("No more chunks available for %s ID: %s", taskType, taskID)
			break
		}

		currentChunkCount := chunkCount
		currentChunk := chunk

		// Add chunk to wait group and process in parallel
		awg.Add()
		go func(chunkNum int, chunk *TaskChunk) {
			defer awg.Done()

			gologger.Info().Msgf("Processing chunk #%d (ID: %s) with %d targets",
				chunkNum,
				chunk.ChunkID,
				len(chunk.Targets))

			// Set initial status to in_progress
			if err := r.UpdateTaskChunkStatus(ctx, taskID, chunk.ChunkID, TaskChunkStatusInProgress); err != nil {
				gologger.Error().Msgf("Error updating %s chunk status: %v", taskType, err)
			} else {
				gologger.Info().Msgf("Updated chunk %s status to in_progress", chunk.ChunkID)
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
							gologger.Error().Msgf("Error updating %s chunk status: %v", taskType, err)
						} else {
							gologger.Debug().Msgf("Updated chunk %s status to in_progress (heartbeat)", chunkID)
						}
					}
				}
			}(timerCtx, taskID, chunk.ChunkID)

			// Execute the chunk using the provided callback
			executionErr := executeChunk(ctx, chunk)
			if executionErr != nil {
				gologger.Error().Msgf("Error executing %s chunk: %v", taskType, err)
			}

			// Stop the heartbeat timer
			timerCtxCancel()
			gologger.Debug().Msgf("Stopped status update timer for chunk %s", chunk.ChunkID)

			// Wait 1 second before marking as complete
			time.Sleep(time.Second)

			status := TaskChunkStatusAck
			if executionErr != nil {
				status = TaskChunkStatusNack
			}

			// Mark the chunk as completed with ACK
			if err := r.UpdateTaskChunkStatus(ctx, taskID, chunk.ChunkID, status); err != nil {
				gologger.Error().Msgf("Error updating %s chunk status to %s: %v", taskType, status, err)
			} else {
				gologger.Info().Msgf("Successfully completed chunk #%d (ID: %s)", chunkNum, chunk.ChunkID)
			}
		}(currentChunkCount, currentChunk)
	}

Complete:
	// Wait for all chunks to complete
	gologger.Info().Msgf("Waiting for all chunks to complete for %s ID: %s", taskType, taskID)
	awg.Wait()
	gologger.Info().Msgf("Completed processing all chunks for %s ID: %s (total chunks: %d)", taskType, taskID, chunkCount)

	// Mark the task as done
	_, _ = r.getTaskChunk(ctx, taskID, true)
}

// elaborateScanChunks processes distributed scan chunks using the same logic as pd-agent
func (r *Runner) elaborateScanChunks(ctx context.Context, scanID, metaID, config string, templates, assets []string) {
	r.processChunks(ctx, scanID, "scan", func(ctx context.Context, chunk *TaskChunk) error {
		// Execute the chunk using the shared scan execution logic
		r.executeNucleiScan(ctx, scanID, chunk.ChunkID, config, chunk.PublicTemplates, chunk.Targets)
		return nil
	})
}

// elaborateScan processes a non-distributed scan using the same logic as pd-agent
func (r *Runner) elaborateScan(ctx context.Context, scanID, metaID, config string, templates, assets []string) {
	gologger.Info().Msgf("elaborateScan: scanID=%s, metaID=%s, templates=%d, assets=%d", scanID, metaID, len(templates), len(assets))
	r.executeNucleiScan(ctx, scanID, metaID, config, templates, assets)
}

// executeEnumeration is the shared implementation for executing enumerations
// using the same logic as pd-agent
func (r *Runner) executeEnumeration(ctx context.Context, enumID, metaID string, steps, assets []string) {
	gologger.Info().Msgf("Starting enumeration for enumID=%s, metaID=%s, steps=%d, assets=%d", enumID, metaID, len(steps), len(assets))

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
	taskResult, err := pkg.Run(ctx, task)
	if err != nil {
		gologger.Error().Msgf("Enumeration execution failed: %v", err)
		return
	}

	if taskResult != nil {
		gologger.Info().Msgf("Completed enumeration for enumID=%s, metaID=%s\nStdout: %s\nStderr: %s", enumID, metaID, taskResult.Stdout, taskResult.Stderr)
	} else {
		gologger.Info().Msgf("Completed enumeration for enumID=%s, metaID=%s", enumID, metaID)
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
	gologger.Info().Msgf("elaborateEnumeration: enumID=%s, metaID=%s, steps=%d, assets=%d", enumID, metaID, len(steps), len(assets))
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

	return &taskChunk, nil
}

// In handles agent registration with the punch-hole server
func (r *Runner) In(ctx context.Context) error {
	ticker := time.NewTicker(time.Minute)
	defer func() {
		ticker.Stop()
		if err := r.Out(context.TODO()); err != nil {
			gologger.Warning().Msgf("error deregistering agent: %v", err)
		} else {
			gologger.Info().Msgf("deregistered agent")
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
		gologger.Error().Msgf("failed to fetch agent info: %v", resp.Error)
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
				gologger.Info().Msgf("Using tags from %s server: %v (was: %v)", PdcpApiServer, agentInfo.Tags, tagsToUse)
				tagsToUse = agentInfo.Tags
				r.options.AgentTags = agentInfo.Tags // Overwrite local tags with remote
			}
			if len(agentInfo.Networks) > 0 && !sliceutil.Equal(networksToUse, agentInfo.Networks) {
				gologger.Info().Msgf("Using networks from %s server: %v (was: %v)", PdcpApiServer, agentInfo.Networks, networksToUse)
				networksToUse = agentInfo.Networks
				r.options.AgentNetworks = agentInfo.Networks // Overwrite local networks with remote
			}
			// Handle agent name
			if agentInfo.Name != "" && r.options.AgentName != agentInfo.Name {
				gologger.Info().Msgf("Using agent name from %s server: %s (was: %s)", PdcpApiServer, agentInfo.Name, r.options.AgentName)
				r.options.AgentName = agentInfo.Name
			}
			gologger.Info().Msgf("Agent last updated at: %s", lastUpdate.Format(time.RFC3339))
		}
	}

	// Build /in endpoint with query parameters
	inURL := fmt.Sprintf("%s/v1/agents/in", PdcpApiServer)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, inURL, nil)
	if err != nil {
		gologger.Error().Msgf("failed to create /in request: %v", err)
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
		gologger.Info().Msgf("Discovered network subnets: %v", networkSubnets)
		q.Add("network_subnets", strings.Join(networkSubnets, ","))
	} else {
		gologger.Info().Msg("No network subnets discovered")
	}

	req.URL.RawQuery = q.Encode()

	inResp := r.makeRequest(ctx, http.MethodPost, req.URL.String(), nil, headers)
	if inResp.Error != nil {
		gologger.Error().Msgf("failed to call /in endpoint: %v", inResp.Error)
		return inResp.Error
	}

	if inResp.StatusCode != http.StatusOK {
		gologger.Error().Msgf("unexpected status code from /in endpoint: %d, body: %s", inResp.StatusCode, string(inResp.Body))
		return fmt.Errorf("unexpected status code from /in endpoint: %v, body: %s", inResp.StatusCode, string(inResp.Body))
	}

	if !isRegistered {
		gologger.Info().Msgf("agent registered successfully")
		isRegistered = true
	}

	gologger.Info().Msgf("/in requests sent: %d, agent up since: %s", r.inRequestCount, r.agentStartTime.Format(time.RFC3339))
	return nil
}

// Out handles agent deregistration
func (r *Runner) Out(ctx context.Context) error {
	endpoint := fmt.Sprintf("%s/v1/agents/out?id=%s&type=agent", PdcpApiServer, r.options.AgentId)
	resp := r.makeRequest(ctx, http.MethodPost, endpoint, nil, nil)
	if resp.Error != nil {
		gologger.Error().Msgf("failed to call /out endpoint: %v", resp.Error)
		return resp.Error
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code from /out endpoint: %v, body: %s", resp.StatusCode, string(resp.Body))
	}

	if isRegistered {
		gologger.Info().Msgf("agent deregistered successfully")
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
		gologger.Error().Msgf("Error getting network interfaces: %v", err)
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
		gologger.Error().Msgf("Error reading hosts file: %v", err)
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

	return targets
}

// startPassiveDiscovery starts passive discovery on all network interfaces using libpcap/gopacket
// func (r *Runner) startPassiveDiscovery() {
// 	passiveDiscoveredIPs = mapsutil.NewSyncLockMap[string, struct{}]()
// 	ifs, err := pcap.FindAllDevs()
// 	if err != nil {
// 		gologger.Error().Msgf("Could not list interfaces for passive discovery: %v", err)
// 		return
// 	}
// 	for _, iface := range ifs {
// 		go func(iface pcap.Interface) {
// 			handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
// 			if err != nil {
// 				gologger.Error().Msgf("Could not open interface %s: %v", iface.Name, err)
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
// 	gologger.Info().Msg("Started passive discovery on all interfaces")
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
func sanitizeEnumerationConfig(enumerationConfig string, enumerationName string) string {
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
	gologger.Info().Msgf("Removing unsupported steps from enumeration \"%s\": %s", enumerationName, strings.Join(unsupportedSteps, ", "))

	// Parse the entire config as JSON to properly reconstruct it
	var configMap map[string]interface{}
	if err := json.Unmarshal([]byte(enumerationConfig), &configMap); err != nil {
		// If parsing fails, return original config
		gologger.Warning().Msgf("Failed to parse enumeration config for sanitization: %v", err)
		return enumerationConfig
	}

	// Update the steps array with only supported steps
	configMap["steps"] = supportedSteps

	// Reconstruct the JSON
	sanitizedConfig, err := json.Marshal(configMap)
	if err != nil {
		// If marshaling fails, return original config
		gologger.Warning().Msgf("Failed to marshal sanitized enumeration config: %v", err)
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
		flagSet.StringVar(&options.AgentOutput, "agent-output", "", "agent output folder"),
		flagSet.StringSliceVarP(&options.AgentTags, "agent-tags", "at", agentTags, "specify the tags for the agent", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&options.AgentNetworks, "agent-networks", "an", nil, "specify the networks for the agent", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringVar(&options.AgentName, "agent-name", "", "specify the name for the agent"),
		flagSet.BoolVar(&options.PassiveDiscovery, "passive-discovery", false, "enable passive discovery via libpcap/gopacket"),
		flagSet.IntVarP(&options.ChunkParallelism, "chunk-parallelism", "c", defaultChunkParallelism, "number of chunks to process in parallel"),
		flagSet.IntVarP(&options.ScanParallelism, "scan-parallelism", "s", defaultScanParallelism, "number of scans to process in parallel"),
		flagSet.IntVarP(&options.EnumerationParallelism, "enumeration-parallelism", "e", defaultEnumerationParallelism, "number of enumerations to process in parallel"),
	)

	if err := flagSet.Parse(); err != nil {
		gologger.Fatal().Msgf("%s\n", err)
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
// 		gologger.Warning().Msgf("Could not get home directory to delete cache file: %v", err)
// 		return
// 	}

// 	cacheFile := filepath.Join(homeDir, ".pd-agent", "execution-cache.json")
// 	if err := os.Remove(cacheFile); err != nil {
// 		if !os.IsNotExist(err) {
// 			gologger.Warning().Msgf("Could not delete cache file (this is ok if it doesn't exist): %v", err)
// 		}
// 	} else {
// 		gologger.Info().Msg("Deleted execution cache file (FOR TESTING PURPOSES ONLY)")
// 	}
// }

func main() {
	// FOR TESTING PURPOSES ONLY: Delete the cache file containing executed scans and enumerations
	// This ensures that scans/enumerations are not skipped due to cached execution history during testing
	// deleteCacheFileForTesting()

	options := parseOptions()
	pdcpRunner, err := NewRunner(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
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
		gologger.Fatal().Msgf("Could not run pd-agent: %s\n", err)
	}
}
