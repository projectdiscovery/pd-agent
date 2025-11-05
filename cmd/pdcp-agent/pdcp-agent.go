package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/projectdiscovery/gcache"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/pdtm-agent/pkg"
	"github.com/projectdiscovery/pdtm-agent/pkg/client"
	envutil "github.com/projectdiscovery/utils/env"
	mapsutil "github.com/projectdiscovery/utils/maps"
	sliceutil "github.com/projectdiscovery/utils/slice"
	"github.com/tidwall/gjson"
)

var (
	PDCPApiKey        = envutil.GetEnvOrDefault("PDCP_API_KEY", "")
	TeamIDEnv         = envutil.GetEnvOrDefault("PDCP_TEAM_ID", "")
	PunchHoleHost     = envutil.GetEnvOrDefault("PUNCH_HOLE_HOST", "proxy-dev.projectdiscovery.io")
	PunchHoleHTTPPort = envutil.GetEnvOrDefault("PUNCH_HOLE_HTTP_PORT", "8880")
)

// Options contains the configuration options for the agent
type Options struct {
	TeamID           string
	AgentId          string
	AgentTags        goflags.StringSlice
	AgentOutput      string
	AgentName        string
	Verbose          bool
	PassiveDiscovery bool // Enable passive discovery
	AgentMode        bool // Agent mode (always true for pdcp-agent)
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

	cacheDir := filepath.Join(homeDir, ".pdcp-agent")
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

	cacheFile := filepath.Join(homeDir, ".pdcp-agent", "execution-cache.json")
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
func (r *Runner) makeRequest(ctx context.Context, method, url string, body io.Reader, headers map[string]string) *Response {
	client, err := client.CreateAuthenticatedClient(r.options.TeamID, PDCPApiKey)
	if err != nil {
		return &Response{
			StatusCode: 0,
			Body:       nil,
			Error:      fmt.Errorf("error creating authenticated client: %v", err),
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return &Response{
			StatusCode: 0,
			Body:       nil,
			Error:      fmt.Errorf("error creating request: %v", err),
		}
	}

	// Add custom headers if provided
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return &Response{
			StatusCode: 0,
			Body:       nil,
			Error:      fmt.Errorf("error sending request: %v", err),
		}
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return &Response{
			StatusCode: resp.StatusCode,
			Body:       nil,
			Error:      fmt.Errorf("error reading response: %v", err),
		}
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Body:       bodyBytes,
		Error:      nil,
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
)

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

	// If no agent ID is provided, try to get the stored one or generate a new one
	if r.options.AgentId == "" {
		if storedID := getStoredAgentID(); storedID != "" {
			r.options.AgentId = storedID
		} else {
			// Generate a new agent ID
			r.options.AgentId = generateRandomString(8)
			if err := storeAgentID(r.options.AgentId); err != nil {
				gologger.Warning().Msgf("error storing agent ID: %v", err)
			}
		}
	}

	return r, nil
}

// getStoredAgentID retrieves the stored agent ID from disk
func getStoredAgentID() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	agentIDFile := filepath.Join(homeDir, ".pdcp-agent", "agent-id")
	data, err := os.ReadFile(agentIDFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// storeAgentID stores the agent ID to disk
func storeAgentID(agentID string) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("error getting home directory: %v", err)
	}
	agentIDFile := filepath.Join(homeDir, ".pdcp-agent", "agent-id")
	dir := filepath.Dir(agentIDFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("error creating directory: %v", err)
	}
	return os.WriteFile(agentIDFile, []byte(agentID), 0644)
}

// generateRandomString generates a random string of specified length
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
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
		infoMessage.WriteString(fmt.Sprintf(" (tags: %s)", strings.Join(r.options.AgentTags, ",")))
	} else {
		infoMessage.WriteString(" (no tags)")
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

	limit := 100
	offset := 0
	totalPages := 1
	currentPage := 1

	for currentPage <= totalPages {
		paginatedURL := fmt.Sprintf("%s?limit=%d&offset=%d", apiURL, limit, offset)
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

		// Process scans
		result.Get("data").ForEach(func(key, value gjson.Result) bool {
			scanName := value.Get("name").String()
			hasScanNameTag := strings.Contains(scanName, "["+r.options.AgentId+"]")
			agentId := value.Get("worker_id").String()
			isAssignedToagent := agentId == r.options.AgentId

			// Check if it has any tag in name
			var hasTagInName bool
			for _, tag := range r.options.AgentTags {
				if strings.Contains(scanName, "["+tag+"]") {
					hasTagInName = true
					break
				}
			}

			// Check if worker tag matches
			var hasWorkerTag bool
			if value.Get("worker_tags").Exists() {
				value.Get("worker_tags").ForEach(func(key, value gjson.Result) bool {
					if sliceutil.Contains(r.options.AgentTags, value.String()) {
						hasWorkerTag = true
					}
					return true
				})
			}

			if !isAssignedToagent && !hasScanNameTag && !hasTagInName && !hasWorkerTag {
				gologger.Verbose().Msgf("skipping scan %s as it's not assigned|tagged|has-tag-in-name to %s\n", scanName, r.options.AgentId)
				return true
			}

			// Parse schedule and start time
			var targetExecutionTime time.Time
			startTime := value.Get("start_time").String()
			if startTime != "" {
				parsedStartTime, err := time.Parse(time.RFC3339, startTime)
				if err != nil {
					gologger.Error().Msgf("Error parsing start time: %v", err)
					return true
				}
				targetExecutionTime = parsedStartTime
			}

			scheduleData := value.Get("schedule")
			if scheduleData.Exists() {
				nextRun := scheduleData.Get("schedule_next_run").String()
				if nextRun != "" {
					nextRunTime, err := time.Parse(time.RFC3339, nextRun)
					if err != nil {
						gologger.Error().Msgf("Error parsing next run time: %v", err)
						return true
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
					gologger.Verbose().Msgf("skipping scan %s as it's scheduled for %s (current time: %s)\n", scanName, targetExecutionTime, now)
					return true
				}
			}

			id := value.Get("scan_id").String()
			metaId := fmt.Sprintf("%s-%s", id, targetExecutionTime)

			// First check completed and pending tasks
			if completedTasks.Has(metaId) {
				gologger.Verbose().Msgf("skipping scan %s as it's already completed recently\n", scanName)
				return true
			}

			if pendingTasks.Has(metaId) {
				gologger.Verbose().Msgf("skipping scan %s as it's already in progress\n", scanName)
				return true
			}

			// Fetch minimal config first to compute hash
			scanConfig, err := r.fetchScanConfig(id)
			if err != nil {
				gologger.Error().Msgf("Error fetching scan config for ID %s: %v", id, err)
				return true
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

			var templates []string
			value.Get("public_templates").ForEach(func(key, value gjson.Result) bool {
				templates = append(templates, value.String())
				return true
			})

			workerBehavior := value.Get("worker_behavior").String()
			isDistributed := workerBehavior == "distribute"

			// Compute hash of the entire configuration
			configHash := computeScanConfigHash(finalConfig, templates, assets)

			// Skip if this exact configuration was already executed
			if r.localCache.HasScanBeenExecuted(id, configHash) && !scheduleData.Exists() {
				gologger.Verbose().Msgf("skipping scan %s as it was already executed with same configuration\n", scanName)
				return true
			}

			gologger.Info().Msgf("scan %s enqueued...\n", scanName)

			_ = pendingTasks.Set(metaId, struct{}{})

			if isDistributed {
				// Process distributed scan chunks
				r.elaborateScanChunks(ctx, id, metaId, finalConfig, templates, assets)
			} else {
				// Process non-distributed scan
				r.elaborateScan(ctx, id, metaId, finalConfig, templates, assets)
			}

			// After queueing the task, mark it as executed
			r.localCache.MarkScanExecuted(id, configHash)

			return true
		})

		currentPage++
		offset += limit
	}

	return nil
}

// getEnumerations fetches and processes enumerations from the API
func (r *Runner) getEnumerations(ctx context.Context) error {
	gologger.Verbose().Msg("Retrieving enumerations...")
	apiURL := fmt.Sprintf("%s/v1/asset/enumerate", pkg.PCDPApiServer)

	limit := 100
	offset := 0
	totalPages := 1
	currentPage := 1

	for currentPage <= totalPages {
		paginatedURL := fmt.Sprintf("%s?limit=%d&offset=%d", apiURL, limit, offset)
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

		// Process enumerations
		result.Get("data").ForEach(func(key, value gjson.Result) bool {
			scanName := value.Get("name").String()
			hasScanNameTag := strings.Contains(scanName, "["+r.options.AgentId+"]")
			agentId := value.Get("worker_id").String()
			isAssignedToagent := agentId == r.options.AgentId

			// Check if it has any tag in name
			var hasTagInName bool
			for _, tag := range r.options.AgentTags {
				if strings.Contains(scanName, "["+tag+"]") {
					hasTagInName = true
					break
				}
			}

			// Check if worker tag matches
			var hasWorkerTag bool
			if value.Get("worker_tags").Exists() {
				value.Get("worker_tags").ForEach(func(key, value gjson.Result) bool {
					if sliceutil.Contains(r.options.AgentTags, value.String()) {
						hasWorkerTag = true
					}
					return true
				})
			}

			if !isAssignedToagent && !hasScanNameTag && !hasTagInName && !hasWorkerTag {
				gologger.Verbose().Msgf("skipping enumeration %s as it's not assigned|tagged to %s\n", scanName, r.options.AgentId)
				return true
			}

			// Parse schedule and start time
			var targetExecutionTime time.Time
			startTime := value.Get("start_time").String()
			if startTime != "" {
				parsedStartTime, err := time.Parse(time.RFC3339, startTime)
				if err != nil {
					gologger.Error().Msgf("Error parsing start time: %v", err)
					return true
				}
				targetExecutionTime = parsedStartTime
			}

			scheduleData := value.Get("schedule")
			if scheduleData.Exists() {
				nextRun := scheduleData.Get("schedule_next_run").String()
				if nextRun != "" {
					nextRunTime, err := time.Parse(time.RFC3339, nextRun)
					if err != nil {
						gologger.Error().Msgf("Error parsing next run time: %v", err)
						return true
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
					gologger.Verbose().Msgf("skipping enumeration %s as it's scheduled for %s (current time: %s)\n", scanName, targetExecutionTime, now)
					return true
				}
			}

			id := value.Get("id").String()
			metaId := fmt.Sprintf("%s-%s", id, targetExecutionTime)

			// First check completed and pending tasks
			if completedTasks.Has(metaId) {
				gologger.Verbose().Msgf("skipping enumeration %s as it's already completed recently\n", scanName)
				return true
			}

			if pendingTasks.Has(metaId) {
				gologger.Verbose().Msgf("skipping enumeration %s as it's already in progress\n", scanName)
				return true
			}

			// Fetch minimal config first
			enumerationConfig, err := r.fetchEnumerationConfig(id)
			if err != nil {
				gologger.Error().Msgf("Error fetching enumeration config for ID %s: %v", id, err)
				return true
			}

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
			if r.localCache.HasEnumerationBeenExecuted(id, configHash) && !scheduleData.Exists() {
				gologger.Verbose().Msgf("skipping enumeration %s as it was already executed with same configuration\n", scanName)
				return true
			}

			gologger.Info().Msgf("enumeration %s enqueued...\n", scanName)

			workerBehavior := value.Get("worker_behavior").String()
			isDistributed := workerBehavior == "distribute"

			_ = pendingTasks.Set(metaId, struct{}{})

			if isDistributed {
				// Process distributed enumeration chunks
				r.elaborateEnumerationChunks(ctx, id, metaId, steps, assets)
			} else {
				// Process non-distributed enumeration
				r.elaborateEnumeration(ctx, id, metaId, steps, assets)
			}

			// After queueing the task, mark it as executed
			r.localCache.MarkEnumerationExecuted(id, configHash)

			return true
		})

		currentPage++
		offset += limit
	}

	return nil
}

// elaborateScanChunks processes distributed scan chunks
func (r *Runner) elaborateScanChunks(ctx context.Context, scanID, metaID, config string, templates, assets []string) {
	time.Sleep(10 * time.Second)
	// TODO: Implement chunk elaboration logic
	gologger.Info().Msgf("elaborateScanChunks: scanID=%s, metaID=%s", scanID, metaID)
}

// elaborateScan processes a non-distributed scan
func (r *Runner) elaborateScan(ctx context.Context, scanID, metaID, config string, templates, assets []string) {
	time.Sleep(10 * time.Second)
	// TODO: Implement scan elaboration logic
	gologger.Info().Msgf("elaborateScan: scanID=%s, metaID=%s", scanID, metaID)
}

// elaborateEnumerationChunks processes distributed enumeration chunks
func (r *Runner) elaborateEnumerationChunks(ctx context.Context, enumID, metaID string, steps, assets []string) {
	// TODO: Implement enumeration chunk elaboration logic
	gologger.Info().Msgf("elaborateEnumerationChunks: enumID=%s, metaID=%s", enumID, metaID)
}

// elaborateEnumeration processes a non-distributed enumeration
func (r *Runner) elaborateEnumeration(ctx context.Context, enumID, metaID string, steps, assets []string) {
	// TODO: Implement enumeration elaboration logic
	gologger.Info().Msgf("elaborateEnumeration: enumID=%s, metaID=%s", enumID, metaID)
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
	apiURL := fmt.Sprintf("%s/v1/enumerate/%s/export", pkg.PCDPApiServer, enumerationID)
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

	// Fetch agent info from punch_hole /workers/:id
	endpoint := fmt.Sprintf("http://%s:%s/workers/%s?type=agent", PunchHoleHost, PunchHoleHTTPPort, r.options.AgentId)
	headers := map[string]string{"x-api-key": PDCPApiKey}
	resp := r.makeRequest(ctx, http.MethodGet, endpoint, nil, headers)
	if resp.Error != nil {
		gologger.Error().Msgf("failed to fetch agent info: %v", resp.Error)
		// don't return, fallback to local tags
	}

	// Default to local tags
	tagsToUse := r.options.AgentTags
	var lastUpdate time.Time
	if resp.Error == nil && resp.StatusCode == http.StatusOK {
		var agentInfo struct {
			Id         string    `json:"id"`
			Tags       []string  `json:"tags"`
			LastUpdate time.Time `json:"last_update"`
			Name       string    `json:"name"`
		}
		if err := json.Unmarshal(resp.Body, &agentInfo); err == nil {
			lastUpdate = agentInfo.LastUpdate
			if len(agentInfo.Tags) > 0 && !sliceutil.Equal(tagsToUse, agentInfo.Tags) {
				gologger.Info().Msgf("Using tags from punch_hole server: %v (was: %v)", agentInfo.Tags, tagsToUse)
				tagsToUse = agentInfo.Tags
				r.options.AgentTags = agentInfo.Tags // Overwrite local tags with remote
			}
			// Handle agent name
			if agentInfo.Name != "" && r.options.AgentName != agentInfo.Name {
				gologger.Info().Msgf("Using agent name from punch_hole server: %s (was: %s)", agentInfo.Name, r.options.AgentName)
				r.options.AgentName = agentInfo.Name
			}
			gologger.Info().Msgf("Agent last updated at: %s", lastUpdate.Format(time.RFC3339))
		}
	}

	// Now send the /in registration with the tagsToUse
	inEndpoint := fmt.Sprintf("http://%s:%s/in?os=%s&arch=%s&id=%s&type=agent&tags=%s",
		PunchHoleHost, PunchHoleHTTPPort, runtime.GOOS, runtime.GOARCH, r.options.AgentId, strings.Join(tagsToUse, ","))
	inResp := r.makeRequest(ctx, http.MethodPost, inEndpoint, nil, headers)
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
	endpoint := fmt.Sprintf("http://%s:%s/out?id=%s&type=agent", PunchHoleHost, PunchHoleHTTPPort, r.options.AgentId)
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
	flagSet.SetDescription(`pdcp-agent is an agent for ProjectDiscovery Cloud Platform`)

	flagSet.CreateGroup("agent", "Agent",
		flagSet.BoolVar(&options.AgentMode, "agent", false, "agent mode"),
		flagSet.BoolVar(&options.Verbose, "verbose", false, "show verbose output"),
		flagSet.StringVar(&options.AgentOutput, "agent-output", "", "agent output folder"),
		flagSet.StringVar(&options.AgentId, "agent-id", "", "specify the id for the agent"),
		flagSet.StringSliceVarP(&options.AgentTags, "agent-tags", "at", nil, "specify the tags for the agent", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringVar(&options.AgentName, "agent-name", "", "specify the name for the agent"),
		flagSet.BoolVar(&options.PassiveDiscovery, "passive-discovery", false, "enable passive discovery via libpcap/gopacket"),
	)

	if err := flagSet.Parse(); err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}

	// Parse environment variables (env vars take precedence as defaults)
	if agentID := os.Getenv("PDCP_AGENT_ID"); agentID != "" && options.AgentId == "" {
		options.AgentId = agentID
	}
	if agentTags := os.Getenv("PDCP_AGENT_TAGS"); agentTags != "" && len(options.AgentTags) == 0 {
		options.AgentTags = goflags.StringSlice(strings.Split(agentTags, ","))
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

	configureLogging(options)

	// Also support env variable PASSIVE_DISCOVERY
	if os.Getenv("PASSIVE_DISCOVERY") == "1" || os.Getenv("PASSIVE_DISCOVERY") == "true" {
		options.PassiveDiscovery = true
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
func deleteCacheFileForTesting() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		gologger.Warning().Msgf("Could not get home directory to delete cache file: %v", err)
		return
	}

	cacheFile := filepath.Join(homeDir, ".pdcp-agent", "execution-cache.json")
	if err := os.Remove(cacheFile); err != nil {
		if !os.IsNotExist(err) {
			gologger.Warning().Msgf("Could not delete cache file (this is ok if it doesn't exist): %v", err)
		}
	} else {
		gologger.Info().Msg("Deleted execution cache file (FOR TESTING PURPOSES ONLY)")
	}
}

func main() {
	// FOR TESTING PURPOSES ONLY: Delete the cache file containing executed scans and enumerations
	// This ensures that scans/enumerations are not skipped due to cached execution history during testing
	deleteCacheFileForTesting()

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
		gologger.Fatal().Msgf("Could not run pdcp-agent: %s\n", err)
	}
}
