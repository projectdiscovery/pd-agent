package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"encoding/base64"

	"github.com/Mzack9999/gcache"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/pdtm-agent/pkg"
	"github.com/projectdiscovery/pdtm-agent/pkg/client"
	"github.com/projectdiscovery/pdtm-agent/pkg/path"
	"github.com/projectdiscovery/pdtm-agent/pkg/tools"
	"github.com/projectdiscovery/pdtm-agent/pkg/types"
	"github.com/projectdiscovery/pdtm-agent/pkg/utils"
	pdcpauth "github.com/projectdiscovery/utils/auth/pdcp"
	errorutil "github.com/projectdiscovery/utils/errors"
	mapsutil "github.com/projectdiscovery/utils/maps"
	stringsutil "github.com/projectdiscovery/utils/strings"
	syncutil "github.com/projectdiscovery/utils/sync"
	"github.com/tidwall/gjson"
)

var excludedToolList = []string{"nuclei-templates"}

// Runner contains the internal logic of the program
type Runner struct {
	options *Options
}

// NewRunner instance
func NewRunner(options *Options) (*Runner, error) {
	return &Runner{options: options}, nil
}

// Run the instance
func (r *Runner) Run(ctx context.Context) error {
	// add default path to $PATH
	if r.options.SetPath || r.options.Path == tools.DefaultPath {
		if err := path.SetENV(r.options.Path); err != nil {
			return errorutil.NewWithErr(err).Msgf(`Failed to set path: %s. Add it to $PATH and run again`, r.options.Path)
		}
	}

	if r.options.SetGoPath {
		goBinEnvVar, goPathEnvVar := getGoEnv("GOBIN"), getGoEnv("GOPATH")
		goEnvVar := goBinEnvVar
		if goEnvVar == "" {
			goEnvVar = goPathEnvVar
		}
		if goEnvVar != "" {
			if err := path.SetENV(goEnvVar); err != nil {
				return errorutil.NewWithErr(err).Msgf(`Failed to set path: %s. Add it to $PATH and run again`, goEnvVar)
			}
		}
	}

	if r.options.UnSetPath {
		if err := path.UnsetENV(r.options.Path); err != nil {
			return errorutil.NewWithErr(err).Msgf(`Failed to unset path: %s. Remove it from $PATH and run again`, r.options.Path)
		}
	}

	toolListApi, err := utils.FetchToolList()
	var toolList []types.Tool

	for _, tool := range toolListApi {
		if !stringsutil.ContainsAny(tool.Name, excludedToolList...) {
			toolList = append(toolList, tool)
		}
	}

	// if toolList is not nil save/update the cache
	// else fetch from cache file
	if toolList != nil {
		go func() {
			if err := tools.UpdateCache(toolList); err != nil {
				gologger.Warning().Msgf("%s\n", err)
			}
		}()
	} else {
		toolList, err = tools.FetchFromCache()
		if err != nil {
			return errors.New("pdtm api is down, please try again later")
		}
		if toolList != nil {
			gologger.Warning().Msg("pdtm api is down, using cached information while we fix the issue \n\n")
		}
	}
	if toolList == nil && err != nil {
		return err
	}

	switch {
	case r.options.InstallAll:
		for _, tool := range toolList {
			r.options.Install = append(r.options.Install, tool.Name)
		}
	case r.options.UpdateAll:
		for _, tool := range toolList {
			r.options.Update = append(r.options.Update, tool.Name)
		}
	case r.options.RemoveAll:
		for _, tool := range toolList {
			r.options.Remove = append(r.options.Remove, tool.Name)
		}
	}
	gologger.Verbose().Msgf("using path %s", r.options.Path)

	for _, toolName := range r.options.Install {
		if !path.IsSubPath(tools.HomeDir, r.options.Path) {
			gologger.Error().Msgf("skipping install outside home folder: %s", toolName)
			continue
		}
		if i, ok := utils.Contains(toolList, toolName); ok {
			tool := toolList[i]
			if tool.InstallType == types.Go && isGoInstalled() {
				if err := pkg.GoInstall(r.options.Path, tool); err != nil {
					gologger.Error().Msgf("%s: %s", tool.Name, err)
				}
				continue
			}

			if err := pkg.Install(r.options.Path, tool); err != nil {
				if errors.Is(err, types.ErrIsInstalled) {
					gologger.Info().Msgf("%s: %s", tool.Name, err)
				} else {
					gologger.Error().Msgf("error while installing %s: %s", tool.Name, err)
					gologger.Info().Msgf("trying to install %s using go install", tool.Name)
					if err := pkg.GoInstall(r.options.Path, tool); err != nil {
						gologger.Error().Msgf("%s: %s", tool.Name, err)
					}
				}
			}
		} else {
			gologger.Error().Msgf("error while installing %s: %s not found in the list", toolName, toolName)
		}
	}
	for _, tool := range r.options.Update {
		if !path.IsSubPath(tools.HomeDir, r.options.Path) {
			gologger.Error().Msgf("skipping update outside home folder: %s", tool)
			continue
		}
		if i, ok := utils.Contains(toolList, tool); ok {
			if err := pkg.Update(r.options.Path, toolList[i], r.options.DisableChangeLog); err != nil {
				if err == types.ErrIsUpToDate {
					gologger.Info().Msgf("%s: %s", tool, err)
				} else {
					gologger.Info().Msgf("%s\n", err)
				}
			}
		}
	}
	for _, tool := range r.options.Remove {
		if !path.IsSubPath(tools.HomeDir, r.options.Path) {
			gologger.Error().Msgf("skipping remove outside home folder: %s", tool)
			continue
		}
		if i, ok := utils.Contains(toolList, tool); ok {
			if err := pkg.Remove(r.options.Path, toolList[i]); err != nil {
				var notFoundError *exec.Error
				if errors.As(err, &notFoundError) {
					gologger.Info().Msgf("%s: not found", tool)
				} else {
					gologger.Info().Msgf("%s\n", err)
				}
			}

		}
	}

	if r.options.AgentMode {
		// recommend the time to use on platform dashboard to schedule the scans
		gologger.Info().Msg("platform dashboard uses UTC timezone")
		now := time.Now().UTC()
		recommendedTime := now.Add(5 * time.Minute)
		gologger.Info().Msgf("recommended time to schedule scans (UTC): %s", recommendedTime.Format("2006-01-02 03:04:05 PM MST"))

		gologger.Info().Msgf("running in agent mode with name %s", r.options.AgentName)
		return r.agentMode(ctx)
	}

	if len(r.options.Install) == 0 && len(r.options.Update) == 0 && len(r.options.Remove) == 0 {
		return r.ListToolsAndEnv(toolList)
	}

	return nil
}

func getGoEnv(key string) string {
	cmd := exec.Command("go", "env", key)
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func isGoInstalled() bool {
	cmd := exec.Command("go", "version")
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

// ListToolsAndEnv prints the list of tools
func (r *Runner) ListToolsAndEnv(tools []types.Tool) error {
	gologger.Info().Msgf("%s\n", path.GetOsData())
	gologger.Info().Msgf("Path to download project binary: %s\n", r.options.Path)
	var fmtMsg string
	if path.IsSet(r.options.Path) {
		fmtMsg = "Path %s configured in environment variable $PATH\n"
	} else {
		fmtMsg = "Path %s not configured in environment variable $PATH\n"
	}
	gologger.Info().Msgf(fmtMsg, r.options.Path)

	for i, tool := range tools {
		msg := utils.InstalledVersion(tool, r.options.Path, au)
		fmt.Printf("%d. %s %s\n", i+1, tool.Name, msg)
	}
	return nil
}

// Close the runner instance
func (r *Runner) Close() {
	close(queuedTasks)
}

// - will download the scan list
// - execute scans without schedule or uploaded state
// - execute schedules scans with time proximity
// - Perform scan with:
//   - templates
//   - targets
//   - todo: nuclei config
//
// - configure nuclei to upload results with scan id
// TODO. since it's unclear how pdtm-agent should interact with all the cloyd layers, for the time being we connect directly
// with aurora api
func (r *Runner) agentMode(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		if err := r.In(ctx); err != nil {
			log.Fatalf("error registering agent: %v", err)
		}
	}()

	go r.monitorScans(ctx)
	go r.monitorEnumerations(ctx)
	awg, err := syncutil.New(syncutil.WithSize(5))
	if err != nil {
		return errors.Join(err, errors.New("could not create worker group"))
	}

	defer func() {
		wg.Wait()
		awg.Wait()
	}()

	for {

		select {
		case <-ctx.Done():
			return nil
		case task := <-queuedTasks:
			if task == nil {
				continue
			}
			awg.Add()

			go func(task *types.Task) {
				defer awg.Done()

				gologger.Info().Msgf("Running task:\nId: %s\nTool: %s\nOptions: %+v\n", task.Id, task.Tool, task.Options)

				if err := pkg.Run(ctx, task); err != nil {
					gologger.Error().Msgf("Error executing task: %v", err)
				}
				gologger.Info().Msgf("Task %s completed\n", task.Id)
				_ = completedTasks.Set(task.Id, struct{}{})
				pendingTasks.Delete(task.Id)
			}(task)
		}
	}
}

func (r *Runner) fetchScanConfig(scanID, todoUserId string) (string, error) {
	apiURL := fmt.Sprintf("%s/v1/scans/%s/config?user_id=%s", pdcpauth.DefaultApiServer, scanID, todoUserId)
	client, err := client.CreateAuthenticatedClient(r.options.TeamID, r.options.TodoUserId, PDCPApiKey)
	if err != nil {
		return "", fmt.Errorf("error creating authenticated client: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return "", fmt.Errorf("error creating request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response: %v", err)
	}

	return string(body), nil
}

func (r *Runner) fetchSingleConfig(scanConfigId string) (string, error) {
	apiURL := fmt.Sprintf("%s/v1/scans/config/%s", pdcpauth.DefaultApiServer, scanConfigId)
	client, err := client.CreateAuthenticatedClient(r.options.TeamID, r.options.TodoUserId, PDCPApiKey)
	if err != nil {
		return "", fmt.Errorf("error creating authenticated client: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return "", fmt.Errorf("error creating request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response: %v", err)
	}

	return string(body), nil
}

func (r *Runner) fetchAssets(enumerationID string) ([]byte, error) {
	apiURL := fmt.Sprintf("%s/v1/enumerate/%s/export", pdcpauth.DefaultApiServer, enumerationID)
	client, err := client.CreateAuthenticatedClient(r.options.TeamID, r.options.TodoUserId, PDCPApiKey)
	if err != nil {
		return nil, fmt.Errorf("error creating authenticated client: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %v", err)
	}

	return body, nil
}

// Agent defines model for Agent.
type Agent struct {
	AgentId      string    `json:"agent_id"`
	AgentName    string    `json:"agent_name"`
	Architecture string    `json:"architecture"`
	LastSeen     time.Time `json:"last_seen"`
	Os           string    `json:"os"`
	PdtmVersion  string    `json:"pdtm_version"`
}

var (
	completedTasks = gcache.New[string, struct{}](1024).
			LRU().
			Expiration(time.Hour).
			Build()
	pendingTasks = mapsutil.NewSyncLockMap[string, struct{}]()
	queuedTasks  = make(chan *types.Task, 1024)
)

func (r *Runner) getScans(ctx context.Context) error {
	gologger.Verbose().Msg("Retrieving scans...")
	apiURL := fmt.Sprintf("%s/v1/scans", PCDPApiServer)

	client, err := client.CreateAuthenticatedClient(r.options.TeamID, r.options.TodoUserId, PDCPApiKey)
	if err != nil {
		return fmt.Errorf("error creating authenticated client: %v", err)
	}

	limit := 100
	offset := 0
	totalPages := 1
	currentPage := 1

	for currentPage <= totalPages {
		paginatedURL := fmt.Sprintf("%s?limit=%d&offset=%d", apiURL, limit, offset)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, paginatedURL, nil)
		if err != nil {
			return fmt.Errorf("error creating request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("error sending request: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("error reading response: %v", err)
		}

		result := gjson.ParseBytes(body)

		// Update totalPages on the first iteration
		if currentPage == 1 {
			totalPages = int(result.Get("total_pages").Int())
			gologger.Verbose().Msgf("Total pages: %d", totalPages)
		}

		gologger.Verbose().Msgf("Processing page %d of %d\n", currentPage, totalPages)

		// Process scans
		result.Get("data").ForEach(func(key, value gjson.Result) bool {
			// since we have no control over platform-backend or product evolution
			// we use the scan name to contain the [pdtm-agent-id] temporarily
			scanName := value.Get("name").String()
			hasScanNameTag := strings.Contains(scanName, "["+r.options.AgentName+"]")
			agentId := value.Get("pdtm_agent_id").String()
			isAssignedToagent := agentId == r.options.AgentName

			// tmp
			isPatched := stringsutil.EqualFoldAny(scanName, "test1 [pdtm-agent]", "test2 [pdtm-agent]")
			if isPatched {
				isAssignedToagent = true
				hasScanNameTag = true
			}

			if !isAssignedToagent && !hasScanNameTag {
				gologger.Verbose().Msgf("skipping scan %s as it's not assigned|tagged to %s\n", scanName, r.options.AgentName)
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
			if !scheduleData.Exists() {
				gologger.Verbose().Msgf("skipping scan %s as it has no schedule\n", scanName)
				return true
			}

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

			if isPatched {
				isInRange = true
			}

			if !targetExecutionTime.IsZero() && !isInRange {
				gologger.Verbose().Msgf("skipping scan %s as it's scheduled for %s (current time: %s)\n", scanName, targetExecutionTime, now)
				return true
			}

			id := value.Get("scan_id").String()
			metaId := fmt.Sprintf("%s-%s", id, targetExecutionTime)

			if completedTasks.Has(metaId) {
				gologger.Verbose().Msgf("skipping scan %s as it's already completed recently\n", scanName)
				return true
			}

			if pendingTasks.Has(metaId) {
				gologger.Verbose().Msgf("skipping scan %s as it's already in progress\n", scanName)
				return true
			}

			// Fetch scan config for each scan
			scanConfig, err := r.fetchScanConfig(id, r.options.TodoUserId)
			if err != nil {
				gologger.Error().Msgf("Error fetching scan config for ID %s: %v", id, err)
			}

			// Fetch each single scan configuration
			// - Templates
			// - Scan Configuration (Headers, Variables, Interactsh)
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

			// apparently we need to merge all configs into one
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

			// gets assets from enumeration id
			var assets []string
			for _, enumerationID := range enumerationIDs {
				asset, err := r.fetchAssets(enumerationID)
				if err != nil {
					gologger.Error().Msgf("Error fetching assets for enumeration ID %s: %v", enumerationID, err)
				}
				assets = append(assets, strings.Split(string(asset), "\n")...)
			}
			// gets assets from scan config
			gjson.Parse(scanConfig).Get("targets").ForEach(func(key, value gjson.Result) bool {
				assets = append(assets, value.String())
				return true
			})

			var templates []string
			value.Get("public_templates").ForEach(func(key, value gjson.Result) bool {
				templates = append(templates, value.String())
				return true
			})

			gologger.Info().Msgf("scan %s enqueued...\n", scanName)

			task := &types.Task{
				Tool: types.Nuclei,
				Options: types.Options{
					Hosts:     assets,
					Templates: templates,
					Silent:    true,
					ScanID:    id,
					Config:    finalConfig,
				},
				Id: metaId,
			}

			if r.options.AgentOutput != "" {
				task.Options.Output = filepath.Join(r.options.AgentOutput, metaId)
			}

			_ = pendingTasks.Set(metaId, struct{}{})

			queuedTasks <- task

			return true
		})

		currentPage++
		offset += limit
	}

	return nil
}

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

func (r *Runner) getEnumerations(ctx context.Context) error {
	gologger.Verbose().Msg("Retrieving enumerations...")
	apiURL := fmt.Sprintf("%s/v1/asset/enumerate", PCDPApiServer)

	client, err := client.CreateAuthenticatedClient(r.options.TeamID, r.options.TodoUserId, PDCPApiKey)
	if err != nil {
		return fmt.Errorf("error creating authenticated client: %v", err)
	}

	limit := 100
	offset := 0
	totalPages := 1
	currentPage := 1

	for currentPage <= totalPages {
		paginatedURL := fmt.Sprintf("%s?limit=%d&offset=%d", apiURL, limit, offset)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, paginatedURL, nil)
		if err != nil {
			return fmt.Errorf("error creating request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("error sending request: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("error reading response: %v", err)
		}

		result := gjson.ParseBytes(body)

		// Update totalPages on the first iteration
		if currentPage == 1 {
			totalPages = int(result.Get("total_pages").Int())
			gologger.Verbose().Msgf("Total pages: %d", totalPages)
		}

		gologger.Verbose().Msgf("Processing page %d of %d\n", currentPage, totalPages)

		// Process scans
		result.Get("data").ForEach(func(key, value gjson.Result) bool {
			// since we have no control over platform-backend or product evolution
			// we use the scan name to contain the [pdtm-agent-id] temporarily
			scanName := value.Get("name").String()
			hasScanNameTag := strings.Contains(scanName, "["+r.options.AgentName+"]")
			agentId := value.Get("pdtm_agent_id").String()
			isAssignedToagent := agentId == r.options.AgentName

			if !isAssignedToagent && !hasScanNameTag {
				gologger.Verbose().Msgf("skipping enumeration %s as it's not assigned|tagged to %s\n", scanName, r.options.AgentName)
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
			if !scheduleData.Exists() {
				gologger.Verbose().Msgf("skipping enumeration %s as it has no schedule\n", scanName)
				return true
			}

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

			// TODO: remove this
			// isInRange = true

			if !targetExecutionTime.IsZero() && !isInRange {
				gologger.Verbose().Msgf("skipping enumeration %s as it's scheduled for %s (current time: %s)\n", scanName, targetExecutionTime, now)
				return true
			}

			id := value.Get("id").String()
			metaId := fmt.Sprintf("%s-%s", id, targetExecutionTime)

			if completedTasks.Has(metaId) {
				gologger.Verbose().Msgf("skipping enumeration %s as it's already completed recently\n", scanName)
				return true
			}

			if pendingTasks.Has(metaId) {
				gologger.Verbose().Msgf("skipping enumeration %s as it's already in progress\n", scanName)
				return true
			}

			// Fetch scan config for each scan
			scanConfig, err := r.fetchEnumerationConfig(id, r.options.TodoUserId)
			if err != nil {
				gologger.Error().Msgf("Error fetching scan config for ID %s: %v", id, err)
			}

			// Fetch assets if enumeration ID is defined
			// gets assets from enumeration id
			var assets []string
			gjson.Parse(scanConfig).Get("enrichment_inputs").ForEach(func(key, value gjson.Result) bool {
				assets = append(assets, value.String())
				return true
			})
			gjson.Parse(scanConfig).Get("root_domains").ForEach(func(key, value gjson.Result) bool {
				assets = append(assets, value.String())
				return true
			})

			var steps []string
			gjson.Parse(scanConfig).Get("steps").ForEach(func(key, value gjson.Result) bool {
				steps = append(steps, value.String())
				return true
			})

			gologger.Info().Msgf("enumeration %s enqueued...\n", scanName)

			task := &types.Task{
				Tool: types.Nuclei,
				Options: types.Options{
					Hosts:         assets,
					Silent:        true,
					Steps:         steps,
					EnumerationID: id,
				},
				Id: metaId,
			}

			if r.options.AgentOutput != "" {
				task.Options.Output = filepath.Join(r.options.AgentOutput, metaId)
			}

			_ = pendingTasks.Set(metaId, struct{}{})

			queuedTasks <- task

			return true
		})

		currentPage++
		offset += limit
	}

	return nil
}

func (r *Runner) fetchEnumerationConfig(enumerationId, todoUserId string) (string, error) {
	apiURL := fmt.Sprintf("%s/v1/asset/enumerate/%s/config?user_id=%s", pdcpauth.DefaultApiServer, enumerationId, todoUserId)
	client, err := client.CreateAuthenticatedClient(r.options.TeamID, r.options.TodoUserId, PDCPApiKey)
	if err != nil {
		return "", fmt.Errorf("error creating authenticated client: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return "", fmt.Errorf("error creating request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response: %v", err)
	}

	return string(body), nil
}

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
	if err := r.inFunctionTickCallback(ctx, true); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := r.inFunctionTickCallback(ctx, false); err != nil {
				return err
			}
		}
	}
}

var isRegistered bool

func (r *Runner) inFunctionTickCallback(ctx context.Context, first bool) error {
	endpoint := fmt.Sprintf("http://%s:%s/in", PunchHoleHost, PunchHoleHTTPPort)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		log.Printf("failed to create request: %v", err)
		return err
	}
	q := req.URL.Query()
	q.Add("os", runtime.GOOS)
	q.Add("arch", runtime.GOARCH)
	q.Add("id", r.options.AgentName)
	q.Add("type", "agent")
	req.URL.RawQuery = q.Encode()

	client, err := client.CreateAuthenticatedClient(r.options.TeamID, r.options.TodoUserId, PDCPApiKey)
	if err != nil {
		return fmt.Errorf("error creating authenticated client: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("failed to call /in endpoint: %v", err)
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("failed to read response body: %v", err)
		return err
	}
	if resp.StatusCode != http.StatusOK {
		log.Printf("unexpected status code from /in endpoint: %d, body: %s", resp.StatusCode, string(body))
		return fmt.Errorf("unexpected status code from /in endpoint: %v, body: %s", resp.StatusCode, string(body))
	} else {
		if !isRegistered {
			gologger.Info().Msgf("agent registered successfully")
			isRegistered = true
		}
	}
	time.Sleep(time.Second)
	if first {
		if r.options.AgentName != "" {
			if err := r.renameAgent(ctx, r.options.AgentName); err != nil {
				gologger.Error().Msgf("error renaming agent: %v", err)
			}
		}
	}
	return nil
}

func (r *Runner) Out(ctx context.Context) error {
	endpoint := fmt.Sprintf("http://%s:%s/out", PunchHoleHost, PunchHoleHTTPPort)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		log.Printf("failed to create request: %v", err)
		return err
	}
	client, err := client.CreateAuthenticatedClient(r.options.TeamID, r.options.TodoUserId, PDCPApiKey)
	if err != nil {
		return fmt.Errorf("error creating authenticated client: %v", err)
	}
	q := req.URL.Query()
	q.Add("id", r.options.AgentName)
	q.Add("type", "agent")
	req.URL.RawQuery = q.Encode()
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("failed to call /out endpoint: %v", err)
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("failed to read response body: %v", err)
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code from /out endpoint: %v, body: %s", resp.StatusCode, string(body))
	} else {
		if isRegistered {
			gologger.Info().Msgf("agent deregistered successfully")
			isRegistered = false
		}
	}
	return nil
}

func (r *Runner) renameAgent(ctx context.Context, name string) error {
	endpoint := fmt.Sprintf("http://%s:%s/rename", PunchHoleHost, PunchHoleHTTPPort)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	q := req.URL.Query()
	q.Add("id", r.options.AgentName)
	q.Add("name", name)
	q.Add("type", "agent")
	req.URL.RawQuery = q.Encode()

	client, err := client.CreateAuthenticatedClient(r.options.TeamID, r.options.TodoUserId, PDCPApiKey)
	if err != nil {
		return fmt.Errorf("error creating authenticated client: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to call /rename endpoint: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code from /rename endpoint: %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}
