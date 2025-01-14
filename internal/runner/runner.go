package runner

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/Mzack9999/gcache"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/pdtm-agent/pkg"
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
	close(queuedScans)
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

	go r.registerAgent(ctx)

	go r.monitorScans(ctx)

	awg, err := syncutil.New(syncutil.WithSize(5))
	if err != nil {
		return errors.Join(err, errors.New("could not create worker group"))
	}

	defer awg.Wait()

	for {

		select {
		case <-ctx.Done():
			return nil
		case task := <-queuedScans:
			awg.AddWithContext(ctx)

			go func(task *types.Task) {
				defer awg.Done()

				fmt.Printf("running scan %s\n", task.Id)

				if err := pkg.Run(ctx, task); err != nil {
					gologger.Error().Msgf("Error executing task: %v", err)
				}
				fmt.Printf("scan %s completed\n", task.Id)
				completedScans.Set(task.Id, struct{}{})
				pendingScans.Delete(task.Id)
			}(task)
		}
	}
}

func (r *Runner) fetchScanConfig(scanID, todoUserId string) (string, error) {
	apiURL := fmt.Sprintf("%s/v1/scans/%s/config?user_id=%s", PCDPApiServer, scanID, todoUserId)
	client, err := r.createAuthenticatedClient()
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
	client, err := r.createAuthenticatedClient()
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

func (r *Runner) createAuthenticatedClient() (*http.Client, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	client := &http.Client{
		Transport: transport,
	}

	// Create a custom RoundTripper to add headers to every request
	client.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		req.Header.Set("X-Api-Key", PDCPApiKey)
		req.Header.Set("X-Team-Id", r.options.TeamID)
		q := req.URL.Query()
		q.Add("user_id", r.options.TodoUserId)
		req.URL.RawQuery = q.Encode()
		return transport.RoundTrip(req)
	})

	return client, nil
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (rf roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return rf(req)
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

func (r *Runner) registerAgent(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute) // Register every 5 minutes
	defer ticker.Stop()

	doRegisterAgent := func() {
		if err := r.doRegisterAgent(); err != nil {
			gologger.Error().Msgf("Failed to register agent: %v", err)
		}
	}
	doRegisterAgent()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			doRegisterAgent()
		}
	}
}

func (r *Runner) doRegisterAgent() error {
	agent := Agent{
		AgentId:      r.options.AgentName,
		AgentName:    r.options.AgentName,
		Architecture: runtime.GOARCH,
		LastSeen:     time.Now(),
		Os:           runtime.GOOS,
	}

	jsonData, err := json.Marshal(agent)
	if err != nil {
		return fmt.Errorf("error marshaling agent data: %v", err)
	}

	// TODO: change this to the actual api server
	apiURL := fmt.Sprintf("%s/agents", PDCPDevApiServer)
	client, err := r.createAuthenticatedClient()
	if err != nil {
		return fmt.Errorf("error creating authenticated client: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	gologger.Info().Msgf("Agent registered successfully")
	return nil
}

var (
	completedScans = gcache.New[string, struct{}](1024).
			LRU().
			Expiration(time.Hour).
			Build()
	pendingScans = mapsutil.NewSyncLockMap[string, struct{}]()
	queuedScans  = make(chan *types.Task, 1024)
)

func (r *Runner) getScans(ctx context.Context) error {
	apiURL := fmt.Sprintf("%s/v1/scans", PCDPApiServer)

	client, err := r.createAuthenticatedClient()
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
			gologger.Info().Msgf("Total pages: %d", totalPages)
		}

		fmt.Printf("Processing page %d of %d\n", currentPage, totalPages)

		// Process scans
		result.Get("data").ForEach(func(key, value gjson.Result) bool {
			// since we have no control over platform-backend or product evolution
			// we use the scan name to contain the [pdtm-agent-id] temporarily
			scanName := value.Get("name").String()
			hasScanNameTag := strings.Contains(scanName, "["+r.options.AgentName+"]")
			agentId := value.Get("pdtm_agent_id").String()
			isAssignedToagent := agentId == r.options.AgentName

			if !isAssignedToagent && !hasScanNameTag {
				fmt.Printf("skipping scan %s as it's not assigned|tagged to %s\n", scanName, r.options.AgentName)
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
				fmt.Printf("skipping scan %s as it has no schedule\n", scanName)
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
			if !targetExecutionTime.IsZero() && !isInRange {
				fmt.Printf("skipping scan %s as it's scheduled for %s (current time: %s)\n", scanName, targetExecutionTime, now)
				return true
			}

			scanID := value.Get("scan_id").String()
			scanMetaId := fmt.Sprintf("%s-%s", scanID, targetExecutionTime)

			if completedScans.Has(scanMetaId) {
				fmt.Printf("skipping scan %s as it's already completed recently\n", scanName)
				return true
			}

			if pendingScans.Has(scanMetaId) {
				fmt.Printf("skipping scan %s as it's already in progress\n", scanName)
				return true
			}

			// Fetch scan config for each scan
			scanConfig, err := r.fetchScanConfig(scanID, r.options.TodoUserId)
			if err != nil {
				gologger.Error().Msgf("Error fetching scan config for ID %s: %v", scanID, err)
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

			fmt.Printf("scan %s enqueued...\n", scanName)

			task := &types.Task{
				Tool: types.Nuclei,
				Options: types.Options{
					Hosts:     assets,
					Templates: templates,
					ScanID:    scanID,
					Silent:    true,
				},
				Id: scanMetaId,
			}

			pendingScans.Set(scanMetaId, struct{}{})

			queuedScans <- task

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
			r.getScans(ctx)
			time.Sleep(time.Minute)
		}
	}
}
