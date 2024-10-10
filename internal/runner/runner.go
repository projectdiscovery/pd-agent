package runner

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/pdtm/pkg"
	"github.com/projectdiscovery/pdtm/pkg/path"
	"github.com/projectdiscovery/pdtm/pkg/tools"
	"github.com/projectdiscovery/pdtm/pkg/types"
	"github.com/projectdiscovery/pdtm/pkg/utils"
	pdcpauth "github.com/projectdiscovery/utils/auth/pdcp"
	errorutil "github.com/projectdiscovery/utils/errors"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
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
func (r *Runner) Run() error {
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
		gologger.Info().Msgf("running in agent mode with name %s", r.options.AgentName)
		return r.agentMode()
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
func (r *Runner) Close() {}

func (r *Runner) agentMode() error {
	apiURL := fmt.Sprintf("%s/v1/scans", pdcpauth.DefaultApiServer)
	client, err := r.createAuthenticatedClient()
	if err != nil {
		return fmt.Errorf("error creating authenticated client: %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return fmt.Errorf("error creating request: %v", err)
	}

	// Send the request using the client with proxy and InsecureSkipVerify
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response: %v", err)
	}

	// Use GJSON to parse the JSON response
	result := gjson.ParseBytes(body)

	// todo: initial support only for nuclei scans
	fmt.Println("List of Scans:")
	result.Get("data").ForEach(func(key, value gjson.Result) bool {
		scanID := value.Get("scan_id").String()
		fmt.Printf("ID: %s | Name: %s | Status: %s\n",
			scanID,
			value.Get("name").String(),
			value.Get("status").String(),
		)

		// Fetch scan config for each scan
		scanConfig, err := r.fetchScanConfig(scanID)
		if err != nil {
			gologger.Error().Msgf("Error fetching scan config for ID %s: %v", scanID, err)
		} else {
			fmt.Printf("Scan Config: %s\n", scanConfig)
		}

		// Fetch assets if enumeration ID is defined
		var enumerationIDs []string
		gjson.Parse(scanConfig).Get("enumeration_ids").ForEach(func(key, value gjson.Result) bool {
			log.Printf("enumeration ID: %s", value.String())
			id := value.Get("id").String()
			if id != "" {
				enumerationIDs = append(enumerationIDs, id)
			}
			return true
		})
		for _, enumerationID := range enumerationIDs {
			asset, err := r.fetchAssets(enumerationID)
			if err != nil {
				gologger.Error().Msgf("Error fetching assets for enumeration ID %s: %v", enumerationID, err)
			} else {
				fmt.Printf("Assets: %s\n", asset)
			}
		}

		fmt.Println("---")

		// todo: temporarily integrate with backend by adding agent_ids in scan_config and enumeration_config
		// we are ignoring scan state as well for now
		var agentIds []string

		// todo: hardcoding agent_ids for now
		agentIds = append(agentIds, r.options.AgentName)

		gjson.Parse(scanConfig).Get("agent_ids").ForEach(func(key, value gjson.Result) bool {
			log.Printf("agent ID: %s", value.String())
			id := value.Get("id").String()
			if id != "" {
				agentIds = append(agentIds, id)
			}
			return true
		})
		// check if current agent is within the ids
		if sliceutil.Contains(agentIds, r.options.AgentName) {
			fmt.Println("Agent is within the list of agents for this scan")

			// execute scan with templates and targets
			fmt.Println("Executing nuclei scan with templates and targets")

			task := &types.Task{
				Tool: types.Nuclei,
				Options: types.Options{
					Hosts: []string{"http://192.168.5.32:8000"},
				},
			}
			if err := pkg.Run(task); err != nil {
				gologger.Error().Msgf("Error executing task: %v", err)
			}

			fmt.Println("Scan completed")
		} else {
			fmt.Println("Agent is not within the list of agents for this scan")
		}

		return true
	})

	return nil
}

func (r *Runner) fetchScanConfig(scanID string) (string, error) {
	apiURL := fmt.Sprintf("%s/v1/scans/%s/config", pdcpauth.DefaultApiServer, scanID)
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
	apiURL := fmt.Sprintf("%s/v1/asset/enumerate/%s/export", pdcpauth.DefaultApiServer, enumerationID)
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
		return transport.RoundTrip(req)
	})

	return client, nil
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (rf roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return rf(req)
}
