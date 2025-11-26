package pkg

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	mapsutil "github.com/projectdiscovery/utils/maps"
	sliceutil "github.com/projectdiscovery/utils/slice"
	syncutil "github.com/projectdiscovery/utils/sync"
)

// FilterTargetsByTemplatePorts extracts ports from templates and filters targets
// to only include hosts with open ports using naabu scan.
// Takes as input:
//   - targetsFile: filename containing targets (one per line, same format as passed to nuclei -l)
//   - templatesFile: filename containing templates (one per line, same format as passed to nuclei -templates)
//   - scanID: scan identifier for logging
//   - chunkID: chunk identifier for logging
//
// Returns:
//   - filtered hosts with open ports
//   - ports extracted from targets
func FilterTargetsByTemplatePorts(ctx context.Context, targetsFile, templatesFile, scanID, chunkID string) ([]string, []string, error) {
	// Read targets file
	targetsF, err := os.Open(targetsFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open targets file: %w", err)
	}
	defer func() {
		_ = targetsF.Close()
	}()

	var hosts []string
	var ports []string

	scanner := bufio.NewScanner(targetsF)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Try to split host:port using net.SplitHostPort
		host, port, err := net.SplitHostPort(line)
		if err == nil {
			// Successfully split, we have both host and port
			hosts = append(hosts, host)
			if port != "" {
				ports = append(ports, port)
			}
		} else {
			// No port, just host
			hosts = append(hosts, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("error reading targets file: %w", err)
	}

	// Read templates file and extract ports
	templatePorts, _, err := extractPortsFromTemplatesFile(templatesFile, scanID, chunkID)
	if err != nil {
		return nil, nil, fmt.Errorf("error extracting ports from templates: %w", err)
	}

	// Merge ports from targets and templates
	allPorts := make(map[string]struct{})
	for _, p := range ports {
		allPorts[p] = struct{}{}
	}
	for _, p := range templatePorts {
		allPorts[p] = struct{}{}
	}

	// Convert to slice
	mergedPorts := make([]string, 0, len(allPorts))
	for p := range allPorts {
		mergedPorts = append(mergedPorts, p)
	}

	// Deduplicate targets and ports before returning
	hosts = sliceutil.Dedupe(hosts)
	mergedPorts = sliceutil.Dedupe(mergedPorts)

	// Perform naabu scan and filter hosts with open ports
	if len(hosts) > 0 && len(mergedPorts) > 0 {
		openHosts, err := runNaabuScan(ctx, hosts, mergedPorts, scanID, chunkID)
		if err != nil {
			slog.Warn("Naabu scan failed",
				"scan_id", scanID,
				"chunk_id", chunkID,
				"error", err)
		} else {
			hosts = openHosts
		}
	}

	return hosts, mergedPorts, nil
}

// runNaabuScan runs naabu scan with specified targets and ports using the SDK
// Uses -no-probe (skip host discovery) for fast scanning
// Returns list of hosts with open ports
func runNaabuScan(ctx context.Context, targets []string, ports []string, scanID, chunkID string) ([]string, error) {
	if len(targets) == 0 || len(ports) == 0 {
		return targets, nil
	}

	// Convert ports to comma-separated string for naabu
	portStr := strings.Join(ports, ",")

	// Collect hosts with open ports
	openHostsSet := mapsutil.NewSyncLockMap[string, struct{}]()

	// Configure naabu options
	options := &runner.Options{
		Host:              goflags.StringSlice(targets),
		Ports:             portStr,
		SkipHostDiscovery: true, // Skip host discovery (equivalent to nmap -Pn)
		Silent:            true, // Silent mode
		OnResult: func(hr *result.HostResult) {
			if hr.Host != "" && len(hr.Ports) > 0 {
				_ = openHostsSet.Set(hr.Host, struct{}{})
			}
		},
	}

	// Create naabu runner
	naabuRunner, err := runner.NewRunner(options)
	if err != nil {
		return nil, fmt.Errorf("failed to create naabu runner: %w", err)
	}
	defer func() {
		_ = naabuRunner.Close()
	}()

	// Run enumeration
	err = naabuRunner.RunEnumeration(ctx)
	if err != nil {
		// naabu may return errors if no ports are found, which is acceptable
		slog.Debug("Naabu enumeration completed",
			"scan_id", scanID,
			"chunk_id", chunkID,
			"status", err)
	}

	// Convert set to slice
	openHosts := make([]string, 0)
	allHosts := openHostsSet.GetAll()
	for host := range allHosts {
		openHosts = append(openHosts, host)
	}

	return openHosts, nil
}

// extractPortsFromTemplatesFile reads the templates file (one template path per line)
// and extracts ports from each template using all available extractors in parallel
// Returns ports, template count, and error
func extractPortsFromTemplatesFile(templatesFile, scanID, chunkID string) ([]string, int, error) {
	templatesF, err := os.Open(templatesFile)
	if err != nil {
		slog.Error("Failed to open templates file",
			"scan_id", scanID,
			"chunk_id", chunkID,
			"templates_file", templatesFile,
			"error", err)
		return nil, 0, fmt.Errorf("failed to open templates file: %w", err)
	}
	defer func() {
		_ = templatesF.Close()
	}()

	// Collect all template paths first
	var templatePaths []string
	scanner := bufio.NewScanner(templatesF)
	for scanner.Scan() {
		templatePath := strings.TrimSpace(scanner.Text())
		if templatePath != "" {
			templatePaths = append(templatePaths, templatePath)
		}
	}

	if err := scanner.Err(); err != nil {
		slog.Error("Error scanning templates file",
			"scan_id", scanID,
			"chunk_id", chunkID,
			"templates_file", templatesFile,
			"error", err)
		return nil, 0, fmt.Errorf("error reading templates file: %w", err)
	}

	// If no template paths in file, try to get all default nuclei templates
	if len(templatePaths) == 0 {
		defaultTemplateDir := GetNucleiDefaultTemplateDir()
		if defaultTemplateDir != "" {
			// Try to get all templates from the directory
			err := filepath.Walk(defaultTemplateDir, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !info.IsDir() {
					ext := filepath.Ext(path)
					if ext == ".yaml" || ext == ".yml" {
						// Get relative path from template directory
						relPath, err := filepath.Rel(defaultTemplateDir, path)
						if err == nil {
							templatePaths = append(templatePaths, relPath)
						}
					}
				}
				return nil
			})
			if err != nil {
				slog.Warn("Failed to walk nuclei template directory",
					"scan_id", scanID,
					"chunk_id", chunkID,
					"template_dir", defaultTemplateDir,
					"error", err)
			}
		}
		// If still no templates found, return empty
		if len(templatePaths) == 0 {
			return []string{}, 0, nil
		}
	}

	// Get nuclei default template directory once
	defaultTemplateDir := GetNucleiDefaultTemplateDir()

	// Use thread-safe map for ports
	portSet := mapsutil.NewSyncLockMap[string, struct{}]()

	// Use atomic counter for template count
	var templateCount int64

	// Create syncutil waitgroup with 50 threads
	awg, err := syncutil.New(syncutil.WithSize(50))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create syncutil: %w", err)
	}

	// Process templates in parallel
	for _, templatePath := range templatePaths {
		templatePath := templatePath // capture for goroutine

		awg.Add()
		go func(tp string) {
			defer awg.Done()

			atomic.AddInt64(&templateCount, 1)

			// Resolve template path - if relative, use nuclei default template directory
			resolvedPath := tp
			if !filepath.IsAbs(tp) {
				if defaultTemplateDir != "" {
					resolvedPath = filepath.Join(defaultTemplateDir, tp)
				}
			}

			// Read the actual template file
			templateContent, err := os.ReadFile(resolvedPath)
			if err != nil {
				slog.Error("Failed to read template file",
					"scan_id", scanID,
					"chunk_id", chunkID,
					"template_path", tp,
					"resolved_path", resolvedPath,
					"error", err)
				// Template path might not exist, skip
				return
			}

			content := string(templateContent)

			// Extract ports using all extractors
			ports := extractAllPorts(content)
			for _, port := range ports {
				_ = portSet.Set(port, struct{}{})
			}
		}(templatePath)
	}

	// Wait for all templates to be processed
	awg.Wait()

	// Convert set to slice
	allPorts := make([]string, 0)
	allPortsMap := portSet.GetAll()
	for p := range allPortsMap {
		allPorts = append(allPorts, p)
	}

	return allPorts, int(templateCount), nil
}

var cachedTemplateDir string
var templateDirOnce sync.Once

// GetNucleiDefaultTemplateDir returns the default nuclei template directory
// Caches the result to avoid repeated lookups
// Exported for use in other packages
func GetNucleiDefaultTemplateDir() string {
	templateDirOnce.Do(func() {
		// Try to get from nuclei config
		if cfg := config.DefaultConfig; cfg != nil && cfg.TemplatesDirectory != "" {
			cachedTemplateDir = cfg.TemplatesDirectory
			return
		}

		// Fallback to default location: $HOME/nuclei-templates
		homeDir, err := os.UserHomeDir()
		if err != nil {
			cachedTemplateDir = ""
			return
		}

		cachedTemplateDir = filepath.Join(homeDir, "nuclei-templates")
	})
	return cachedTemplateDir
}

// extractAllPorts is the super function that calls all port extractors
func extractAllPorts(content string) []string {
	var allPorts []string

	// Call all extractors
	allPorts = append(allPorts, extractJavascriptSinglePort(content)...)
	allPorts = append(allPorts, extractJavascriptMultiplePorts(content)...)
	allPorts = append(allPorts, extractHttpProtocolPorts(content)...)

	return allPorts
}

// extractJavascriptSinglePort extracts single port from JavaScript template format
// Pattern: Port: "3389" or Port: 3389
func extractJavascriptSinglePort(content string) []string {
	var ports []string
	regex := regexp.MustCompile(`(?i)(?:^|\s)Port:\s*["']?(\d+)["']?\s*$`)

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		matches := regex.FindStringSubmatch(line)
		if len(matches) > 1 {
			port := matches[1]
			if isValidPort(port) {
				ports = append(ports, port)
			}
		}
	}

	return ports
}

// extractJavascriptMultiplePorts extracts multiple ports from JavaScript template format
// Pattern: ports: port1,port2 or ports: [port1, port2]
func extractJavascriptMultiplePorts(content string) []string {
	var ports []string
	regex := regexp.MustCompile(`(?i)(?:^|\s)ports:\s*([\d,\s\[\]]+)\s*$`)

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		matches := regex.FindStringSubmatch(line)
		if len(matches) > 1 {
			portsStr := matches[1]
			// Remove brackets if present
			portsStr = strings.Trim(portsStr, "[]")
			// Split by comma
			portParts := strings.Split(portsStr, ",")
			for _, part := range portParts {
				port := strings.TrimSpace(part)
				if isValidPort(port) {
					ports = append(ports, port)
				}
			}
		}
	}

	return ports
}

// extractHttpProtocolPorts extracts ports 80 and 443 if http protocol is detected
// Pattern: http: section in template
func extractHttpProtocolPorts(content string) []string {
	var ports []string
	regex := regexp.MustCompile(`(?i)^\s*http:\s*$`)

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if regex.MatchString(line) {
			// HTTP protocol detected, add default HTTP ports
			ports = append(ports, "80", "443")
			break
		}
	}

	return ports
}

// isValidPort validates if a string is a valid port number (1-65535)
func isValidPort(portStr string) bool {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}
	return port > 0 && port <= 65535
}
