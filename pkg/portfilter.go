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

// FilterTargetsByTemplatePorts extracts ports from templates, runs naabu
// against (host x ports), and returns the URLs whose ports were reachable
// plus the merged port list.
func FilterTargetsByTemplatePorts(ctx context.Context, targetsFile, templatesFile, scanID, chunkID string) ([]string, []string, error) {
	targetsF, err := os.Open(targetsFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open targets file: %w", err)
	}
	defer func() {
		_ = targetsF.Close()
	}()

	// nuclei's SDK does not auto-probe scheme for bare host:port targets the
	// way the CLI does, so preserve the input scheme to keep {{BaseURL}}
	// templates working.
	var hosts []string
	var ports []string
	hostSchemes := make(map[string]string)

	scanner := bufio.NewScanner(targetsF)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		stripped := line
		scheme := ""
		if idx := strings.Index(stripped, "://"); idx != -1 {
			scheme = stripped[:idx]
			stripped = stripped[idx+3:]
		}
		if idx := strings.Index(stripped, "/"); idx != -1 {
			stripped = stripped[:idx]
		}

		host, port, err := net.SplitHostPort(stripped)
		if err == nil {
			hosts = append(hosts, host)
			if port != "" {
				ports = append(ports, port)
			}
			if scheme != "" {
				hostSchemes[host] = scheme
			}
		} else {
			hosts = append(hosts, stripped)
			if scheme != "" {
				hostSchemes[stripped] = scheme
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("error reading targets file: %w", err)
	}

	templatePorts, _, err := extractPortsFromTemplatesFile(templatesFile, scanID, chunkID)
	if err != nil {
		return nil, nil, fmt.Errorf("error extracting ports from templates: %w", err)
	}

	allPorts := make(map[string]struct{})
	for _, p := range ports {
		allPorts[p] = struct{}{}
	}
	for _, p := range templatePorts {
		allPorts[p] = struct{}{}
	}

	mergedPorts := make([]string, 0, len(allPorts))
	for p := range allPorts {
		mergedPorts = append(mergedPorts, p)
	}

	hosts = sliceutil.Dedupe(hosts)
	mergedPorts = sliceutil.Dedupe(mergedPorts)

	var hostPorts map[string][]string
	if len(hosts) > 0 && len(mergedPorts) > 0 {
		hostPorts, err = runNaabuScan(ctx, hosts, mergedPorts, scanID, chunkID)
		if err != nil {
			slog.Warn("Naabu scan failed",
				"scan_id", scanID,
				"chunk_id", chunkID,
				"error", err)
		}
	}

	out := make([]string, 0)
	for host, openPorts := range hostPorts {
		scheme := hostSchemes[host]
		for _, p := range openPorts {
			hostport := net.JoinHostPort(host, p)
			if scheme != "" {
				out = append(out, scheme+"://"+hostport)
			} else {
				out = append(out, hostport)
			}
		}
	}
	out = sliceutil.Dedupe(out)

	return out, mergedPorts, nil
}

// runNaabuScan returns host -> []openPort for hosts with at least one reachable port.
func runNaabuScan(ctx context.Context, targets []string, ports []string, scanID, chunkID string) (map[string][]string, error) {
	if len(targets) == 0 || len(ports) == 0 {
		slog.Info("naabu prefilter: skipped (no targets or ports)",
			"scan_id", scanID, "chunk_id", chunkID,
			"targets", len(targets), "ports", len(ports))
		return nil, nil
	}

	portStr := strings.Join(ports, ",")

	slog.Info("naabu prefilter: running",
		"scan_id", scanID, "chunk_id", chunkID,
		"targets", targets, "ports", portStr)

	var mu sync.Mutex
	hostPorts := make(map[string][]string)

	options := &runner.Options{
		Host:              goflags.StringSlice(targets),
		Ports:             portStr,
		SkipHostDiscovery: true,
		Silent:            true,
		OnResult: func(hr *result.HostResult) {
			if hr.Host == "" || len(hr.Ports) == 0 {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, p := range hr.Ports {
				hostPorts[hr.Host] = append(hostPorts[hr.Host], strconv.Itoa(p.Port))
			}
		},
	}

	naabuRunner, err := runner.NewRunner(options)
	if err != nil {
		return nil, fmt.Errorf("failed to create naabu runner: %w", err)
	}
	defer func() {
		_ = naabuRunner.Close()
	}()

	err = naabuRunner.RunEnumeration(ctx)
	if err != nil {
		// naabu returns an error when no ports are found; not fatal.
		slog.Debug("Naabu enumeration completed",
			"scan_id", scanID,
			"chunk_id", chunkID,
			"status", err)
	}

	mu.Lock()
	for h := range hostPorts {
		hostPorts[h] = sliceutil.Dedupe(hostPorts[h])
	}
	mu.Unlock()

	slog.Info("naabu prefilter: completed",
		"scan_id", scanID, "chunk_id", chunkID,
		"input_hosts", len(targets), "host_ports", hostPorts)

	return hostPorts, nil
}

// extractPortsFromTemplatesFile reads the templates file and extracts ports
// from each template in parallel. Returns ports, template count, and error.
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

	if len(templatePaths) == 0 {
		defaultTemplateDir := GetNucleiDefaultTemplateDir()
		if defaultTemplateDir != "" {
			err := filepath.Walk(defaultTemplateDir, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !info.IsDir() {
					ext := filepath.Ext(path)
					if ext == ".yaml" || ext == ".yml" {
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
		if len(templatePaths) == 0 {
			return []string{}, 0, nil
		}
	}

	defaultTemplateDir := GetNucleiDefaultTemplateDir()

	portSet := mapsutil.NewSyncLockMap[string, struct{}]()

	var templateCount int64

	awg, err := syncutil.New(syncutil.WithSize(50))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create syncutil: %w", err)
	}

	for _, templatePath := range templatePaths {
		templatePath := templatePath

		awg.Add()
		go func(tp string) {
			defer awg.Done()

			atomic.AddInt64(&templateCount, 1)

			resolvedPath := tp
			if !filepath.IsAbs(tp) {
				if defaultTemplateDir != "" {
					resolvedPath = filepath.Join(defaultTemplateDir, tp)
				}
			}

			templateContent, err := os.ReadFile(resolvedPath)
			if err != nil {
				slog.Error("Failed to read template file",
					"scan_id", scanID,
					"chunk_id", chunkID,
					"template_path", tp,
					"resolved_path", resolvedPath,
					"error", err)
				return
			}

			content := string(templateContent)

			ports := extractAllPorts(content)
			for _, port := range ports {
				_ = portSet.Set(port, struct{}{})
			}
		}(templatePath)
	}

	awg.Wait()

	allPorts := make([]string, 0)
	allPortsMap := portSet.GetAll()
	for p := range allPortsMap {
		allPorts = append(allPorts, p)
	}

	return allPorts, int(templateCount), nil
}

var cachedTemplateDir string
var templateDirOnce sync.Once

// GetNucleiDefaultTemplateDir returns the default nuclei template directory, cached.
func GetNucleiDefaultTemplateDir() string {
	templateDirOnce.Do(func() {
		if cfg := config.DefaultConfig; cfg != nil && cfg.TemplatesDirectory != "" {
			cachedTemplateDir = cfg.TemplatesDirectory
			return
		}

		homeDir, err := os.UserHomeDir()
		if err != nil {
			cachedTemplateDir = ""
			return
		}

		cachedTemplateDir = filepath.Join(homeDir, "nuclei-templates")
	})
	return cachedTemplateDir
}

func extractAllPorts(content string) []string {
	var allPorts []string
	allPorts = append(allPorts, extractJavascriptSinglePort(content)...)
	allPorts = append(allPorts, extractJavascriptMultiplePorts(content)...)
	allPorts = append(allPorts, extractHttpProtocolPorts(content)...)
	return allPorts
}

// extractJavascriptSinglePort matches: Port: "3389" or Port: 3389.
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

// extractJavascriptMultiplePorts matches: ports: 1,2 or ports: [1, 2].
func extractJavascriptMultiplePorts(content string) []string {
	var ports []string
	regex := regexp.MustCompile(`(?i)(?:^|\s)ports:\s*([\d,\s\[\]]+)\s*$`)

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		matches := regex.FindStringSubmatch(line)
		if len(matches) > 1 {
			portsStr := matches[1]
			portsStr = strings.Trim(portsStr, "[]")
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

// extractHttpProtocolPorts returns 80 and 443 if the template has an http: section.
func extractHttpProtocolPorts(content string) []string {
	var ports []string
	regex := regexp.MustCompile(`(?i)^\s*http:\s*$`)

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if regex.MatchString(line) {
			ports = append(ports, "80", "443")
			break
		}
	}

	return ports
}

func isValidPort(portStr string) bool {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}
	return port > 0 && port <= 65535
}
