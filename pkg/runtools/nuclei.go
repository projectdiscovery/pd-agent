package runtools

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/installer"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// UpdateNucleiTemplates installs nuclei-templates if missing, otherwise
// updates them. Idempotent.
func UpdateNucleiTemplates() error {
	tm := &installer.TemplateManager{}
	if err := tm.UpdateIfOutdated(); err != nil {
		return fmt.Errorf("update nuclei templates: %w", err)
	}
	return nil
}

// NucleiOptions configures an embedded nuclei scan.
type NucleiOptions struct {
	// OutputFile receives one JSON ResultEvent per match. Required.
	OutputFile string
	// Targets is the list of hosts/URLs to scan. Required.
	Targets []string
	// Templates lists template paths or IDs; empty runs the default set.
	Templates []string
	// ScanID and TeamID stamp dashboard-upload metadata into output.
	ScanID               string
	TeamID               string
	AllowLocalFileAccess bool
	MatcherStatus        bool
	EnableCodeTemplates  bool
	Headless             bool
	// ProbeNonHttp enables tcp/dns/etc protocol probing in addition to HTTP.
	ProbeNonHttp bool
	// ConfigYAML is the cloud-shipped nuclei RuntimeConfig (tags, severity,
	// rate-limit, ...). Already base64-decoded by the caller.
	ConfigYAML []byte
	// ReportingConfigYAML is the cloud-shipped tracker config (Jira/Linear/GitHub/etc.).
	ReportingConfigYAML []byte
}

// RunNuclei runs nuclei via the embedded SDK and writes one JSON ResultEvent
// per finding to opts.OutputFile.
func RunNuclei(ctx context.Context, opts NucleiOptions) (string, error) {
	if opts.OutputFile == "" {
		return "", errors.New("RunNuclei: OutputFile is required")
	}
	if len(opts.Targets) == 0 {
		return "", errors.New("RunNuclei: Targets is required")
	}

	out, err := os.Create(opts.OutputFile)
	if err != nil {
		return "", fmt.Errorf("create output file: %w", err)
	}
	defer out.Close()

	bw := bufio.NewWriter(out)
	defer bw.Flush()

	var (
		mu       sync.Mutex
		writeErr error
	)
	writeLine := func(line []byte) {
		mu.Lock()
		defer mu.Unlock()
		if writeErr != nil {
			return
		}
		if _, err := bw.Write(line); err != nil {
			writeErr = err
			return
		}
		if err := bw.WriteByte('\n'); err != nil {
			writeErr = err
		}
	}

	sdkOpts := []nuclei.NucleiSDKOptions{
		nuclei.WithVerbosity(nuclei.VerbosityOptions{Silent: true}),
		nuclei.WithSandboxOptions(opts.AllowLocalFileAccess, false),
	}
	if len(opts.Templates) > 0 {
		sdkOpts = append(sdkOpts, nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
			Templates: opts.Templates,
		}))
	}
	if opts.Headless {
		sdkOpts = append(sdkOpts, nuclei.EnableHeadlessWithOpts(nil))
	}
	if opts.MatcherStatus {
		sdkOpts = append(sdkOpts, nuclei.EnableMatcherStatus())
	}
	if opts.EnableCodeTemplates {
		sdkOpts = append(sdkOpts, nuclei.EnableCodeTemplates())
	}
	if len(opts.ConfigYAML) > 0 {
		sdkOpts = append(sdkOpts, nuclei.WithConfigBytes(opts.ConfigYAML))
	}
	if len(opts.ReportingConfigYAML) > 0 {
		sdkOpts = append(sdkOpts, nuclei.WithReportingConfigBytes(opts.ReportingConfigYAML))
	}
	if opts.ScanID != "" {
		sdkOpts = append(sdkOpts, nuclei.WithPDCPUpload(opts.ScanID, opts.TeamID))
	}

	ne, err := nuclei.NewNucleiEngineCtx(ctx, sdkOpts...)
	if err != nil {
		return opts.OutputFile, fmt.Errorf("init nuclei engine: %w", err)
	}
	defer ne.Close()

	ne.LoadTargets(opts.Targets, opts.ProbeNonHttp)

	err = ne.ExecuteCallbackWithCtx(ctx, func(event *output.ResultEvent) {
		if event == nil {
			return
		}
		// Interaction can carry raw bytes from interactsh DNS responses that
		// fail JSON marshal with control-char errors.
		event.Interaction = nil

		line, marshalErr := json.Marshal(event)
		if marshalErr != nil {
			slog.Debug("nuclei: marshal event failed", "err", marshalErr)
			return
		}
		writeLine(line)
	})
	if err != nil {
		return opts.OutputFile, fmt.Errorf("nuclei execution: %w", err)
	}

	if writeErr != nil {
		return opts.OutputFile, fmt.Errorf("write output: %w", writeErr)
	}
	return opts.OutputFile, nil
}
