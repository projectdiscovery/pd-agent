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

// UpdateNucleiTemplates installs nuclei-templates if missing, otherwise checks
// for updates and applies them. Replaces a `nuclei -update-templates` shell-out.
// Idempotent: safe to call at every agent startup.
func UpdateNucleiTemplates() error {
	tm := &installer.TemplateManager{}
	if err := tm.UpdateIfOutdated(); err != nil {
		return fmt.Errorf("update nuclei templates: %w", err)
	}
	return nil
}

// NucleiOptions configures an embedded nuclei scan. Mirrors the CLI flags
// pd-agent's scan path drives today.
type NucleiOptions struct {
	// OutputFile receives one JSON ResultEvent per match. Required.
	OutputFile string
	// Targets is the list of hosts/URLs to scan. Required.
	Targets []string
	// Templates is the list of template paths or IDs to run. Empty means run
	// the default template set.
	Templates []string
	// ScanID and TeamID gate dashboard upload — pd-agent does the upload
	// itself via the embedded helper, so we just stamp these into output.
	ScanID string
	TeamID string
	// AllowLocalFileAccess maps to nuclei's -lfa flag.
	AllowLocalFileAccess bool
	// MatcherStatus emits records for failed matches too (nuclei -ms).
	MatcherStatus bool
	// EnableCodeTemplates allows code: protocol templates (nuclei -code).
	// pd-agent gates this by available RAM (>2GB).
	EnableCodeTemplates bool
	// Headless allows browser-driven templates (nuclei -headless). pd-agent
	// gates this by RAM (>8GB) and arch (amd64).
	Headless bool
	// ProbeNonHttp passes through to LoadTargets — when true, nuclei probes
	// non-HTTP services via tcp/dns/etc. Defaults to false (HTTP-only).
	ProbeNonHttp bool
	// ConfigYAML is the raw -config style YAML the cloud sent in the work
	// message (already base64-decoded by the caller). When non-empty it's
	// merged into engine options via the SDK's WithConfigBytes — same path
	// the CLI uses for `-config <path>`.
	ConfigYAML []byte
	// ReportingConfigYAML is the raw -report-config style YAML (Jira/Linear/
	// etc. tracker config). When non-empty it's merged via the SDK's
	// WithReportingConfigBytes. nuclei also resolves `report-config: <path>`
	// references inside ConfigYAML implicitly, so most callers won't need
	// this field unless the reporting YAML is sent inline.
	ReportingConfigYAML []byte
}

// RunNuclei runs nuclei via the embedded SDK and writes one JSON ResultEvent
// per finding to opts.OutputFile (matching `nuclei -jsonl -o`). Returns the
// output path.
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
	}
	if len(opts.Templates) > 0 {
		sdkOpts = append(sdkOpts, nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
			Templates: opts.Templates,
		}))
	}
	if opts.Headless {
		sdkOpts = append(sdkOpts, nuclei.EnableHeadlessWithOpts(nil))
	}
	if len(opts.ConfigYAML) > 0 {
		sdkOpts = append(sdkOpts, nuclei.WithConfigBytes(opts.ConfigYAML))
	}
	if len(opts.ReportingConfigYAML) > 0 {
		sdkOpts = append(sdkOpts, nuclei.WithReportingConfigBytes(opts.ReportingConfigYAML))
	}
	// PDCP cloud upload: matches CLI -dashboard -scan-id -team-id. The SDK
	// wraps the engine's output writer with pdcp.UploadWriter, which filters
	// to matched results only (its inner StandardWriter defaults
	// matcherStatus=false), exactly as the CLI does today.
	if opts.ScanID != "" {
		sdkOpts = append(sdkOpts, nuclei.WithPDCPUpload(opts.ScanID, opts.TeamID))
	}

	ne, err := nuclei.NewNucleiEngineCtx(ctx, sdkOpts...)
	if err != nil {
		return opts.OutputFile, fmt.Errorf("init nuclei engine: %w", err)
	}
	defer ne.Close()

	// Stamp options on the underlying engine that don't have dedicated SDK
	// option functions. Matches the CLI flag set pd-agent passes today.
	if engineOpts := ne.Options(); engineOpts != nil {
		engineOpts.AllowLocalFileAccess = opts.AllowLocalFileAccess
		engineOpts.MatcherStatus = opts.MatcherStatus
		engineOpts.EnableCodeTemplates = opts.EnableCodeTemplates
		engineOpts.JSONL = true
	}

	ne.LoadTargets(opts.Targets, opts.ProbeNonHttp)

	err = ne.ExecuteCallbackWithCtx(ctx, func(event *output.ResultEvent) {
		if event == nil {
			return
		}
		// Strip Interaction since it can carry raw bytes from interactsh
		// DNS responses that fail JSON marshal with control-char errors.
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
