// Package scanlog ships raw per-chunk nuclei output (matched and unmatched)
// to one or more storage destinations.
package scanlog

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/projectdiscovery/pd-agent/pkg/envconfig"
)

// Meta identifies the chunk a scan log belongs to.
type Meta struct {
	TeamID    string
	ScanID    string
	ChunkID   string
	HistoryID int64
}

// Uploader ships one gzipped scan log. Implementations receive an already
// compressed file and return where the object landed.
type Uploader interface {
	Upload(ctx context.Context, m Meta, gzPath string, gzSize int64) (location string, err error)
	Name() string
}

// Destinations resolves the configured upload targets. An empty slice means
// scan-log upload is off.
func Destinations() []Uploader {
	var dests []Uploader
	if envconfig.ScanLogUploadEnabled() {
		dests = append(dests, NewPlatformUploader())
	}
	return dests
}

// Upload gzips outputFile once and ships it to every destination. An empty
// output file is skipped without contacting any destination.
func Upload(ctx context.Context, dests []Uploader, m Meta, outputFile string) error {
	if len(dests) == 0 {
		return nil
	}

	info, err := os.Stat(outputFile)
	if err != nil {
		return fmt.Errorf("stat output: %w", err)
	}
	if info.Size() == 0 {
		slog.Debug("scan-log: output file empty, skipping upload",
			"scan_id", m.ScanID, "chunk_id", m.ChunkID)
		return nil
	}

	// Gzip into a sibling temp so we can stat for ContentLength. Unique name
	// keeps a redelivered chunk from clobbering a still-uploading goroutine.
	gzFile, err := os.CreateTemp(filepath.Dir(outputFile), filepath.Base(outputFile)+"-*.gz")
	if err != nil {
		return fmt.Errorf("create gz tempfile: %w", err)
	}
	gzPath := gzFile.Name()
	_ = gzFile.Close()
	defer func() { _ = os.Remove(gzPath) }()

	gzSize, err := gzipFile(outputFile, gzPath)
	if err != nil {
		return fmt.Errorf("gzip output: %w", err)
	}

	slog.Debug("scan-log: gzipped output",
		"scan_id", m.ScanID, "chunk_id", m.ChunkID,
		"raw_bytes", info.Size(), "gz_bytes", gzSize)

	var errs []error
	for _, dest := range dests {
		location, err := dest.Upload(ctx, m, gzPath, gzSize)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", dest.Name(), err))
			continue
		}
		slog.Info("scan-log: output file uploaded",
			"dest", dest.Name(),
			"scan_id", m.ScanID,
			"history_id", m.HistoryID,
			"chunk_id", m.ChunkID,
			"raw_bytes", info.Size(),
			"gz_bytes", gzSize,
			"location", location)
	}

	return errors.Join(errs...)
}

// gzipFile streams src through gzip into dst at BestSpeed (nuclei JSONL
// compresses ~10x even at level 1) and returns the dst size.
func gzipFile(src, dst string) (int64, error) {
	in, err := os.Open(src)
	if err != nil {
		return 0, fmt.Errorf("open src: %w", err)
	}
	defer func() { _ = in.Close() }()

	out, err := os.Create(dst)
	if err != nil {
		return 0, fmt.Errorf("create dst: %w", err)
	}
	gzw, err := gzip.NewWriterLevel(out, gzip.BestSpeed)
	if err != nil {
		_ = out.Close()
		return 0, fmt.Errorf("gzip writer: %w", err)
	}
	if _, err := io.Copy(gzw, in); err != nil {
		_ = gzw.Close()
		_ = out.Close()
		return 0, fmt.Errorf("gzip copy: %w", err)
	}
	if err := gzw.Close(); err != nil {
		_ = out.Close()
		return 0, fmt.Errorf("gzip close: %w", err)
	}
	if err := out.Close(); err != nil {
		return 0, fmt.Errorf("close dst: %w", err)
	}
	st, err := os.Stat(dst)
	if err != nil {
		return 0, fmt.Errorf("stat dst: %w", err)
	}
	return st.Size(), nil
}
