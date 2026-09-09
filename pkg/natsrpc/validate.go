package natsrpc

import (
	"fmt"

	"github.com/projectdiscovery/pd-agent/pkg/validate"
)

// safeIdentifier accepts an absent id and rejects an unsafe one.
//
// Absent is not unsafe: pkg/execute.go falls back to "nuclei" for an empty
// chunk id and main.go's output dir degrades to the configured root, so the
// agent already handles it. A decode error terminates the message with no
// redelivery, so treating absent as fatal would permanently discard work the
// rest of the agent would have processed.
//
// A separator or a ".." segment is a different matter, because both escape the
// path or object key the id is interpolated into.
func safeIdentifier(field, value string) error {
	if value == "" {
		return nil
	}
	if _, err := validate.PathSegment(field, value); err != nil {
		return err
	}
	return nil
}

// Validate checks the identifiers the agent does not generate itself before
// anything downstream interpolates them into a path, a URL or an object key.
//
// This is the ingest boundary: scan and chunk ids arrive on the group stream
// and reach filesystem paths (pkg/execute.go), the platform API URL and
// customer object storage. Checking here means each of those sinks inherits
// the guarantee instead of repeating the check and eventually missing one.
func (w *WorkMessage) Validate() error {
	if err := safeIdentifier("scan_id", w.ScanID); err != nil {
		return fmt.Errorf("work message: %w", err)
	}
	return nil
}

// Validate checks the chunk id for the same reason WorkMessage.Validate does.
func (c *ChunkMessage) Validate() error {
	if err := safeIdentifier("chunk_id", c.ChunkID); err != nil {
		return fmt.Errorf("chunk message: %w", err)
	}
	return nil
}
