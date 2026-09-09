package natsrpc

import (
	"fmt"

	"github.com/projectdiscovery/pd-agent/pkg/validate"
)

// Validate checks the identifiers the agent does not generate itself before
// anything downstream interpolates them into a path, a URL or an object key.
//
// This is the ingest boundary: scan and chunk ids arrive on the group stream
// and reach filesystem paths (pkg/execute.go), the platform API URL and
// customer object storage. Checking here means each of those sinks inherits
// the guarantee instead of repeating the check and eventually missing one.
func (w *WorkMessage) Validate() error {
	if _, err := validate.PathSegment("scan_id", w.ScanID); err != nil {
		return fmt.Errorf("work message: %w", err)
	}
	return nil
}

// Validate checks the chunk id for the same reason WorkMessage.Validate does.
func (c *ChunkMessage) Validate() error {
	if _, err := validate.PathSegment("chunk_id", c.ChunkID); err != nil {
		return fmt.Errorf("chunk message: %w", err)
	}
	return nil
}
