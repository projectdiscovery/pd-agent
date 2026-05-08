// Package runtools embeds ProjectDiscovery scanners (tlsx, dnsx, httpx, naabu,
// nuclei) as Go SDK calls instead of shelling out to CLI binaries. Each
// function exposes the narrow surface pd-agent actually uses — not the full
// CLI flag set — and writes output files in the same JSONL format the CLIs
// produce, so downstream pipeline steps remain unchanged.
package runtools
