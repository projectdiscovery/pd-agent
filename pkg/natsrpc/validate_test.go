package natsrpc

import (
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/proto"

	"github.com/projectdiscovery/pd-agent/pkg/agentproto"
)

// These ids reach filesystem paths, the platform API URL and customer object
// storage. Rejecting at ingest is what lets those sinks interpolate them.
func TestWorkMessageValidate(t *testing.T) {
	tests := []struct {
		name    string
		scanID  string
		wantErr bool
	}{
		{"xid", "d35h1tee67qc73c71olg", false},
		{"uuid", "3f2504e0-4f89-11d3-9a0c-0305e82c3301", false},
		{"dotted", "scan-abc.1", false},
		{"empty is not unsafe", "", false},
		{"traversal", "../../../../tmp/pwned", true},
		{"separator", "a/b", true},
		{"dotdot", "..", true},
		{"newline", "scan\nid", true},
		{"null byte", "scan\x00id", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := (&WorkMessage{ScanID: tt.scanID}).Validate()
			if tt.wantErr && err == nil {
				t.Errorf("Validate() = nil for %q, want rejected", tt.scanID)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Validate() = %v for %q, want accepted", err, tt.scanID)
			}
		})
	}
}

func TestChunkMessageValidate(t *testing.T) {
	if err := (&ChunkMessage{ChunkID: "c1"}).Validate(); err != nil {
		t.Errorf("Validate() = %v for a normal id", err)
	}
	if err := (&ChunkMessage{ChunkID: ""}).Validate(); err != nil {
		t.Errorf("Validate() = %v for an absent id; execute.go falls back to \"nuclei\" so absent must not drop the chunk", err)
	}
	for _, bad := range []string{"..", "../../etc/cron.d/x", `a\b`, "c\x00"} {
		if err := (&ChunkMessage{ChunkID: bad}).Validate(); err == nil {
			t.Errorf("Validate() = nil for %q, want rejected", bad)
		}
	}
}

// A malformed id cannot be fixed by redelivery, so decode must reject it and
// let the caller Term the message rather than nak it into a poison loop.
func TestDecodeChunkMsgRejectsUnsafeChunkID(t *testing.T) {
	data, err := encodeScanChunkForTest("../../../../tmp/pwned")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := decodeChunkMsg(data); err == nil {
		t.Fatal("decodeChunkMsg() = nil error, want the traversal rejected")
	} else if !strings.Contains(err.Error(), "chunk_id") {
		t.Errorf("error = %q, want it to name chunk_id", err)
	}
}

func TestDecodeChunkMsgAcceptsRealChunkID(t *testing.T) {
	data, err := encodeScanChunkForTest("d35h1tf67qc73c71olh")
	if err != nil {
		t.Fatal(err)
	}

	chunk, err := decodeChunkMsg(data)
	if err != nil {
		t.Fatalf("decodeChunkMsg: %v", err)
	}
	if chunk.ChunkID != "d35h1tf67qc73c71olh" {
		t.Errorf("ChunkID = %q", chunk.ChunkID)
	}
}

// Mirrors publishChunk's wire format: ZSTD-compressed ScanRequest protobuf.
func encodeScanChunkForTest(chunkID string) ([]byte, error) {
	data, err := proto.Marshal(&agentproto.ScanRequest{ChunkID: chunkID})
	if err != nil {
		return nil, err
	}
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = enc.Close() }()
	return enc.EncodeAll(data, nil), nil
}

// The reason the gate sits at ingest rather than in each sink: a chunk id that
// would escape its output directory never reaches executeNucleiScan, so the
// filepath.Join in pkg/execute.go is covered without touching it.
func TestIngestGateBlocksTraversalBeforeAnySink(t *testing.T) {
	traversals := []string{
		"../../../../tmp/pwned",
		"../../etc/cron.d/x",
		"..",
		`..\..\windows\system32\x`,
	}

	for _, chunkID := range traversals {
		t.Run(chunkID, func(t *testing.T) {
			data, err := encodeScanChunkForTest(chunkID)
			if err != nil {
				t.Fatal(err)
			}
			chunk, err := decodeChunkMsg(data)
			if err == nil {
				t.Fatalf("decode accepted %q and would hand it to filepath.Join as %q",
					chunkID, chunk.ChunkID)
			}
		})
	}
}

// Enumeration chunks decode from plain protobuf, not ZSTD, and go through the
// same gate. ChunkID is proto3 field 4 with no presence semantics, so an
// absent one has to survive: decodeChunkMsg's error terminates the message
// with no redelivery, which would discard the enumeration permanently.
func TestDecodeEnrichmentChunk(t *testing.T) {
	tests := []struct {
		name       string
		chunkID    string
		wantReject bool
	}{
		{"normal id", "d35h1tf67qc73c71olh", false},
		{"absent id must not drop the chunk", "", false},
		{"traversal is still rejected", "../../../../tmp/pwned", true},
		{"separator is still rejected", "a/b", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := proto.Marshal(&agentproto.AssetEnrichmentRequest{
				ChunkID:      tt.chunkID,
				EnrichmentID: "e1",
			})
			if err != nil {
				t.Fatal(err)
			}

			chunk, err := decodeChunkMsg(data)
			if tt.wantReject {
				if err == nil {
					t.Fatalf("decodeChunkMsg accepted %q and would hand it to filepath.Join", tt.chunkID)
				}
				return
			}
			if err != nil {
				t.Fatalf("decodeChunkMsg: %v", err)
			}
			if chunk.ChunkID != tt.chunkID {
				t.Errorf("ChunkID = %q, want %q", chunk.ChunkID, tt.chunkID)
			}
		})
	}
}
