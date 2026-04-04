package natsrpc

import (
	"sync"
	"time"
)

// LogEntry represents a single log line stored in the ring buffer.
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
}

// LogBuffer is a thread-safe, fixed-capacity ring buffer for log entries.
// When full, the oldest entry is silently overwritten.
type LogBuffer struct {
	mu      sync.RWMutex
	entries []LogEntry
	cap     int
	head    int // next write index (wraps around)
	count   int // total entries currently in buffer (max = cap)
}

// NewLogBuffer allocates a ring buffer that holds up to capacity entries.
func NewLogBuffer(capacity int) *LogBuffer {
	return &LogBuffer{
		entries: make([]LogEntry, capacity),
		cap:     capacity,
	}
}

// Add appends an entry, overwriting the oldest if full.
func (b *LogBuffer) Add(entry LogEntry) {
	b.mu.Lock()
	b.entries[b.head] = entry
	b.head = (b.head + 1) % b.cap
	if b.count < b.cap {
		b.count++
	}
	b.mu.Unlock()
}

// Query returns up to `limit` entries starting from `offset` (0 = oldest in buffer).
// Also returns the total number of entries in the buffer.
// If level is non-empty, only entries matching that level are returned.
func (b *LogBuffer) Query(offset, limit int, level string) ([]LogEntry, int) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.count == 0 || limit <= 0 {
		return nil, b.count
	}

	// oldest entry is at (head - count + cap) % cap
	oldest := (b.head - b.count + b.cap) % b.cap

	if level == "" {
		// No filter — direct slice from ring buffer
		if offset >= b.count {
			return nil, b.count
		}
		end := offset + limit
		if end > b.count {
			end = b.count
		}

		result := make([]LogEntry, 0, end-offset)
		for i := offset; i < end; i++ {
			idx := (oldest + i) % b.cap
			result = append(result, b.entries[idx])
		}
		return result, b.count
	}

	// With level filter — iterate and collect matching entries
	var result []LogEntry
	skipped := 0
	for i := 0; i < b.count && len(result) < limit; i++ {
		idx := (oldest + i) % b.cap
		if b.entries[idx].Level != level {
			continue
		}
		if skipped < offset {
			skipped++
			continue
		}
		result = append(result, b.entries[idx])
	}
	return result, b.count
}
