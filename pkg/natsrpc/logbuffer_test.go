package natsrpc

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func makeEntry(level, msg string) LogEntry {
	return LogEntry{
		Timestamp: time.Now().UTC(),
		Level:     level,
		Message:   msg,
	}
}

func TestLogBuffer_AddAndQuery(t *testing.T) {
	buf := NewLogBuffer(10)

	buf.Add(makeEntry("INFO", "hello"))
	buf.Add(makeEntry("ERROR", "boom"))

	entries, total := buf.Query(0, 10, "")
	if total != 2 {
		t.Fatalf("expected total=2, got %d", total)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Message != "hello" {
		t.Errorf("expected first message 'hello', got %q", entries[0].Message)
	}
	if entries[1].Message != "boom" {
		t.Errorf("expected second message 'boom', got %q", entries[1].Message)
	}
}

func TestLogBuffer_WrapAround(t *testing.T) {
	buf := NewLogBuffer(3)

	// Add 5 entries into a buffer of capacity 3 — first two should be evicted
	for i := 0; i < 5; i++ {
		buf.Add(makeEntry("INFO", fmt.Sprintf("msg-%d", i)))
	}

	entries, total := buf.Query(0, 10, "")
	if total != 3 {
		t.Fatalf("expected total=3 (capacity), got %d", total)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	// Oldest surviving entry should be msg-2
	if entries[0].Message != "msg-2" {
		t.Errorf("expected oldest entry 'msg-2', got %q", entries[0].Message)
	}
	if entries[2].Message != "msg-4" {
		t.Errorf("expected newest entry 'msg-4', got %q", entries[2].Message)
	}
}

func TestLogBuffer_OffsetLimit(t *testing.T) {
	buf := NewLogBuffer(10)

	for i := 0; i < 7; i++ {
		buf.Add(makeEntry("INFO", fmt.Sprintf("msg-%d", i)))
	}

	// Offset 2, limit 3 → entries msg-2, msg-3, msg-4
	entries, total := buf.Query(2, 3, "")
	if total != 7 {
		t.Fatalf("expected total=7, got %d", total)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	if entries[0].Message != "msg-2" {
		t.Errorf("expected 'msg-2', got %q", entries[0].Message)
	}
	if entries[2].Message != "msg-4" {
		t.Errorf("expected 'msg-4', got %q", entries[2].Message)
	}

	// Offset beyond count
	entries, _ = buf.Query(100, 10, "")
	if len(entries) != 0 {
		t.Errorf("expected empty for offset beyond count, got %d entries", len(entries))
	}

	// Limit clips to remaining entries
	entries, _ = buf.Query(5, 100, "")
	if len(entries) != 2 {
		t.Errorf("expected 2 remaining entries, got %d", len(entries))
	}
}

func TestLogBuffer_LevelFilter(t *testing.T) {
	buf := NewLogBuffer(10)

	buf.Add(makeEntry("INFO", "info-1"))
	buf.Add(makeEntry("ERROR", "error-1"))
	buf.Add(makeEntry("INFO", "info-2"))
	buf.Add(makeEntry("WARNING", "warn-1"))
	buf.Add(makeEntry("ERROR", "error-2"))

	entries, total := buf.Query(0, 10, "ERROR")
	if total != 5 {
		t.Fatalf("expected total=5, got %d", total)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 ERROR entries, got %d", len(entries))
	}
	if entries[0].Message != "error-1" || entries[1].Message != "error-2" {
		t.Errorf("unexpected entries: %v", entries)
	}

	// Level filter with offset
	entries, _ = buf.Query(1, 10, "ERROR")
	if len(entries) != 1 {
		t.Fatalf("expected 1 ERROR entry with offset=1, got %d", len(entries))
	}
	if entries[0].Message != "error-2" {
		t.Errorf("expected 'error-2', got %q", entries[0].Message)
	}

	// Non-existent level
	entries, _ = buf.Query(0, 10, "CRITICAL")
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for CRITICAL, got %d", len(entries))
	}
}

func TestLogBuffer_EmptyBuffer(t *testing.T) {
	buf := NewLogBuffer(10)

	entries, total := buf.Query(0, 10, "")
	if total != 0 {
		t.Errorf("expected total=0, got %d", total)
	}
	if entries != nil {
		t.Errorf("expected nil entries, got %v", entries)
	}

	// Zero limit
	buf.Add(makeEntry("INFO", "x"))
	entries, total = buf.Query(0, 0, "")
	if total != 1 {
		t.Errorf("expected total=1, got %d", total)
	}
	if entries != nil {
		t.Errorf("expected nil entries for limit=0, got %v", entries)
	}
}

func TestLogBuffer_ConcurrentSafety(t *testing.T) {
	buf := NewLogBuffer(100)
	var wg sync.WaitGroup

	// Concurrent writers
	for w := 0; w < 10; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				buf.Add(makeEntry("INFO", fmt.Sprintf("writer-%d-msg-%d", id, i)))
			}
		}(w)
	}

	// Concurrent readers
	for r := 0; r < 5; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				entries, total := buf.Query(0, 50, "")
				// total should never exceed capacity
				if total > 100 {
					t.Errorf("total %d exceeds capacity 100", total)
				}
				// returned entries should never exceed requested limit
				if len(entries) > 50 {
					t.Errorf("got %d entries, limit was 50", len(entries))
				}
			}
		}()
	}

	wg.Wait()

	// After all writes, buffer should be at capacity (10 writers × 200 = 2000 > 100)
	_, total := buf.Query(0, 1, "")
	if total != 100 {
		t.Errorf("expected total=100 (full buffer), got %d", total)
	}
}
