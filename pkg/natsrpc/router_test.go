package natsrpc

import (
	"context"
	stdjson "encoding/json"
	"fmt"
	json "github.com/json-iterator/go"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// startTestServer spins up an in-process NATS server for testing.
func startTestServer(t *testing.T) *server.Server {
	t.Helper()
	opts := &server.Options{
		Host: "127.0.0.1",
		Port: -1, // random port
	}
	ns, err := server.NewServer(opts)
	if err != nil {
		t.Fatalf("failed to create test NATS server: %v", err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS server not ready")
	}
	return ns
}

func connect(t *testing.T, ns *server.Server) *nats.Conn {
	t.Helper()
	nc, err := nats.Connect(ns.ClientURL())
	if err != nil {
		t.Fatalf("failed to connect to NATS: %v", err)
	}
	return nc
}

// --- extractMethod unit tests ---

func TestExtractMethod(t *testing.T) {
	tests := []struct {
		name     string
		subject  string
		prefix   string
		expected string
	}{
		{
			name:     "simple method",
			subject:  "ws-123.scanners.requests.httpx",
			prefix:   "ws-123.scanners.requests",
			expected: "httpx",
		},
		{
			name:     "hyphenated method",
			subject:  "ws-123.scanners.requests.nuclei-retest",
			prefix:   "ws-123.scanners.requests",
			expected: "nuclei-retest",
		},
		{
			name:     "nested method",
			subject:  "ws-123.scanners.requests.nuclei.retest",
			prefix:   "ws-123.scanners.requests",
			expected: "nuclei.retest",
		},
		{
			name:     "broadcast method",
			subject:  "ws-123.scanners.broadcast.health-check",
			prefix:   "ws-123.scanners.broadcast",
			expected: "health-check",
		},
		{
			name:     "no match - different prefix",
			subject:  "other.prefix.httpx",
			prefix:   "ws-123.scanners.requests",
			expected: "",
		},
		{
			name:     "no match - exact prefix without method",
			subject:  "ws-123.scanners.requests",
			prefix:   "ws-123.scanners.requests",
			expected: "",
		},
		{
			name:     "no match - wildcard only",
			subject:  "ws-123.scanners.requests.>",
			prefix:   "ws-123.scanners.requests",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractMethod(tt.subject, tt.prefix)
			if got != tt.expected {
				t.Errorf("extractMethod(%q, %q) = %q, want %q", tt.subject, tt.prefix, got, tt.expected)
			}
		})
	}
}

// --- Router handler registration ---

func TestRouterHandle(t *testing.T) {
	r := NewRouter(context.Background())
	called := false
	r.Handle("test", func(ctx context.Context, method string, data []byte) (any, error) {
		called = true
		return nil, nil
	})

	fn := r.lookup("test")
	if fn == nil {
		t.Fatal("expected handler to be registered")
	}

	_, _ = fn(context.Background(), "test", nil)
	if !called {
		t.Fatal("handler was not called")
	}

	if r.lookup("nonexistent") != nil {
		t.Fatal("expected nil for unregistered method")
	}
}

// --- Integration tests with embedded NATS server ---

func TestSubscribeRequests_Dispatch(t *testing.T) {
	ns := startTestServer(t)
	defer ns.Shutdown()

	nc := connect(t, ns)
	defer nc.Close()

	router := NewRouter(context.Background())
	router.Handle("httpx", func(ctx context.Context, method string, data []byte) (any, error) {
		var req HTTPXRequest
		if err := json.Unmarshal(data, &req); err != nil {
			return nil, err
		}
		return map[string]any{
			"target": req.Target,
			"status": "received",
		}, nil
	})

	prefix := "ws-test.scanners.requests"
	sub, err := router.SubscribeRequests(nc, prefix, "test-group")
	if err != nil {
		t.Fatalf("SubscribeRequests failed: %v", err)
	}
	defer func() { _ = sub.Unsubscribe() }()
	nc.Flush()

	// Send a request
	reqData, _ := json.Marshal(HTTPXRequest{
		Target: "example.com",
	})

	msg, err := nc.Request(prefix+".httpx", reqData, 2*time.Second)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	var resp Response
	if err := json.Unmarshal(msg.Data, &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.Status != "ok" {
		t.Fatalf("expected status ok, got %s (error: %s)", resp.Status, resp.Error)
	}

	var result map[string]any
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		t.Fatalf("failed to unmarshal data: %v", err)
	}

	target, ok := result["target"].(string)
	if !ok || target != "example.com" {
		t.Fatalf("unexpected target: %v", result["target"])
	}
}

func TestSubscribeRequests_UnknownMethod(t *testing.T) {
	ns := startTestServer(t)
	defer ns.Shutdown()

	nc := connect(t, ns)
	defer nc.Close()

	router := NewRouter(context.Background())
	prefix := "ws-test.scanners.requests"
	sub, err := router.SubscribeRequests(nc, prefix, "test-group")
	if err != nil {
		t.Fatalf("SubscribeRequests failed: %v", err)
	}
	defer func() { _ = sub.Unsubscribe() }()
	nc.Flush()

	msg, err := nc.Request(prefix+".unknown-tool", nil, 2*time.Second)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	var resp Response
	if err := json.Unmarshal(msg.Data, &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.Status != "error" {
		t.Fatalf("expected status error, got %s", resp.Status)
	}

	if resp.Error != "unknown method: unknown-tool" {
		t.Fatalf("unexpected error message: %s", resp.Error)
	}
}

func TestSubscribeRequests_HandlerError(t *testing.T) {
	ns := startTestServer(t)
	defer ns.Shutdown()

	nc := connect(t, ns)
	defer nc.Close()

	router := NewRouter(context.Background())
	router.Handle("fail", func(ctx context.Context, method string, data []byte) (any, error) {
		return nil, fmt.Errorf("intentional failure")
	})

	prefix := "ws-test.scanners.requests"
	sub, err := router.SubscribeRequests(nc, prefix, "test-group")
	if err != nil {
		t.Fatalf("SubscribeRequests failed: %v", err)
	}
	defer func() { _ = sub.Unsubscribe() }()
	nc.Flush()

	msg, err := nc.Request(prefix+".fail", nil, 2*time.Second)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	var resp Response
	if err := json.Unmarshal(msg.Data, &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.Status != "error" {
		t.Fatalf("expected error status, got %s", resp.Status)
	}
	if resp.Error != "intentional failure" {
		t.Fatalf("unexpected error: %s", resp.Error)
	}
}

func TestSubscribeBroadcast_AllReceive(t *testing.T) {
	ns := startTestServer(t)
	defer ns.Shutdown()

	prefix := "ws-test.scanners.broadcast"
	const numAgents = 3

	type result struct {
		agentID string
	}
	results := make(chan result, numAgents)

	conns := make([]*nats.Conn, numAgents)
	subs := make([]*nats.Subscription, numAgents)

	for i := 0; i < numAgents; i++ {
		nc := connect(t, ns)
		conns[i] = nc

		agentID := fmt.Sprintf("agent-%d", i)
		router := NewRouter(context.Background())
		router.Handle("health-check", func(ctx context.Context, method string, data []byte) (any, error) {
			results <- result{agentID: agentID}
			return HealthCheckData{AgentID: agentID, Version: "test"}, nil
		})

		sub, err := router.SubscribeBroadcast(nc, prefix)
		if err != nil {
			t.Fatalf("SubscribeBroadcast failed for agent %d: %v", i, err)
		}
		subs[i] = sub
		nc.Flush()
	}

	defer func() {
		for i := 0; i < numAgents; i++ {
			_ = subs[i].Unsubscribe()
			conns[i].Close()
		}
	}()

	// Publish broadcast (no reply expected since it's a publish, not request)
	publisher := connect(t, ns)
	defer publisher.Close()

	if err := publisher.Publish(prefix+".health-check", nil); err != nil {
		t.Fatalf("publish failed: %v", err)
	}
	publisher.Flush()

	// Collect results - all agents should receive the broadcast
	seen := make(map[string]bool)
	timeout := time.After(3 * time.Second)
	for i := 0; i < numAgents; i++ {
		select {
		case r := <-results:
			seen[r.agentID] = true
		case <-timeout:
			t.Fatalf("timeout waiting for broadcast responses, got %d/%d", len(seen), numAgents)
		}
	}

	if len(seen) != numAgents {
		t.Fatalf("expected %d unique agents, got %d", numAgents, len(seen))
	}
}

func TestSubscribeRequests_QueueGroupLoadBalancing(t *testing.T) {
	ns := startTestServer(t)
	defer ns.Shutdown()

	prefix := "ws-test.scanners.requests"
	queueGroup := "scanners"
	const numAgents = 3
	const numRequests = 30

	counts := make(chan string, numRequests)

	conns := make([]*nats.Conn, numAgents)
	subs := make([]*nats.Subscription, numAgents)

	for i := 0; i < numAgents; i++ {
		nc := connect(t, ns)
		conns[i] = nc

		agentID := fmt.Sprintf("agent-%d", i)
		router := NewRouter(context.Background())
		router.Handle("httpx", func(ctx context.Context, method string, data []byte) (any, error) {
			counts <- agentID
			return map[string]string{"agent": agentID}, nil
		})

		sub, err := router.SubscribeRequests(nc, prefix, queueGroup)
		if err != nil {
			t.Fatalf("SubscribeRequests failed for agent %d: %v", i, err)
		}
		subs[i] = sub
		nc.Flush()
	}

	defer func() {
		for i := 0; i < numAgents; i++ {
			_ = subs[i].Unsubscribe()
			conns[i].Close()
		}
	}()

	requester := connect(t, ns)
	defer requester.Close()

	// Send requests and verify each gets exactly one response
	for i := 0; i < numRequests; i++ {
		msg, err := requester.Request(prefix+".httpx", nil, 2*time.Second)
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		var resp Response
		if err := json.Unmarshal(msg.Data, &resp); err != nil {
			t.Fatalf("failed to unmarshal response for request %d: %v", i, err)
		}
		if resp.Status != "ok" {
			t.Fatalf("request %d got error: %s", i, resp.Error)
		}
	}

	close(counts)
	agentCounts := make(map[string]int)
	for id := range counts {
		agentCounts[id]++
	}

	// Each agent should handle at least 1 request (NATS distributes across queue group)
	if len(agentCounts) < 2 {
		t.Logf("warning: load balancing sent all requests to %d agent(s): %v", len(agentCounts), agentCounts)
	}

	total := 0
	for _, c := range agentCounts {
		total += c
	}
	if total != numRequests {
		t.Fatalf("expected %d total handled requests, got %d", numRequests, total)
	}
}

func TestResponseEnvelope_JSON(t *testing.T) {
	tests := []struct {
		name     string
		resp     Response
		expected string
	}{
		{
			name: "ok response with data",
			resp: Response{
				Status: "ok",
				Data:   stdjson.RawMessage(`{"key":"value"}`),
			},
			expected: `{"status":"ok","data":{"key":"value"}}`,
		},
		{
			name: "error response",
			resp: Response{
				Status: "error",
				Error:  "something broke",
			},
			expected: `{"status":"error","error":"something broke"}`,
		},
		{
			name: "ok with no data",
			resp: Response{
				Status: "ok",
			},
			expected: `{"status":"ok"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.resp)
			if err != nil {
				t.Fatalf("marshal failed: %v", err)
			}
			if string(data) != tt.expected {
				t.Errorf("got %s, want %s", string(data), tt.expected)
			}
		})
	}
}
