package natsrpc

import (
	"context"
	json "github.com/json-iterator/go"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
)

// HandlerFunc processes an RPC request. method is the extracted suffix from the
// NATS subject (e.g. "httpx", "nuclei-retest"). data is the raw JSON body of
// the NATS message. Return value is marshalled into Response.Data on success.
type HandlerFunc func(ctx context.Context, method string, data []byte) (any, error)

// Router dispatches NATS messages to registered handlers based on the method
// name extracted from the subject suffix. The lifecycle context is propagated
// to all handlers so they can be cancelled on agent shutdown.
type Router struct {
	ctx      context.Context
	mu       sync.RWMutex
	handlers map[string]HandlerFunc
}

// NewRouter creates a Router with a lifecycle context. When ctx is cancelled,
// in-flight handlers receive cancellation and should exit promptly.
func NewRouter(ctx context.Context) *Router {
	return &Router{
		ctx:      ctx,
		handlers: make(map[string]HandlerFunc),
	}
}

// Handle registers a handler for the given method name.
// Method names are case-sensitive and must not contain dots.
func (r *Router) Handle(method string, fn HandlerFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handlers[method] = fn
}

// lookup returns the handler for method, or nil.
func (r *Router) lookup(method string) HandlerFunc {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.handlers[method]
}

// SubscribeRequests subscribes to subjectPrefix.> using QueueSubscribe so that
// only one agent in the queue group handles each request.
func (r *Router) SubscribeRequests(nc *nats.Conn, subjectPrefix, queueGroup string) (*nats.Subscription, error) {
	subject := subjectPrefix + ".>"
	return nc.QueueSubscribe(subject, queueGroup, func(msg *nats.Msg) {
		r.dispatch(msg, subjectPrefix)
	})
}

// SubscribeBroadcast subscribes to subjectPrefix.> using a plain Subscribe
// (NOT QueueSubscribe) so that every agent receives every message. This is
// intentional — broadcast messages like health-check need all agents to respond.
func (r *Router) SubscribeBroadcast(nc *nats.Conn, subjectPrefix string) (*nats.Subscription, error) {
	subject := subjectPrefix + ".>"
	return nc.Subscribe(subject, func(msg *nats.Msg) {
		r.dispatch(msg, subjectPrefix)
	})
}

// SubscribeDirect subscribes to subjectPrefix.> for a single agent using a
// plain Subscribe. The subject prefix includes the agent ID
// (e.g., groupPrefix.direct.<agentID>), so only this agent receives messages.
// Kept as a separate method from SubscribeBroadcast for call-site readability.
func (r *Router) SubscribeDirect(nc *nats.Conn, subjectPrefix string) (*nats.Subscription, error) {
	subject := subjectPrefix + ".>"
	return nc.Subscribe(subject, func(msg *nats.Msg) {
		r.dispatch(msg, subjectPrefix)
	})
}

// dispatch extracts the method from the subject suffix and calls the matching handler.
func (r *Router) dispatch(msg *nats.Msg, subjectPrefix string) {
	method := extractMethod(msg.Subject, subjectPrefix)
	if method == "" {
		r.respond(msg, Response{
			Status: "error",
			Error:  fmt.Sprintf("could not extract method from subject: %s", msg.Subject),
		})
		return
	}

	fn := r.lookup(method)
	if fn == nil {
		r.respond(msg, Response{
			Status: "error",
			Error:  fmt.Sprintf("unknown method: %s", method),
		})
		return
	}

	slog.Info("NATS RPC: request received", "method", method, "subject", msg.Subject)

	start := time.Now()
	result, err := fn(r.ctx, method, msg.Data)
	duration := time.Since(start)

	if err != nil {
		slog.Warn("NATS RPC: request failed", "method", method, "duration", duration, "error", err)
		r.respond(msg, Response{
			Status: "error",
			Error:  err.Error(),
		})
		return
	}

	data, err := json.Marshal(result)
	if err != nil {
		r.respond(msg, Response{
			Status: "error",
			Error:  fmt.Sprintf("failed to marshal response: %v", err),
		})
		return
	}

	slog.Info("NATS RPC: request completed", "method", method, "duration", duration)
	r.respond(msg, Response{
		Status: "ok",
		Data:   data,
	})
}

// respond marshals resp as JSON and sends it via msg.Respond.
// If the message has no reply subject (e.g. broadcast), respond is a no-op.
func (r *Router) respond(msg *nats.Msg, resp Response) {
	if msg.Reply == "" {
		return
	}

	data, err := json.Marshal(resp)
	if err != nil {
		slog.Error("natsrpc: failed to marshal response", "error", err)
		return
	}

	if err := msg.Respond(data); err != nil {
		slog.Error("natsrpc: failed to send response", "error", err)
	}
}

// extractMethod returns the portion of subject after subjectPrefix + ".".
// For example, subject "ws-123.scanners.requests.httpx" with prefix
// "ws-123.scanners.requests" returns "httpx".
// For nested methods like "ws-123.scanners.requests.nuclei.retest", it returns
// "nuclei.retest".
func extractMethod(subject, subjectPrefix string) string {
	if !strings.HasPrefix(subject, subjectPrefix+".") {
		return ""
	}
	method := subject[len(subjectPrefix)+1:]
	if method == "" || method == ">" {
		return ""
	}
	return method
}
