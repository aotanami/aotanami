/*
Copyright 2026 Zelyo AI
*/

// Package dashboard provides a REST API, Server-Sent Events (SSE) endpoint,
// and an embedded single-page dashboard for the Zelyo Operator.
package dashboard

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/zelyo-ai/zelyo-operator/internal/events"
)

//go:embed static
var staticFiles embed.FS

// Server is the dashboard HTTP server.
type Server struct {
	mux      *http.ServeMux
	log      logr.Logger
	port     int
	basePath string
	client   client.Client

	// startCtx is the long-lived server-lifecycle context set by Start().
	// Handlers that spawn background work (e.g. the demo PR synthesizer)
	// derive from it so goroutines observe server shutdown instead of
	// outliving the process into an inconsistent state.
	startCtxMu sync.RWMutex
	startCtx   context.Context

	mu          sync.RWMutex
	subscribers map[string]chan Event
}

// Event represents a server-sent event for real-time updates.
type Event struct {
	Type      string      `json:"type"`
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}

// Config configures the dashboard server.
type Config struct {
	Port     int    `json:"port"`
	BasePath string `json:"basePath"`
	Enabled  bool   `json:"enabled"`
}

// NewServer creates a new dashboard server.
func NewServer(cfg *Config, k8sClient client.Client, log logr.Logger) *Server {
	s := &Server{
		mux:         http.NewServeMux(),
		log:         log,
		port:        cfg.Port,
		basePath:    cfg.BasePath,
		client:      k8sClient,
		subscribers: make(map[string]chan Event),
	}
	s.registerRoutes()
	return s
}

func (s *Server) registerRoutes() {
	prefix := s.basePath
	if prefix == "/" {
		prefix = ""
	}

	// API routes.
	s.mux.HandleFunc(prefix+"/api/v1/health", s.handleHealth)
	s.mux.HandleFunc(prefix+"/api/v1/overview", s.handleOverview)
	s.mux.HandleFunc(prefix+"/api/v1/policies", s.handlePolicies)
	s.mux.HandleFunc(prefix+"/api/v1/scans", s.handleScans)
	s.mux.HandleFunc(prefix+"/api/v1/reports/", s.handleReport)
	s.mux.HandleFunc(prefix+"/api/v1/scans/", s.handleScanReports)
	s.mux.HandleFunc(prefix+"/api/v1/cloud", s.handleCloud)
	s.mux.HandleFunc(prefix+"/api/v1/compliance", s.handleCompliance)
	s.mux.HandleFunc(prefix+"/api/v1/settings", s.handleSettings)
	s.mux.HandleFunc(prefix+"/api/v1/events", s.handleSSE)
	s.mux.HandleFunc(prefix+"/api/v1/pipeline", s.handlePipeline)
	s.mux.HandleFunc(prefix+"/api/v1/remediations", s.handleRemediations)
	s.mux.HandleFunc(prefix+"/api/v1/explain", s.handleExplain)
	s.mux.HandleFunc(prefix+"/api/v1/presets", s.handlePresets)
	s.mux.HandleFunc(prefix+"/api/v1/presets/", s.dispatchPresetRoute)

	// Embedded static files.
	staticSub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		s.log.Error(err, "Failed to create sub-filesystem for static files")
		return
	}
	s.mux.Handle(prefix+"/static/", http.StripPrefix(prefix+"/static/", http.FileServer(http.FS(staticSub))))

	// SPA catch-all — serve index.html for any unmatched path.
	s.mux.HandleFunc(prefix+"/", s.handleSPA)
}

func (s *Server) handleSPA(w http.ResponseWriter, r *http.Request) {
	// Let /api and /static fall through to their handlers.
	indexHTML, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "dashboard not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	if _, err = w.Write(indexHTML); err != nil {
		s.log.Error(err, "Failed to write dashboard HTML")
	}
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	id := fmt.Sprintf("sub-%d", time.Now().UnixNano())
	ch := make(chan Event, 100)

	s.mu.Lock()
	s.subscribers[id] = ch
	s.mu.Unlock()

	// Do NOT close(ch) on cleanup: Broadcast reads the subscribers map under
	// RLock and sends with `select default`, so closing the channel outside
	// the map-mutation lock would race with an in-flight send and panic
	// with "send on closed channel". Deleting from the map under Lock is
	// sufficient — the channel is unreachable and GC'd once this handler
	// returns.
	defer func() {
		s.mu.Lock()
		delete(s.subscribers, id)
		s.mu.Unlock()
	}()

	for {
		select {
		case <-r.Context().Done():
			return
		case event := <-ch:
			data, err := json.Marshal(event)
			if err != nil {
				// Skip this event rather than emitting "data: null" which
				// poisons the stream for clients that parse strictly.
				s.log.V(1).Info("skipping SSE event with unmarshalable Data", "type", event.Type)
				continue
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event.Type, data)
			flusher.Flush()
		}
	}
}

// Broadcast sends an event to all SSE subscribers.
func (s *Server) Broadcast(event Event) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, ch := range s.subscribers {
		select {
		case ch <- event:
		default:
		}
	}
}

// Start starts the dashboard HTTP server and the heartbeat goroutine.
func (s *Server) Start(ctx context.Context) error {
	// Publish the shutdown-aware context so handlers that spawn background
	// goroutines (preset PR simulator, etc.) can observe cancellation.
	s.startCtxMu.Lock()
	s.startCtx = ctx
	s.startCtxMu.Unlock()

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", s.port),
		Handler:           s.mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Heartbeat: broadcast overview.refresh every 30 seconds.
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.Broadcast(Event{
					Type: "overview.refresh",
					Data: map[string]string{"trigger": "heartbeat"},
				})
			}
		}
	}()

	// Pipeline bridge: forward events from the in-process bus to SSE
	// subscribers. Runs until ctx is canceled.
	go s.bridgePipelineEvents(ctx)

	s.log.Info("Starting dashboard", "port", s.port, "basePath", s.basePath)

	// Run ListenAndServe in a goroutine so the returned error can be joined
	// with Shutdown completion: the manager treats Start's return as
	// "runnable stopped" and without the join Start returns before Shutdown
	// finishes draining in-flight handlers.
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.ListenAndServe()
	}()

	select {
	case err := <-serveErr:
		if err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			s.log.Error(err, "Dashboard server shutdown error")
		}
		// Drain ListenAndServe's return; a real startup failure (bind
		// error, cert load failure, ...) can race ctx.Done() and would
		// otherwise be silently discarded on this branch.
		if err := <-serveErr; err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	}
}

// NeedLeaderElection returns false so the dashboard runs on all replicas.
func (s *Server) NeedLeaderElection() bool { return false }

// backgroundContext returns the server-lifecycle context set by Start(),
// or a pre-canceled context when Start has not yet been called (test
// paths, direct handler invocations). Returning context.Background() there
// would silently re-introduce the exact long-lived-goroutine leak the
// startCtx plumbing is meant to close — so instead we return a canceled
// context and let sleepCtx-style goroutines bail out on their first check.
func (s *Server) backgroundContext() context.Context {
	s.startCtxMu.RLock()
	defer s.startCtxMu.RUnlock()
	if s.startCtx == nil {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx
	}
	return s.startCtx
}

// bridgePipelineEvents subscribes to the pipeline event bus and forwards each
// event to SSE subscribers tagged with its type (scan.started, finding.detected, ...).
func (s *Server) bridgePipelineEvents(ctx context.Context) {
	ch, cancel := events.Default().Subscribe()
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			s.Broadcast(Event{
				Type:      ev.Type,
				Data:      ev,
				Timestamp: ev.Timestamp,
			})
		}
	}
}
