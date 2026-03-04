/*
Copyright 2026 Zelyo AI.
*/

// Package dashboard provides a REST API and Server-Sent Events (SSE) endpoint
// for the Aotanami real-time dashboard.
package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-logr/logr"
)

// Server is the dashboard HTTP server.
type Server struct {
	mux      *http.ServeMux
	log      logr.Logger
	port     int
	basePath string

	mu          sync.RWMutex
	subscribers map[string]chan Event
}

// Event represents a server-sent event for real-time updates.
type Event struct {
	Type      string      `json:"type"`
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}

// ClusterOverview summarizes the cluster security posture.
type ClusterOverview struct {
	SecurityScore       int        `json:"security_score"`
	TotalPolicies       int        `json:"total_policies"`
	TotalViolations     int        `json:"total_violations"`
	CriticalViolations  int        `json:"critical_violations"`
	LastScanTime        *time.Time `json:"last_scan_time,omitempty"`
	ActiveIncidents     int        `json:"active_incidents"`
	CompliancePct       float64    `json:"compliance_pct"`
	CostSavingsEstimate string     `json:"cost_savings_estimate,omitempty"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// Config configures the dashboard server.
type Config struct {
	Port     int    `json:"port"`
	BasePath string `json:"base_path"`
	Enabled  bool   `json:"enabled"`
}

// NewServer creates a new dashboard server.
func NewServer(cfg *Config, log logr.Logger) *Server {
	s := &Server{
		mux:         http.NewServeMux(),
		log:         log,
		port:        cfg.Port,
		basePath:    cfg.BasePath,
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
	s.mux.HandleFunc(prefix+"/api/v1/health", s.handleHealth)
	s.mux.HandleFunc(prefix+"/api/v1/overview", s.handleOverview)
	s.mux.HandleFunc(prefix+"/api/v1/events", s.handleSSE)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
		s.log.Error(err, "Failed to encode health response")
	}
}

func (s *Server) handleOverview(w http.ResponseWriter, _ *http.Request) {
	overview := ClusterOverview{
		SecurityScore: 0,
		UpdatedAt:     time.Now(),
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(overview); err != nil {
		s.log.Error(err, "Failed to encode overview response")
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

	defer func() {
		s.mu.Lock()
		delete(s.subscribers, id)
		s.mu.Unlock()
		close(ch)
	}()

	for {
		select {
		case <-r.Context().Done():
			return
		case event := <-ch:
			data, _ := json.Marshal(event)
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

// Start starts the dashboard HTTP server.
func (s *Server) Start(ctx context.Context) error {
	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", s.port),
		Handler:           s.mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		if err := server.Shutdown(ctx); err != nil {
			s.log.Error(err, "Dashboard server shutdown error")
		}
	}()

	s.log.Info("Starting dashboard", "port", s.port, "basePath", s.basePath)
	return server.ListenAndServe()
}
