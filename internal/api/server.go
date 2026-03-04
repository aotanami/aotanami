/*
Copyright 2026 Zelyo AI.
*/

// Package api provides the public REST API for external integrations with Aotanami.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-logr/logr"
)

// Server is the public API server.
type Server struct {
	mux  *http.ServeMux
	log  logr.Logger
	port int
}

// Config configures the API server.
type Config struct {
	Port    int  `json:"port"`
	Enabled bool `json:"enabled"`
}

// Response is a standard API response wrapper.
type Response struct {
	Status   string            `json:"status"`
	Data     interface{}       `json:"data,omitempty"`
	Error    string            `json:"error,omitempty"`
	Metadata *ResponseMetadata `json:"metadata,omitempty"`
}

// ResponseMetadata holds API response metadata.
type ResponseMetadata struct {
	Total      int       `json:"total,omitempty"`
	Page       int       `json:"page,omitempty"`
	PerPage    int       `json:"per_page,omitempty"`
	APIVersion string    `json:"api_version"`
	Timestamp  time.Time `json:"timestamp"`
}

// NewServer creates a new API server.
func NewServer(cfg *Config, log logr.Logger) *Server {
	s := &Server{
		mux:  http.NewServeMux(),
		log:  log,
		port: cfg.Port,
	}
	s.registerRoutes()
	return s
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("/api/v1/health", s.handleHealth)
	s.mux.HandleFunc("/api/v1/version", s.handleVersion)
	s.mux.HandleFunc("/api/v1/policies", s.handlePolicies)
	s.mux.HandleFunc("/api/v1/scans", s.handleScans)
	s.mux.HandleFunc("/api/v1/incidents", s.handleIncidents)
	s.mux.HandleFunc("/api/v1/compliance", s.handleCompliance)
	s.mux.HandleFunc("/api/v1/webhooks/github", s.handleGitHubWebhook)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, Response{
		Status:   "ok",
		Metadata: &ResponseMetadata{APIVersion: "v1", Timestamp: time.Now()},
	})
}

func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, Response{
		Status: "ok",
		Data:   map[string]string{"name": "Aotanami", "version": "0.1.0"},
	})
}

func (s *Server) handlePolicies(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, Response{
		Status:   "ok",
		Data:     []interface{}{},
		Metadata: &ResponseMetadata{APIVersion: "v1", Timestamp: time.Now(), Total: 0},
	})
}

func (s *Server) handleScans(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, Response{
		Status:   "ok",
		Data:     []interface{}{},
		Metadata: &ResponseMetadata{APIVersion: "v1", Timestamp: time.Now(), Total: 0},
	})
}

func (s *Server) handleIncidents(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, Response{
		Status:   "ok",
		Data:     []interface{}{},
		Metadata: &ResponseMetadata{APIVersion: "v1", Timestamp: time.Now(), Total: 0},
	})
}

func (s *Server) handleCompliance(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, http.StatusOK, Response{
		Status:   "ok",
		Data:     []interface{}{},
		Metadata: &ResponseMetadata{APIVersion: "v1", Timestamp: time.Now(), Total: 0},
	})
}

func (s *Server) handleGitHubWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeJSON(w, http.StatusMethodNotAllowed, Response{Status: "error", Error: "method not allowed"})
		return
	}
	s.writeJSON(w, http.StatusOK, Response{Status: "ok"})
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, resp Response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.log.Error(err, "Failed to encode JSON response")
	}
}

// Start starts the API server.
func (s *Server) Start(ctx context.Context) error {
	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", s.port),
		Handler:           s.mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		if err := server.Shutdown(ctx); err != nil {
			s.log.Error(err, "API server shutdown error")
		}
	}()

	s.log.Info("Starting API server", "port", s.port)
	return server.ListenAndServe()
}
