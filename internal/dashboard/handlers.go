/*
Copyright 2026 Zelyo AI
*/

package dashboard

import (
	"encoding/json"
	"net/http"
	"strings"
)

func (s *Server) writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		s.log.Error(err, "Failed to encode JSON response")
	}
}

func (s *Server) writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": msg}); err != nil {
		s.log.Error(err, "Failed to encode error response")
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	s.writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	resp, err := s.fetchOverview(r.Context())
	if err != nil {
		s.log.Error(err, "Failed to fetch overview")
		s.writeError(w, http.StatusInternalServerError, "failed to fetch overview")
		return
	}
	s.writeJSON(w, resp)
}

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	resp, err := s.fetchPolicies(r.Context())
	if err != nil {
		s.log.Error(err, "Failed to fetch policies")
		s.writeError(w, http.StatusInternalServerError, "failed to fetch policies")
		return
	}
	s.writeJSON(w, resp)
}

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	resp, err := s.fetchScans(r.Context())
	if err != nil {
		s.log.Error(err, "Failed to fetch scans")
		s.writeError(w, http.StatusInternalServerError, "failed to fetch scans")
		return
	}
	s.writeJSON(w, resp)
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	// Handle /api/v1/reports/{name}
	prefix := "/api/v1/reports/"
	if s.basePath != "/" && s.basePath != "" {
		prefix = strings.TrimSuffix(s.basePath, "/") + "/api/v1/reports/"
	}
	name := strings.TrimPrefix(r.URL.Path, prefix)
	if name == "" {
		s.writeError(w, http.StatusBadRequest, "report name required")
		return
	}

	namespace := r.URL.Query().Get("namespace")
	if namespace == "" {
		namespace = "zelyo-system"
	}

	resp, err := s.fetchReport(r.Context(), namespace, name)
	if err != nil {
		s.log.Error(err, "Failed to fetch report", "name", name)
		s.writeError(w, http.StatusNotFound, "report not found")
		return
	}
	s.writeJSON(w, resp)
}

func (s *Server) handleScanReports(w http.ResponseWriter, r *http.Request) {
	// Handle /api/v1/scans/{name}/reports
	prefix := "/api/v1/scans/"
	if s.basePath != "/" && s.basePath != "" {
		prefix = strings.TrimSuffix(s.basePath, "/") + "/api/v1/scans/"
	}
	trimmed := strings.TrimPrefix(r.URL.Path, prefix)
	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		s.writeError(w, http.StatusBadRequest, "scan name required")
		return
	}
	scanName := parts[0]

	reports, err := s.fetchReportsForScan(r.Context(), scanName)
	if err != nil {
		s.log.Error(err, "Failed to fetch reports for scan", "scan", scanName)
		s.writeError(w, http.StatusInternalServerError, "failed to fetch reports")
		return
	}
	s.writeJSON(w, map[string]interface{}{"reports": reports, "scanRef": scanName})
}

func (s *Server) handleCloud(w http.ResponseWriter, r *http.Request) {
	resp, err := s.fetchCloud(r.Context())
	if err != nil {
		s.log.Error(err, "Failed to fetch cloud accounts")
		s.writeError(w, http.StatusInternalServerError, "failed to fetch cloud accounts")
		return
	}
	s.writeJSON(w, resp)
}

func (s *Server) handleCompliance(w http.ResponseWriter, r *http.Request) {
	resp, err := s.fetchCompliance(r.Context())
	if err != nil {
		s.log.Error(err, "Failed to fetch compliance data")
		s.writeError(w, http.StatusInternalServerError, "failed to fetch compliance data")
		return
	}
	s.writeJSON(w, resp)
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	resp, err := s.fetchSettings(r.Context())
	if err != nil {
		s.log.Error(err, "Failed to fetch settings")
		s.writeError(w, http.StatusInternalServerError, "failed to fetch settings")
		return
	}
	s.writeJSON(w, resp)
}
