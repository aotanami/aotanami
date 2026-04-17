/*
Copyright 2026 Zelyo AI
*/

package dashboard

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/zelyo-ai/zelyo-operator/internal/events"
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

// handlePipeline returns the ring-buffer of recent pipeline events.
// Query params: limit (default 200), stage (optional: scan|correlate|fix|verify).
func (s *Server) handlePipeline(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	stage := events.Stage(r.URL.Query().Get("stage"))
	recent := events.Default().Recent(stage, limit)

	// Reverse so oldest-first is cheap for the UI to append without sorting.
	for i, j := 0, len(recent)-1; i < j; i, j = i+1, j-1 {
		recent[i], recent[j] = recent[j], recent[i]
	}

	counts := map[events.Stage]int{}
	all := events.Default().Recent("", 1000)
	for i := range all {
		counts[all[i].Stage]++
	}

	s.writeJSON(w, map[string]interface{}{
		"events": recent,
		"counts": map[string]int{
			"scan":      counts[events.StageScan],
			"correlate": counts[events.StageCorrelate],
			"fix":       counts[events.StageFix],
			"verify":    counts[events.StageVerify],
		},
	})
}

// handleRemediations returns either a single remediation context (when
// `url` is provided) or a list of recent remediations. This backs the
// Pipeline page's Before/Diff/After side panel.
func (s *Server) handleRemediations(w http.ResponseWriter, r *http.Request) {
	store := events.DefaultRemediationStore()

	if u := r.URL.Query().Get("url"); u != "" {
		ctx := store.Get(u)
		if ctx == nil {
			s.writeError(w, http.StatusNotFound, "remediation not found")
			return
		}
		s.writeJSON(w, ctx)
		return
	}

	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	s.writeJSON(w, map[string]interface{}{
		"remediations": store.List(limit),
	})
}

// handleExplain returns a plain-English explanation for a security finding.
// Accepts POST with a JSON body (preferred) or GET with query params.
func (s *Server) handleExplain(w http.ResponseWriter, r *http.Request) {
	req := &ExplainRequest{}
	switch r.Method {
	case http.MethodPost:
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
	case http.MethodGet:
		q := r.URL.Query()
		req.Rule = q.Get("rule")
		req.Severity = q.Get("severity")
		req.Resource = q.Get("resource")
		req.Title = q.Get("title")
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if req.Rule == "" {
		s.writeError(w, http.StatusBadRequest, "rule is required")
		return
	}

	resp, err := getExplainer().Explain(r.Context(), req)
	if err != nil {
		s.log.Error(err, "Failed to generate explanation", "rule", req.Rule)
		s.writeError(w, http.StatusInternalServerError, "failed to generate explanation")
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
