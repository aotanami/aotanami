/*
Copyright 2026 Zelyo AI
*/

// Package correlator provides cross-signal event correlation for Zelyo Operator.
// It links security events, pod crashes, anomalies, and deployments into
// unified incidents for holistic threat assessment.
package correlator

import (
	"fmt"
	"sync"
	"time"
)

// EventType classifies events for correlation.
type EventType string

// Enumeration of event types for correlation.
const (
	EventSecurityViolation EventType = "security_violation"
	EventPodCrash          EventType = "pod_crash"
	EventAnomaly           EventType = "anomaly"
	EventDeployment        EventType = "deployment"
	EventConfigChange      EventType = "config_change"
	EventNetworkAnomaly    EventType = "network_anomaly"
)

// Event represents a single observable event in the cluster.
type Event struct {
	Type         EventType         `json:"type"`
	Source       string            `json:"source"`
	Severity     string            `json:"severity"`
	Namespace    string            `json:"namespace"`
	Resource     string            `json:"resource"`
	ResourceKind string            `json:"resource_kind"`
	Message      string            `json:"message"`
	Timestamp    time.Time         `json:"timestamp"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// Incident represents a correlated group of events.
type Incident struct {
	ID        string    `json:"id"`
	Severity  string    `json:"severity"`
	Title     string    `json:"title"`
	Events    []*Event  `json:"events"`
	Namespace string    `json:"namespace"`
	Resource  string    `json:"resource"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Resolved  bool      `json:"resolved"`
}

// Engine correlates events into incidents.
type Engine struct {
	mu          sync.Mutex
	events      []*Event
	incidents   map[string]*Incident
	window      time.Duration
	incidentSeq int
	onIncident  func(*Incident)
}

// Config configures the correlator.
type Config struct {
	CorrelationWindow time.Duration   `json:"correlation_window"`
	OnIncident        func(*Incident) `json:"-"`
}

// NewEngine creates a new correlation engine.
func NewEngine(cfg *Config) *Engine {
	window := cfg.CorrelationWindow
	if window == 0 {
		window = 5 * time.Minute
	}
	return &Engine{
		events:     make([]*Event, 0, 1000),
		incidents:  make(map[string]*Incident),
		window:     window,
		onIncident: cfg.OnIncident,
	}
}

// Ingest adds an event and attempts to correlate it.
func (e *Engine) Ingest(event *Event) *Incident {
	e.mu.Lock()
	defer e.mu.Unlock()

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	e.events = append(e.events, event)
	e.pruneOldEvents()

	for id, incident := range e.incidents {
		if incident.Resolved {
			continue
		}
		if e.correlates(event, incident) {
			incident.Events = append(incident.Events, event)
			incident.UpdatedAt = time.Now()
			if severityOrder(event.Severity) > severityOrder(incident.Severity) {
				incident.Severity = event.Severity
			}
			if e.onIncident != nil {
				e.onIncident(incident)
			}
			return e.incidents[id]
		}
	}

	related := e.findRelated(event)
	if len(related) >= 2 {
		e.incidentSeq++
		incident := &Incident{
			ID:        fmt.Sprintf("INC-%06d", e.incidentSeq),
			Severity:  highestSeverity(related),
			Title:     fmt.Sprintf("Correlated incident on %s/%s", event.Namespace, event.Resource),
			Events:    related,
			Namespace: event.Namespace,
			Resource:  event.Resource,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		e.incidents[incident.ID] = incident
		if e.onIncident != nil {
			e.onIncident(incident)
		}
		return incident
	}

	return nil
}

// GetOpenIncidents returns all unresolved incidents.
func (e *Engine) GetOpenIncidents() []*Incident {
	e.mu.Lock()
	defer e.mu.Unlock()

	result := make([]*Incident, 0)
	for _, inc := range e.incidents {
		if !inc.Resolved {
			result = append(result, inc)
		}
	}
	return result
}

// ResolveIncident marks an incident as resolved.
func (e *Engine) ResolveIncident(id string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if inc, ok := e.incidents[id]; ok {
		inc.Resolved = true
		inc.UpdatedAt = time.Now()
	}
}

func (e *Engine) correlates(event *Event, incident *Incident) bool {
	if event.Namespace != incident.Namespace || event.Resource != incident.Resource {
		return false
	}
	return time.Since(incident.UpdatedAt) < e.window
}

func (e *Engine) findRelated(event *Event) []*Event {
	cutoff := time.Now().Add(-e.window)
	related := make([]*Event, 0)
	for _, ev := range e.events {
		if ev.Timestamp.Before(cutoff) {
			continue
		}
		if ev.Namespace == event.Namespace && ev.Resource == event.Resource {
			related = append(related, ev)
		}
	}
	return related
}

func (e *Engine) pruneOldEvents() {
	cutoff := time.Now().Add(-e.window * 10)
	pruned := make([]*Event, 0, len(e.events))
	for _, ev := range e.events {
		if ev.Timestamp.After(cutoff) {
			pruned = append(pruned, ev)
		}
	}
	e.events = pruned
}

func severityOrder(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}

func highestSeverity(events []*Event) string {
	highest := "info"
	for _, ev := range events {
		if severityOrder(ev.Severity) > severityOrder(highest) {
			highest = ev.Severity
		}
	}
	return highest
}
