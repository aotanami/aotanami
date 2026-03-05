/*
Copyright 2026 Zelyo AI
*/

package correlator

import (
	"testing"
	"time"
)

func TestEngine_IngestCreatesIncident(t *testing.T) {
	engine := NewEngine(&Config{
		CorrelationWindow: 5 * time.Minute,
	})

	// First event alone doesn't create an incident.
	incident := engine.Ingest(&Event{
		Type:      EventSecurityViolation,
		Severity:  "high",
		Namespace: "default",
		Resource:  "nginx",
		Message:   "Privileged container",
	})
	if incident != nil {
		t.Fatal("Expected no incident from single event")
	}

	// Second event for the same resource should create a correlated incident.
	incident = engine.Ingest(&Event{
		Type:      EventAnomaly,
		Severity:  "medium",
		Namespace: "default",
		Resource:  "nginx",
		Message:   "Restart spike",
	})
	if incident == nil {
		t.Fatal("Expected incident from two correlated events")
	}
	if len(incident.Events) < 2 {
		t.Errorf("Expected at least 2 events in incident, got %d", len(incident.Events))
	}
	if incident.Severity != "high" {
		t.Errorf("Expected highest severity 'high', got %q", incident.Severity)
	}
	if incident.Namespace != "default" {
		t.Errorf("Expected namespace 'default', got %q", incident.Namespace)
	}
}

func TestEngine_SeverityEscalation(t *testing.T) {
	engine := NewEngine(&Config{
		CorrelationWindow: 5 * time.Minute,
	})

	// Create an incident with medium severity.
	engine.Ingest(&Event{
		Type: EventAnomaly, Severity: "medium",
		Namespace: "prod", Resource: "api",
	})
	incident := engine.Ingest(&Event{
		Type: EventPodCrash, Severity: "medium",
		Namespace: "prod", Resource: "api",
	})
	if incident == nil {
		t.Fatal("Expected incident")
	}
	if incident.Severity != "medium" {
		t.Fatalf("Expected medium, got %q", incident.Severity)
	}

	// Add a critical event — severity should escalate.
	incident = engine.Ingest(&Event{
		Type: EventSecurityViolation, Severity: "critical",
		Namespace: "prod", Resource: "api",
	})
	if incident == nil {
		t.Fatal("Expected incident update")
	}
	if incident.Severity != "critical" {
		t.Errorf("Expected escalation to critical, got %q", incident.Severity)
	}
}

func TestEngine_DifferentResourcesNotCorrelated(t *testing.T) {
	engine := NewEngine(&Config{
		CorrelationWindow: 5 * time.Minute,
	})

	engine.Ingest(&Event{
		Type: EventSecurityViolation, Severity: "high",
		Namespace: "default", Resource: "nginx",
	})
	incident := engine.Ingest(&Event{
		Type: EventAnomaly, Severity: "medium",
		Namespace: "default", Resource: "redis", // Different resource.
	})
	if incident != nil {
		t.Error("Expected no correlation between different resources")
	}
}

func TestEngine_GetOpenIncidents(t *testing.T) {
	engine := NewEngine(&Config{
		CorrelationWindow: 5 * time.Minute,
	})

	// Create an incident.
	engine.Ingest(&Event{
		Type: EventSecurityViolation, Severity: "high",
		Namespace: "default", Resource: "app",
	})
	engine.Ingest(&Event{
		Type: EventAnomaly, Severity: "medium",
		Namespace: "default", Resource: "app",
	})

	open := engine.GetOpenIncidents()
	if len(open) != 1 {
		t.Fatalf("Expected 1 open incident, got %d", len(open))
	}
	if open[0].Resolved {
		t.Error("Expected incident to be unresolved")
	}
}

func TestEngine_ResolveIncident(t *testing.T) {
	engine := NewEngine(&Config{
		CorrelationWindow: 5 * time.Minute,
	})

	engine.Ingest(&Event{
		Type: EventSecurityViolation, Severity: "high",
		Namespace: "default", Resource: "db",
	})
	incident := engine.Ingest(&Event{
		Type: EventAnomaly, Severity: "medium",
		Namespace: "default", Resource: "db",
	})
	if incident == nil {
		t.Fatal("Expected incident")
	}

	engine.ResolveIncident(incident.ID)

	open := engine.GetOpenIncidents()
	if len(open) != 0 {
		t.Errorf("Expected 0 open incidents after resolve, got %d", len(open))
	}
}

func TestEngine_IncidentIDFormat(t *testing.T) {
	engine := NewEngine(&Config{
		CorrelationWindow: 5 * time.Minute,
	})

	engine.Ingest(&Event{
		Type: EventSecurityViolation, Severity: "high",
		Namespace: "ns1", Resource: "svc1",
	})
	incident := engine.Ingest(&Event{
		Type: EventAnomaly, Severity: "medium",
		Namespace: "ns1", Resource: "svc1",
	})
	if incident == nil {
		t.Fatal("Expected incident")
	}
	if incident.ID != "INC-000001" {
		t.Errorf("Expected INC-000001, got %q", incident.ID)
	}
}

func TestSeverityOrder(t *testing.T) {
	tests := []struct {
		severity string
		expected int
	}{
		{"critical", 5},
		{"high", 4},
		{"medium", 3},
		{"low", 2},
		{"info", 1},
		{"unknown", 1},
	}

	for _, tt := range tests {
		if got := severityOrder(tt.severity); got != tt.expected {
			t.Errorf("severityOrder(%q) = %d, want %d", tt.severity, got, tt.expected)
		}
	}
}

func TestHighestSeverity(t *testing.T) {
	events := []*Event{
		{Severity: "low"},
		{Severity: "critical"},
		{Severity: "medium"},
	}
	if s := highestSeverity(events); s != "critical" {
		t.Errorf("Expected critical, got %q", s)
	}
}
