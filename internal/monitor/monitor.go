/*
Copyright 2026 Zelyo AI
*/

// Package monitor provides real-time workload monitoring for Zelyo Operator. It watches
// for pod events, deployment rollouts, and resource changes, feeding observations
// into the anomaly detector and event correlator.
package monitor

import (
	"context"
	"time"

	"github.com/go-logr/logr"
)

// WatchEvent represents a Kubernetes resource change observed by the monitor.
type WatchEvent struct {
	// Type is the event type (Added, Modified, Deleted).
	Type EventType `json:"type"`

	// ResourceKind is the K8s resource type.
	ResourceKind string `json:"resource_kind"`

	// ResourceName is the resource name.
	ResourceName string `json:"resource_name"`

	// Namespace is the resource namespace.
	Namespace string `json:"namespace"`

	// Timestamp is when the event was observed.
	Timestamp time.Time `json:"timestamp"`

	// Details contains additional context about the change.
	Details map[string]string `json:"details,omitempty"`

	// PreviousState captures relevant previous state for comparison.
	PreviousState map[string]string `json:"previous_state,omitempty"`
}

// EventType classifies Kubernetes watch events.
type EventType string

// Enumeration values.
const (
	EventAdded    EventType = "ADDED"
	EventModified EventType = "MODIFIED"
	EventDeleted  EventType = "DELETED"
)

// Handler processes watch events.
type Handler interface {
	// OnEvent is called when a relevant resource change is detected.
	OnEvent(ctx context.Context, event *WatchEvent) error
}

// Config configures the monitor.
type Config struct {
	// Namespaces to watch (empty = all namespaces).
	Namespaces []string `json:"namespaces,omitempty"`

	// ExcludeNamespaces are namespaces to skip.
	ExcludeNamespaces []string `json:"exclude_namespaces,omitempty"`

	// ResourceKinds are the resource types to watch.
	ResourceKinds []string `json:"resource_kinds,omitempty"`

	// RescanInterval is how often to do a full rescan independent of watches.
	RescanInterval time.Duration `json:"rescan_interval,omitempty"`
}

// DefaultConfig returns production defaults.
func DefaultConfig() Config {
	return Config{
		ExcludeNamespaces: []string{"kube-system", "kube-public", "kube-node-lease"},
		ResourceKinds:     []string{"Pod", "Deployment", "StatefulSet", "DaemonSet", "CronJob"},
		RescanInterval:    5 * time.Minute,
	}
}

// Monitor watches Kubernetes resources and dispatches events to handlers.
type Monitor struct {
	config   Config
	handlers []Handler
	log      logr.Logger
}

// NewMonitor creates a new monitor.
func NewMonitor(cfg *Config, log logr.Logger) *Monitor {
	return &Monitor{
		config:   *cfg,
		handlers: make([]Handler, 0),
		log:      log,
	}
}

// AddHandler registers an event handler.
func (m *Monitor) AddHandler(h Handler) {
	m.handlers = append(m.handlers, h)
}

// Dispatch sends an event to all registered handlers.
func (m *Monitor) Dispatch(ctx context.Context, event *WatchEvent) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Check namespace filters.
	if !m.shouldWatch(event.Namespace) {
		return
	}

	for _, h := range m.handlers {
		if err := h.OnEvent(ctx, event); err != nil {
			m.log.Error(err, "Event handler failed",
				"handler", h,
				"event_type", event.Type,
				"resource", event.ResourceName)
		}
	}
}

func (m *Monitor) shouldWatch(namespace string) bool {
	// Check exclude list.
	for _, ns := range m.config.ExcludeNamespaces {
		if ns == namespace {
			return false
		}
	}

	// If include list is empty, watch all namespaces.
	if len(m.config.Namespaces) == 0 {
		return true
	}

	// Check include list.
	for _, ns := range m.config.Namespaces {
		if ns == namespace {
			return true
		}
	}

	return false
}
