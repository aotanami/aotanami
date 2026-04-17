/*
Copyright 2026 Zelyo AI

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package events provides a lightweight in-process event bus used by
// controllers to publish pipeline telemetry (scan started, finding detected,
// remediation drafted, PR merged, ...) to the dashboard's live Pipeline view.
//
// The bus is intentionally in-process and best-effort: subscribers with full
// channels drop events silently, and no persistence is offered. This suits the
// dashboard use case (a visual feed of recent activity) without introducing a
// hard dependency on controllers completing their reconcile path.
package events

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Stage names the four pipeline stages rendered by the dashboard.
type Stage string

// Stage values for the four pipeline stages.
const (
	StageScan      Stage = "scan"
	StageCorrelate Stage = "correlate"
	StageFix       Stage = "fix"
	StageVerify    Stage = "verify"
)

// Level categorizes the visual treatment of an event.
type Level string

// Level values for event severity styling.
const (
	LevelInfo    Level = "info"
	LevelSuccess Level = "success"
	LevelWarning Level = "warning"
	LevelError   Level = "error"
)

// Event is a single pipeline activity record. It is serialized as-is to the
// dashboard over JSON/SSE, so field names are stable API surface.
type Event struct {
	ID        string            `json:"id"`
	Type      string            `json:"type"`
	Stage     Stage             `json:"stage"`
	Level     Level             `json:"level"`
	Timestamp time.Time         `json:"timestamp"`
	Title     string            `json:"title"`
	Detail    string            `json:"detail,omitempty"`
	Resource  string            `json:"resource,omitempty"`
	Severity  string            `json:"severity,omitempty"`
	Meta      map[string]string `json:"meta,omitempty"`
}

// Bus fans events out to subscribers and retains a bounded history so late
// joiners (e.g. a dashboard client loading the page) can backfill recent
// activity without waiting for new events.
type Bus struct {
	mu          sync.RWMutex
	subscribers map[chan Event]struct{}
	buffer      []Event
	capacity    int
	seq         uint64
}

// NewBus returns a Bus retaining up to `capacity` recent events.
func NewBus(capacity int) *Bus {
	if capacity <= 0 {
		capacity = 500
	}
	return &Bus{
		subscribers: make(map[chan Event]struct{}),
		buffer:      make([]Event, 0, capacity),
		capacity:    capacity,
	}
}

// defaultBus is the package-level singleton used by the convenience helpers.
// Tests may swap it via SetDefault.
var (
	defaultMu  sync.RWMutex
	defaultBus = NewBus(500)
)

// Default returns the package-level singleton bus.
func Default() *Bus {
	defaultMu.RLock()
	defer defaultMu.RUnlock()
	return defaultBus
}

// SetDefault replaces the package-level bus. Intended for tests.
func SetDefault(b *Bus) {
	defaultMu.Lock()
	defaultBus = b
	defaultMu.Unlock()
}

// Publish appends an event to the ring buffer and fans it out to subscribers.
// Subscribers that cannot keep up drop the event rather than blocking the
// caller — controller reconcile loops must never stall on telemetry.
func (b *Bus) Publish(e *Event) {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}

	b.mu.Lock()
	if e.ID == "" {
		b.seq++
		e.ID = fmt.Sprintf("evt-%d-%d", e.Timestamp.UnixNano(), b.seq)
	}
	b.buffer = append(b.buffer, *e)
	if len(b.buffer) > b.capacity {
		b.buffer = b.buffer[len(b.buffer)-b.capacity:]
	}
	b.mu.Unlock()

	// Hold RLock while sending so unsubscribe (Lock + close) cannot race
	// with an in-flight non-blocking send on a channel about to be closed.
	// The sends are non-blocking (default arm) so this section is O(subs).
	b.mu.RLock()
	for ch := range b.subscribers {
		select {
		case ch <- *e:
		default:
		}
	}
	b.mu.RUnlock()
}

// Subscribe returns a receive-only channel of future events and a cancel
// function that unsubscribes and closes the channel.
func (b *Bus) Subscribe() (events <-chan Event, cancel func()) {
	ch := make(chan Event, 64)
	b.mu.Lock()
	b.subscribers[ch] = struct{}{}
	b.mu.Unlock()

	return ch, func() {
		b.mu.Lock()
		if _, ok := b.subscribers[ch]; ok {
			delete(b.subscribers, ch)
			close(ch)
		}
		b.mu.Unlock()
	}
}

// Recent returns up to `limit` most-recent events matching the optional
// stage filter. An empty stage returns events from all stages.
func (b *Bus) Recent(stage Stage, limit int) []Event {
	if limit <= 0 {
		limit = 100
	}
	b.mu.RLock()
	defer b.mu.RUnlock()

	out := make([]Event, 0, limit)
	for i := len(b.buffer) - 1; i >= 0 && len(out) < limit; i-- {
		if stage != "" && b.buffer[i].Stage != stage {
			continue
		}
		out = append(out, b.buffer[i])
	}
	return out
}

// ---- Convenience helpers (emit against the default bus) ---------------------

// EmitScanStarted announces the beginning of a ClusterScan reconcile.
func EmitScanStarted(name, namespace string, scanners []string) {
	Default().Publish(&Event{
		Type:     "scan.started",
		Stage:    StageScan,
		Level:    LevelInfo,
		Title:    fmt.Sprintf("Scan started: %s", name),
		Detail:   fmt.Sprintf("Running %d scanner(s)", len(scanners)),
		Resource: fmt.Sprintf("%s/%s", namespace, name),
		Meta:     map[string]string{"scanners": strings.Join(scanners, ",")},
	})
}

// ScanCompletion summarizes the outcome of a scan.
type ScanCompletion struct {
	Name, Namespace, ReportName string
	Total                       int32
	Critical, High              int32
	Medium, Low, Info           int32
	DurationMs                  int64
	HasErrors                   bool
}

// EmitScanCompleted announces a finished ClusterScan.
func EmitScanCompleted(c *ScanCompletion) {
	level := LevelSuccess
	if c.HasErrors || c.Critical > 0 || c.High > 0 {
		level = LevelWarning
	}
	Default().Publish(&Event{
		Type:     "scan.completed",
		Stage:    StageScan,
		Level:    level,
		Title:    fmt.Sprintf("Scan completed: %s", c.Name),
		Detail:   fmt.Sprintf("%d findings (C:%d H:%d M:%d L:%d I:%d)", c.Total, c.Critical, c.High, c.Medium, c.Low, c.Info),
		Resource: fmt.Sprintf("%s/%s", c.Namespace, c.Name),
		Meta: map[string]string{
			"report":     c.ReportName,
			"durationMs": fmt.Sprintf("%d", c.DurationMs),
			"findings":   fmt.Sprintf("%d", c.Total),
		},
	})
}

// EmitFindingDetected reports a single high-signal finding during a scan.
// Callers should only emit for Critical/High severities to keep the stream
// focused — everything else is visible via the report.
func EmitFindingDetected(scanName, ruleType, severity, resource, title string) {
	Default().Publish(&Event{
		Type:     "finding.detected",
		Stage:    StageScan,
		Level:    severityLevel(severity),
		Title:    title,
		Detail:   ruleType,
		Resource: resource,
		Severity: severity,
		Meta:     map[string]string{"scan": scanName},
	})
}

// EmitReportCreated announces a fresh ScanReport resource.
func EmitReportCreated(reportName, scanRef string, findings int32) {
	Default().Publish(&Event{
		Type:     "report.created",
		Stage:    StageScan,
		Level:    LevelInfo,
		Title:    fmt.Sprintf("Report ready: %s", reportName),
		Detail:   fmt.Sprintf("%d findings from %s", findings, scanRef),
		Resource: reportName,
	})
}

// EmitCorrelationGrouped announces that N findings were collapsed into M root
// causes by the correlator engine.
func EmitCorrelationGrouped(sourceFindings, rootCauses int, scanRef string) {
	Default().Publish(&Event{
		Type:   "correlation.grouped",
		Stage:  StageCorrelate,
		Level:  LevelInfo,
		Title:  fmt.Sprintf("%d findings → %d root causes", sourceFindings, rootCauses),
		Detail: fmt.Sprintf("Correlator reduced noise by %d%%", reductionPct(sourceFindings, rootCauses)),
		Meta:   map[string]string{"scan": scanRef},
	})
}

// EmitRemediationDrafted announces an AI-authored remediation proposal.
func EmitRemediationDrafted(scanRef, summary string, fileCount int) {
	Default().Publish(&Event{
		Type:   "remediation.drafted",
		Stage:  StageFix,
		Level:  LevelInfo,
		Title:  "Remediation drafted",
		Detail: fmt.Sprintf("%s — touches %d file(s)", summary, fileCount),
		Meta:   map[string]string{"scan": scanRef, "files": fmt.Sprintf("%d", fileCount)},
	})
}

// EmitPullRequestOpened announces a GitOps PR.
func EmitPullRequestOpened(prURL, repo string, fileCount int) {
	Default().Publish(&Event{
		Type:     "pr.opened",
		Stage:    StageFix,
		Level:    LevelSuccess,
		Title:    "Pull request opened",
		Detail:   fmt.Sprintf("%d file(s) changed", fileCount),
		Resource: repo,
		Meta:     map[string]string{"url": prURL, "files": fmt.Sprintf("%d", fileCount)},
	})
}

// EmitPullRequestMerged announces a merged GitOps PR.
func EmitPullRequestMerged(prURL, repo string) {
	Default().Publish(&Event{
		Type:     "pr.merged",
		Stage:    StageFix,
		Level:    LevelSuccess,
		Title:    "Pull request merged",
		Detail:   repo,
		Resource: repo,
		Meta:     map[string]string{"url": prURL},
	})
}

// EmitConfigPRDrafted announces that a user-initiated config change (e.g. a
// compliance preset enablement) was turned into a GitOps PR. The event lands
// in the Fix stage of the Pipeline alongside AI-drafted remediations — same
// machinery, different origin.
func EmitConfigPRDrafted(presetName, prURL, repo, summary string, fileCount int) {
	Default().Publish(&Event{
		Type:     "config.pr.drafted",
		Stage:    StageFix,
		Level:    LevelInfo,
		Title:    fmt.Sprintf("Config change drafted: %s", presetName),
		Detail:   fmt.Sprintf("%s — %d file(s)", summary, fileCount),
		Resource: repo,
		Meta: map[string]string{
			"url":    prURL,
			"preset": presetName,
			"files":  fmt.Sprintf("%d", fileCount),
		},
	})
}

// EmitConfigApplied announces that a user-initiated config change was
// applied directly to the cluster (bypassing GitOps). Used for the
// bootstrap / no-GitOps-repo fallback path.
func EmitConfigApplied(presetName, summary string, fileCount int) {
	Default().Publish(&Event{
		Type:   "config.applied",
		Stage:  StageFix,
		Level:  LevelWarning,
		Title:  fmt.Sprintf("Config applied directly: %s", presetName),
		Detail: fmt.Sprintf("%s — %d resource(s), no PR review", summary, fileCount),
		Meta: map[string]string{
			"preset": presetName,
			"files":  fmt.Sprintf("%d", fileCount),
		},
	})
}

// EmitFindingResolved announces a re-scan that confirmed a prior finding is
// gone after remediation.
func EmitFindingResolved(resource, rule string) {
	Default().Publish(&Event{
		Type:     "finding.resolved",
		Stage:    StageVerify,
		Level:    LevelSuccess,
		Title:    "Finding resolved",
		Detail:   rule,
		Resource: resource,
	})
}

// ---- helpers ----------------------------------------------------------------

func severityLevel(sev string) Level {
	switch strings.ToLower(sev) {
	case "critical", "high":
		return LevelError
	case "medium":
		return LevelWarning
	default:
		return LevelInfo
	}
}

func reductionPct(source, result int) int {
	if source <= 0 {
		return 0
	}
	return int(float64(source-result) / float64(source) * 100)
}
