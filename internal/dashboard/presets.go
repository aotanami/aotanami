/*
Copyright 2026 Zelyo AI

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package dashboard

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Preset is a one-click compliance bundle the user can enable from the UI.
// Each preset maps to one or more Zelyo CRDs (SecurityPolicy,
// MonitoringPolicy, NotificationChannel, ...) that together enforce the
// declared framework.
//
// Presets are the canary for the hybrid PR flow: enabling a preset opens a
// review-required PR in the user's GitOps repo when one is configured, and
// falls back to direct apply otherwise. Either way, the action surfaces in
// the Pipeline's Fix stage as an event the user can click through.
type Preset struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Framework   string       `json:"framework"`
	Description string       `json:"description"`
	Icon        string       `json:"icon"` // short glyph (compliance framework shorthand)
	AccentHex   string       `json:"accentHex"`
	Controls    []string     `json:"controls"`
	Files       []PresetFile `json:"files"`
}

// PresetFile is a single YAML document that will be committed (or applied).
type PresetFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// PresetStatus captures the per-preset runtime state rendered in the UI.
type PresetStatus struct {
	ID         string     `json:"id"`
	State      string     `json:"state"` // not_enabled | proposing | pending_merge | enabled
	PRURL      string     `json:"prUrl,omitempty"`
	ProposedAt *time.Time `json:"proposedAt,omitempty"`
	EnabledAt  *time.Time `json:"enabledAt,omitempty"`
	Message    string     `json:"message,omitempty"`
}

// PresetView is the combined preset + status record sent to the dashboard.
type PresetView struct {
	Preset
	Status PresetStatus `json:"status"`
}

// ConfigStatus summarizes cluster-level capabilities that the hybrid PR
// flow needs to know about (is a GitOps repo registered? is SealedSecrets
// present?). The Compliance page uses this to choose the default action.
type ConfigStatus struct {
	GitOpsConfigured   bool   `json:"gitOpsConfigured"`
	GitOpsRepo         string `json:"gitOpsRepo,omitempty"`
	SealedSecretsReady bool   `json:"sealedSecretsReady"`
	DemoMode           bool   `json:"demoMode"`
}

// ---- Store ----------------------------------------------------------------

type presetStore struct {
	mu           sync.RWMutex
	status       map[string]*PresetStatus
	configStatus ConfigStatus
}

var defaultPresetStore = &presetStore{
	status: map[string]*PresetStatus{},
	configStatus: ConfigStatus{
		// Demo default: pretend GitOps is already connected so the PR flow
		// is the hero path. Real deployments will populate this from the
		// ZelyoConfig + GitOpsRepository reconcilers.
		GitOpsConfigured: true,
		GitOpsRepo:       "zelyo-ai/platform-gitops",
		DemoMode:         true,
	},
}

// PresetStore is the public alias for the preset status store.
type PresetStore = presetStore

// DefaultPresetStore exposes the process-wide preset status store.
func DefaultPresetStore() *PresetStore {
	return defaultPresetStore
}

// SetConfigStatus lets the controller runtime tell the dashboard whether
// GitOps / SealedSecrets are available. Called from main.go once the
// operator has reconciled its config.
func (s *presetStore) SetConfigStatus(c ConfigStatus) {
	s.mu.Lock()
	s.configStatus = c
	s.mu.Unlock()
}

// ConfigStatus returns a snapshot of the cluster capability flags.
func (s *presetStore) ConfigStatus() ConfigStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.configStatus
}

func (s *presetStore) get(id string) *PresetStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if st, ok := s.status[id]; ok {
		cp := *st
		return &cp
	}
	return &PresetStatus{ID: id, State: "not_enabled"}
}

func (s *presetStore) update(id string, mutate func(*PresetStatus)) *PresetStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.status[id]
	if !ok {
		st = &PresetStatus{ID: id, State: "not_enabled"}
		s.status[id] = st
	}
	mutate(st)
	cp := *st
	return &cp
}

// ---- Preset catalog -------------------------------------------------------

// Presets returns the catalog in display order. Curated content lives here
// rather than on disk so the dashboard binary is self-contained.
func Presets() []Preset {
	return presetCatalog
}

// FindPreset returns the preset with the given ID or nil.
func FindPreset(id string) *Preset {
	for i := range presetCatalog {
		if presetCatalog[i].ID == id {
			return &presetCatalog[i]
		}
	}
	return nil
}

// BuildDiff renders a unified-diff representation of creating every file in
// the preset. Used to preview the change in the drawer and to populate the
// RemediationContext when a PR is proposed.
func BuildDiff(p *Preset) string {
	var b strings.Builder
	for _, f := range p.Files {
		fmt.Fprintf(&b, "--- /dev/null\n+++ b/%s\n@@ +0,0 +1,%d @@\n", f.Path, lineCount(f.Content))
		for _, line := range strings.Split(f.Content, "\n") {
			fmt.Fprintf(&b, "+%s\n", line)
		}
	}
	return b.String()
}

func lineCount(s string) int {
	if s == "" {
		return 0
	}
	return strings.Count(s, "\n") + 1
}

// ---- Catalog data ---------------------------------------------------------

var presetCatalog = []Preset{
	{
		ID:          "cis-kubernetes",
		Name:        "CIS Kubernetes Benchmark",
		Framework:   "CIS K8s",
		Description: "Enforces the top 5 CIS Kubernetes Benchmark controls that block the most common real-world exploits — privileged containers, root users, dangerous capabilities, hostPath mounts, and the default-deny NetworkPolicy gap.",
		Icon:        "CIS",
		AccentHex:   "#6366F1",
		Controls: []string{
			"5.2.1 — Minimize admission of privileged containers",
			"5.2.5 — Minimize admission of containers with allowPrivilegeEscalation",
			"5.2.7 — Minimize admission of root containers",
			"5.2.9 — Minimize admission of containers with hostPath volumes",
			"5.3.2 — Ensure all namespaces have a default-deny NetworkPolicy",
		},
		Files: []PresetFile{
			{
				Path: "policies/cis-k8s/privileged.yaml",
				Content: `apiVersion: zelyo.ai/v1alpha1
kind: SecurityPolicy
metadata:
  name: cis-no-privileged
  labels:
    zelyo.ai/preset: cis-kubernetes
    zelyo.ai/framework: cis-k8s
spec:
  description: "CIS 5.2.1 — reject privileged containers"
  severity: Critical
  enforce: true
  rules:
    - type: privileged
      match:
        kinds: ["Pod", "Deployment", "DaemonSet", "StatefulSet"]
      remediation:
        strategy: gitops-pr
`,
			},
			{
				Path: "policies/cis-k8s/root-and-caps.yaml",
				Content: `apiVersion: zelyo.ai/v1alpha1
kind: SecurityPolicy
metadata:
  name: cis-no-root-no-dangerous-caps
  labels:
    zelyo.ai/preset: cis-kubernetes
    zelyo.ai/framework: cis-k8s
spec:
  description: "CIS 5.2.5 + 5.2.7 — reject root users and dangerous capabilities"
  severity: High
  enforce: true
  rules:
    - type: root-user
    - type: capabilities
      match:
        forbidden: ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE"]
`,
			},
			{
				Path: "policies/cis-k8s/host-mounts.yaml",
				Content: `apiVersion: zelyo.ai/v1alpha1
kind: SecurityPolicy
metadata:
  name: cis-no-host-mounts
  labels:
    zelyo.ai/preset: cis-kubernetes
    zelyo.ai/framework: cis-k8s
spec:
  description: "CIS 5.2.9 — reject hostPath volume mounts"
  severity: Critical
  enforce: true
  rules:
    - type: host-mounts
      match:
        forbiddenPaths:
          - /var/run/docker.sock
          - /var/run/containerd/containerd.sock
          - /proc
          - /
`,
			},
			{
				Path: "policies/cis-k8s/network-policy.yaml",
				Content: `apiVersion: zelyo.ai/v1alpha1
kind: SecurityPolicy
metadata:
  name: cis-default-deny-networkpolicy
  labels:
    zelyo.ai/preset: cis-kubernetes
    zelyo.ai/framework: cis-k8s
spec:
  description: "CIS 5.3.2 — require a default-deny NetworkPolicy per namespace"
  severity: High
  enforce: true
  rules:
    - type: network-policy
      match:
        requireDefaultDeny: true
`,
			},
		},
	},
	{
		ID:          "soc2",
		Name:        "SOC 2 Type II",
		Framework:   "SOC 2",
		Description: "Activates the audit logging, change tracking, and incident notification controls auditors map to SOC 2 trust services criteria CC6 (access), CC7 (operations), and CC9 (risk).",
		Icon:        "SOC2",
		AccentHex:   "#10B981",
		Controls: []string{
			"CC6.1 — Logical access controls for infrastructure",
			"CC6.3 — Least-privilege access to production",
			"CC7.2 — Continuous monitoring of changes",
			"CC7.3 — Incident notification within 1 hour",
			"CC9.1 — Documented remediation for identified risks",
		},
		Files: []PresetFile{
			{
				Path: "policies/soc2/monitoring.yaml",
				Content: `apiVersion: zelyo.ai/v1alpha1
kind: MonitoringPolicy
metadata:
  name: soc2-audit-logging
  labels:
    zelyo.ai/preset: soc2
    zelyo.ai/framework: soc2
spec:
  description: "SOC 2 CC7.2 — continuous monitoring of security-relevant changes"
  anomalyDetection:
    enabled: true
    sensitivity: high
  auditEvents:
    - rbac.authorization.k8s.io
    - *.apps
    - zelyo.ai/*
`,
			},
			{
				Path: "policies/soc2/notifications.yaml",
				Content: `apiVersion: zelyo.ai/v1alpha1
kind: NotificationChannel
metadata:
  name: soc2-incidents
  labels:
    zelyo.ai/preset: soc2
spec:
  description: "SOC 2 CC7.3 — incident routing"
  type: slack
  slack:
    channel: "#security-incidents"
    severityFilter: ["Critical", "High"]
  escalationMinutes: 60
`,
			},
			{
				Path: "policies/soc2/remediation.yaml",
				Content: `apiVersion: zelyo.ai/v1alpha1
kind: RemediationPolicy
metadata:
  name: soc2-auto-remediate-criticals
  labels:
    zelyo.ai/preset: soc2
spec:
  description: "SOC 2 CC9.1 — documented auto-remediation for critical findings"
  strategy: gitops-pr
  severityFilter: ["Critical"]
  requireApproval: true
  maxBlastRadius: 5
`,
			},
		},
	},
	{
		ID:          "pci-dss",
		Name:        "PCI-DSS v4.0",
		Framework:   "PCI-DSS",
		Description: "Locks down the Cardholder Data Environment with strict network segmentation, encryption-at-rest verification, and tamper-evident audit trails required by PCI-DSS requirements 1, 3, 7, and 10.",
		Icon:        "PCI",
		AccentHex:   "#F43F5E",
		Controls: []string{
			"1.2.1 — Firewall controls isolate the CDE from untrusted networks",
			"3.5.1 — Cryptographic keys are protected from disclosure",
			"7.2.4 — Access is restricted to least privilege",
			"10.2.1 — Audit logs capture all user access to cardholder data",
		},
		Files: []PresetFile{
			{
				Path: "policies/pci-dss/segmentation.yaml",
				Content: `apiVersion: zelyo.ai/v1alpha1
kind: SecurityPolicy
metadata:
  name: pci-cde-segmentation
  labels:
    zelyo.ai/preset: pci-dss
    zelyo.ai/framework: pci-dss
spec:
  description: "PCI 1.2.1 — require firewall isolation for the CDE"
  severity: Critical
  enforce: true
  rules:
    - type: network-policy
      match:
        namespaceSelector:
          zelyo.ai/zone: cde
        requireStrictEgress: true
`,
			},
			{
				Path: "policies/pci-dss/encryption.yaml",
				Content: `apiVersion: zelyo.ai/v1alpha1
kind: SecurityPolicy
metadata:
  name: pci-encryption-at-rest
  labels:
    zelyo.ai/preset: pci-dss
spec:
  description: "PCI 3.5.1 — verify encryption-at-rest on storage in the CDE"
  severity: Critical
  enforce: true
  rules:
    - type: storage-encryption
      match:
        namespaces: ["cde-*"]
        require: ["kms", "aes-256"]
`,
			},
		},
	},
	{
		ID:          "nist-800-53",
		Name:        "NIST SP 800-53 (Moderate)",
		Framework:   "NIST",
		Description: "Applies the Moderate-baseline security controls from NIST SP 800-53 rev. 5 — access control, audit, configuration management, and system integrity — as a starting point for FedRAMP Moderate or StateRAMP engagements.",
		Icon:        "NIST",
		AccentHex:   "#A855F7",
		Controls: []string{
			"AC-6 — Least privilege",
			"AU-2 — Event logging",
			"CM-7 — Least functionality",
			"SC-7 — Boundary protection",
			"SI-4 — System monitoring",
		},
		Files: []PresetFile{
			{
				Path: "policies/nist-800-53/access-control.yaml",
				Content: `apiVersion: zelyo.ai/v1alpha1
kind: SecurityPolicy
metadata:
  name: nist-least-privilege
  labels:
    zelyo.ai/preset: nist-800-53
    zelyo.ai/framework: nist-800-53
spec:
  description: "NIST AC-6 + CM-7 — least privilege, least functionality"
  severity: High
  enforce: true
  rules:
    - type: capabilities
      match:
        forbidden: ["ALL"]
        allowed: []
    - type: privileged
    - type: root-user
`,
			},
			{
				Path: "policies/nist-800-53/monitoring.yaml",
				Content: `apiVersion: zelyo.ai/v1alpha1
kind: MonitoringPolicy
metadata:
  name: nist-continuous-monitoring
  labels:
    zelyo.ai/preset: nist-800-53
spec:
  description: "NIST SI-4 + AU-2 — continuous system monitoring and audit"
  anomalyDetection:
    enabled: true
    sensitivity: high
  driftDetection:
    enabled: true
    intervalMinutes: 15
`,
			},
		},
	},
}
