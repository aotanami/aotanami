/*
Copyright 2026 Zelyo AI
*/

// Package policy provides policy evaluation logic for Zelyo Operator. It handles the
// mapping between security findings and policy rules, determining which findings
// should be enforced vs. reported, and managing policy exceptions.
package policy

import (
	"time"
)

// EvaluationResult represents the outcome of evaluating a finding against a policy.
type EvaluationResult struct {
	// PolicyName is the SecurityPolicy that was evaluated.
	PolicyName string `json:"policy_name"`

	// PolicyNamespace is the policy's namespace.
	PolicyNamespace string `json:"policy_namespace"`

	// RuleName is the specific rule that matched.
	RuleName string `json:"rule_name"`

	// Action is the resulting action (enforce, report, ignore).
	Action Action `json:"action"`

	// Severity is the finding severity.
	Severity string `json:"severity"`

	// Pass indicates whether the finding passed the policy check.
	Pass bool `json:"pass"`

	// Message is a human-readable result description.
	Message string `json:"message"`

	// EvaluatedAt is when the evaluation occurred.
	EvaluatedAt time.Time `json:"evaluated_at"`

	// Exception is set if an exception is active for this finding.
	Exception *Exception `json:"exception,omitempty"`
}

// Action determines what happens when a policy rule matches.
type Action string

// Enumeration values.
const (
	ActionEnforce Action = "enforce" // Block or remediate
	ActionReport  Action = "report"  // Log and alert only
	ActionIgnore  Action = "ignore"  // Suppress completely
)

// Exception represents a temporary exemption from a policy rule.
type Exception struct {
	// Reason explains why the exception exists.
	Reason string `json:"reason"`

	// ApprovedBy is who approved the exception.
	ApprovedBy string `json:"approved_by"`

	// ExpiresAt is when the exception expires.
	ExpiresAt time.Time `json:"expires_at"`

	// Scope limits the exception to specific items.
	Scope ExceptionScope `json:"scope"`
}

// ExceptionScope limits where an exception applies.
type ExceptionScope struct {
	// Namespaces limits the exception to specific namespaces.
	Namespaces []string `json:"namespaces,omitempty"`

	// Resources limits to specific resource names.
	Resources []string `json:"resources,omitempty"`

	// RuleTypes limits to specific rule types.
	RuleTypes []string `json:"rule_types,omitempty"`
}

// IsExpired returns true if the exception has expired.
func (e *Exception) IsExpired() bool {
	return !e.ExpiresAt.IsZero() && time.Now().After(e.ExpiresAt)
}

// SeverityMeetsThreshold checks if a finding severity meets or exceeds a threshold.
func SeverityMeetsThreshold(findingSeverity, threshold string) bool {
	order := map[string]int{
		"critical": 5,
		"high":     4,
		"medium":   3,
		"low":      2,
		"info":     1,
	}
	return order[findingSeverity] >= order[threshold]
}
