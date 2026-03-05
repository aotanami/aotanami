/*
Copyright 2026 Zelyo AI

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

// Phase constants for CRD status fields.
// Following Kubernetes conventions, these represent the lifecycle state of each resource.
const (
	// PhaseInitializing indicates the resource is being set up for the first time.
	PhaseInitializing = "Initializing"

	// PhasePending indicates the resource is accepted but not yet active.
	PhasePending = "Pending"

	// PhaseActive indicates the resource is fully operational.
	PhaseActive = "Active"

	// PhaseDegraded indicates the resource is operational but with issues.
	PhaseDegraded = "Degraded"

	// PhaseError indicates the resource has encountered an unrecoverable error.
	PhaseError = "Error"

	// PhaseRunning indicates a scan is currently in progress.
	PhaseRunning = "Running"

	// PhaseCompleted indicates a scan or report has finished successfully.
	PhaseCompleted = "Completed"

	// PhaseFailed indicates a scan has failed.
	PhaseFailed = "Failed"

	// PhaseSyncing indicates a GitOps repository sync is in progress.
	PhaseSyncing = "Syncing"

	// PhaseSynced indicates a GitOps repository has been successfully synced.
	PhaseSynced = "Synced"

	// PhaseDiscovering indicates auto-discovery of repo structure or controller is in progress.
	PhaseDiscovering = "Discovering"

	// PhaseComplete indicates a report is finalized.
	PhaseComplete = "Complete"
)

// Condition types for metav1.Condition — following Kubernetes API conventions.
// Each condition type answers a specific question about the resource's state.
const (
	// ConditionReady indicates whether the resource is fully operational.
	// True = ready, False = not ready.
	ConditionReady = "Ready"

	// ConditionReconciling indicates a reconciliation is in progress.
	ConditionReconciling = "Reconciling"

	// ConditionStalled indicates reconciliation is stuck and requires user intervention.
	ConditionStalled = "Stalled"

	// ConditionLLMConfigured indicates whether the LLM provider is properly configured.
	ConditionLLMConfigured = "LLMConfigured"

	// ConditionSecretResolved indicates whether referenced Secrets were found and valid.
	ConditionSecretResolved = "SecretResolved"

	// ConditionScanCompleted indicates whether the last scan completed successfully.
	ConditionScanCompleted = "ScanCompleted"

	// ConditionGitOpsConnected indicates whether the GitOps repository is reachable.
	ConditionGitOpsConnected = "GitOpsConnected"

	// ConditionSourceDetected indicates whether the manifest source type has been determined.
	ConditionSourceDetected = "SourceDetected"

	// ConditionControllerLinked indicates whether a GitOps controller has been linked.
	ConditionControllerLinked = "ControllerLinked"

	// ConditionManifestsParsed indicates whether manifests were successfully parsed.
	ConditionManifestsParsed = "ManifestsParsed"

	// ConditionNotificationDelivered indicates whether the last notification was delivered.
	ConditionNotificationDelivered = "NotificationDelivered"
)

// Condition reason constants — these explain WHY a condition is True/False.
// Following the PascalCase convention from Kubernetes API.
const (
	// ReasonReconcileSuccess indicates successful reconciliation.
	ReasonReconcileSuccess = "ReconcileSuccess"

	// ReasonReconcileFailed indicates reconciliation failure.
	ReasonReconcileFailed = "ReconcileFailed"

	// ReasonSecretNotFound indicates a referenced Secret does not exist.
	ReasonSecretNotFound = "SecretNotFound"

	// ReasonSecretKeyMissing indicates a referenced Secret exists but is missing a required key.
	ReasonSecretKeyMissing = "SecretKeyMissing"

	// ReasonSecretResolved indicates all referenced Secrets are valid.
	ReasonSecretResolved = "SecretResolved"

	// ReasonLLMReady indicates the LLM provider is configured and reachable.
	ReasonLLMReady = "LLMReady"

	// ReasonLLMNotConfigured indicates the LLM provider is not properly configured.
	ReasonLLMNotConfigured = "LLMNotConfigured"

	// ReasonScanSuccess indicates a scan completed without errors.
	ReasonScanSuccess = "ScanSuccess"

	// ReasonScanFailed indicates a scan failed with errors.
	ReasonScanFailed = "ScanFailed"

	// ReasonViolationsFound indicates security violations were detected.
	ReasonViolationsFound = "ViolationsFound"

	// ReasonNoViolations indicates no security violations were found.
	ReasonNoViolations = "NoViolations"

	// ReasonSingletonViolation indicates multiple instances of a singleton resource exist.
	ReasonSingletonViolation = "SingletonViolation"

	// ReasonTargetNotFound indicates the referenced target resource was not found.
	ReasonTargetNotFound = "TargetNotFound"

	// ReasonInvalidConfig indicates the resource configuration is invalid.
	ReasonInvalidConfig = "InvalidConfig"

	// ReasonProgressingMessage is used when reconciliation is actively progressing.
	ReasonProgressingMessage = "Progressing"

	// ReasonSourceAutoDetected indicates the manifest source type was auto-detected.
	ReasonSourceAutoDetected = "SourceAutoDetected"

	// ReasonSourceConfigured indicates the manifest source type was explicitly configured.
	ReasonSourceConfigured = "SourceConfigured"

	// ReasonHelmDetected indicates a Helm chart was detected.
	ReasonHelmDetected = "HelmDetected"

	// ReasonKustomizeDetected indicates Kustomize overlays were detected.
	ReasonKustomizeDetected = "KustomizeDetected"

	// ReasonControllerAutoDetected indicates the GitOps controller was auto-detected.
	ReasonControllerAutoDetected = "ControllerAutoDetected"

	// ReasonControllerNotFound indicates no GitOps controller was found on the cluster.
	ReasonControllerNotFound = "ControllerNotFound"

	// ReasonControllerLinked indicates Zelyo Operator linked to a GitOps controller resource.
	ReasonControllerLinked = "ControllerLinked"

	// ReasonManifestParseError indicates an error parsing manifests.
	ReasonManifestParseError = "ManifestParseError"

	// ReasonManifestsParsed indicates manifests were successfully parsed.
	ReasonManifestsParsed = "ManifestsParsed"
)

// Event reason constants for Kubernetes event recording.
const (
	// EventReasonReconciled is emitted when a resource is successfully reconciled.
	EventReasonReconciled = "Reconciled"

	// EventReasonReconcileError is emitted when reconciliation fails.
	EventReasonReconcileError = "ReconcileError"

	// EventReasonScanStarted is emitted when a security scan begins.
	EventReasonScanStarted = "ScanStarted"

	// EventReasonScanCompleted is emitted when a security scan finishes.
	EventReasonScanCompleted = "ScanCompleted"

	// EventReasonViolationsDetected is emitted when violations are found.
	EventReasonViolationsDetected = "ViolationsDetected"

	// EventReasonLLMConfigured is emitted when LLM is successfully configured.
	EventReasonLLMConfigured = "LLMConfigured"

	// EventReasonSecretMissing is emitted when a required Secret is not found.
	EventReasonSecretMissing = "SecretMissing"

	// EventReasonSingletonConflict is emitted when duplicate singleton resources exist.
	EventReasonSingletonConflict = "SingletonConflict"

	// EventReasonSourceDetected is emitted when the manifest source type is detected.
	EventReasonSourceDetected = "SourceDetected"

	// EventReasonControllerLinked is emitted when a GitOps controller is linked.
	EventReasonControllerLinked = "ControllerLinked"

	// EventReasonDiscoveryComplete is emitted when auto-discovery finishes.
	EventReasonDiscoveryComplete = "DiscoveryComplete"
)

// Severity constants used across SecurityPolicy, ScanReport, and NotificationChannel.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// SecurityRule type constants.
const (
	RuleTypeContainerSecurityContext = "container-security-context"
	RuleTypeRBACAudit                = "rbac-audit"
	RuleTypeImageVulnerability       = "image-vulnerability"
	RuleTypeNetworkPolicy            = "network-policy"
	RuleTypePodSecurity              = "pod-security"
	RuleTypeSecretsExposure          = "secrets-exposure"
	RuleTypeResourceLimits           = "resource-limits"
	RuleTypePrivilegeEscalation      = "privilege-escalation"
)
