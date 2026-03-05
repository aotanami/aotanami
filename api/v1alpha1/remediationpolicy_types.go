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

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RemediationPolicySpec defines the desired state of RemediationPolicy.
// A RemediationPolicy configures how Zelyo Operator generates and submits fixes
// via GitOps when policy violations are detected.
type RemediationPolicySpec struct {
	// targetPolicies lists the SecurityPolicy names this remediation applies to. Empty means all.
	// +optional
	TargetPolicies []string `json:"targetPolicies,omitempty"`

	// gitOpsRepository is the name of the GitOpsRepository resource to submit PRs against.
	// +required
	GitOpsRepository string `json:"gitOpsRepository"`

	// prTemplate configures how pull requests are created.
	// +optional
	PRTemplate PRTemplateConfig `json:"prTemplate,omitempty"`

	// dryRun when true, generates fixes but does not create actual PRs.
	// +kubebuilder:default=false
	// +optional
	DryRun bool `json:"dryRun,omitempty"`

	// maxConcurrentPRs limits the number of open PRs at any time.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=5
	// +optional
	MaxConcurrentPRs int32 `json:"maxConcurrentPRs,omitempty"`

	// autoMerge when true, enables auto-merge on PRs after all checks pass.
	// +kubebuilder:default=false
	// +optional
	AutoMerge bool `json:"autoMerge,omitempty"`

	// severityFilter only creates PRs for findings at or above this severity level.
	// +kubebuilder:validation:Enum=critical;high;medium;low
	// +kubebuilder:default=high
	// +optional
	SeverityFilter string `json:"severityFilter,omitempty"`
}

// PRTemplateConfig defines how PRs are structured.
type PRTemplateConfig struct {
	// titlePrefix is prepended to all PR titles (e.g., "[Zelyo Operator]").
	// +kubebuilder:default="[Zelyo Operator]"
	// +optional
	TitlePrefix string `json:"titlePrefix,omitempty"`

	// labels applied to created PRs.
	// +optional
	Labels []string `json:"labels,omitempty"`

	// assignees for created PRs.
	// +optional
	Assignees []string `json:"assignees,omitempty"`

	// branchPrefix for fix branches (e.g., "zelyo-operator/fix-").
	// +kubebuilder:default="zelyo-operator/fix-"
	// +optional
	BranchPrefix string `json:"branchPrefix,omitempty"`
}

// RemediationPolicyStatus defines the observed state of RemediationPolicy.
type RemediationPolicyStatus struct {
	// phase indicates the current lifecycle phase.
	// +kubebuilder:validation:Enum=Pending;Active;Error
	// +optional
	Phase string `json:"phase,omitempty"`

	// remediationsApplied is the total number of PRs successfully created.
	// +optional
	RemediationsApplied int32 `json:"remediationsApplied,omitempty"`

	// openPRs is the count of currently open PRs.
	// +optional
	OpenPRs int32 `json:"openPRs,omitempty"`

	// lastRun is the timestamp of the last remediation cycle.
	// +optional
	LastRun *metav1.Time `json:"lastRun,omitempty"`

	// observedGeneration is the most recent generation observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// conditions represent the current state of the resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="GitOps Repo",type=string,JSONPath=`.spec.gitOpsRepository`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="PRs Created",type=integer,JSONPath=`.status.remediationsApplied`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// RemediationPolicy is the Schema for the remediationpolicies API.
// It configures how Zelyo Operator generates and submits GitOps PRs for detected violations.
type RemediationPolicy struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec RemediationPolicySpec `json:"spec"`

	// +optional
	Status RemediationPolicyStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// RemediationPolicyList contains a list of RemediationPolicy
type RemediationPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []RemediationPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&RemediationPolicy{}, &RemediationPolicyList{})
}
