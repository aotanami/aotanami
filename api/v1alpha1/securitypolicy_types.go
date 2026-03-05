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

// SecurityPolicySpec defines the desired state of SecurityPolicy.
// A SecurityPolicy declares what security rules to evaluate and enforce
// across targeted namespaces and workloads.
type SecurityPolicySpec struct {
	// severity defines the minimum severity level of findings to report.
	// +kubebuilder:validation:Enum=critical;high;medium;low;info
	// +kubebuilder:default=medium
	Severity string `json:"severity"`

	// match defines the scope of this policy — which namespaces and workloads it applies to.
	// +required
	Match PolicyMatch `json:"match"`

	// rules defines the set of security rules to evaluate.
	// +kubebuilder:validation:MinItems=1
	// +required
	Rules []SecurityRule `json:"rules"`

	// autoRemediate enables automatic fix generation via GitOps for violations found by this policy.
	// Only effective when a GitOpsRepository is onboarded (Protect Mode).
	// +kubebuilder:default=false
	// +optional
	AutoRemediate bool `json:"autoRemediate,omitempty"`

	// schedule defines a cron expression for periodic evaluation. If empty, the policy is evaluated continuously.
	// +optional
	Schedule string `json:"schedule,omitempty"`

	// notificationChannels lists the names of NotificationChannel resources to send alerts to.
	// +optional
	NotificationChannels []string `json:"notificationChannels,omitempty"`
}

// PolicyMatch defines the target scope for a policy.
type PolicyMatch struct {
	// namespaces restricts the policy to specific namespaces. Empty means all namespaces.
	// +optional
	Namespaces []string `json:"namespaces,omitempty"`

	// excludeNamespaces excludes specific namespaces from evaluation.
	// +optional
	ExcludeNamespaces []string `json:"excludeNamespaces,omitempty"`

	// labelSelector restricts the policy to resources matching these labels.
	// +optional
	LabelSelector *metav1.LabelSelector `json:"labelSelector,omitempty"`

	// resourceKinds restricts the policy to specific resource kinds (e.g., Deployment, StatefulSet, Pod).
	// +optional
	ResourceKinds []string `json:"resourceKinds,omitempty"`
}

// SecurityRule defines a single security check to perform.
type SecurityRule struct {
	// name is a unique identifier for this rule within the policy.
	// +required
	Name string `json:"name"`

	// type identifies the category of security check.
	// +kubebuilder:validation:Enum=container-security-context;rbac-audit;image-vulnerability;network-policy;pod-security;secrets-exposure;resource-limits;privilege-escalation
	// +required
	Type string `json:"type"`

	// enforce when true, the rule violations are treated as failures; when false, as warnings.
	// +kubebuilder:default=true
	// +optional
	Enforce bool `json:"enforce,omitempty"`

	// params provides rule-specific configuration parameters.
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	Params map[string]string `json:"params,omitempty"`
}

// SecurityPolicyStatus defines the observed state of SecurityPolicy.
type SecurityPolicyStatus struct {
	// observedGeneration is the most recent generation observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// phase indicates the current lifecycle phase of the policy.
	// +kubebuilder:validation:Enum=Pending;Active;Error
	// +optional
	Phase string `json:"phase,omitempty"`

	// violationCount is the total number of active violations found by this policy.
	// +optional
	ViolationCount int32 `json:"violationCount,omitempty"`

	// lastEvaluated is the timestamp of the last policy evaluation.
	// +optional
	LastEvaluated *metav1.Time `json:"lastEvaluated,omitempty"`

	// conditions represent the current state of the SecurityPolicy resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Severity",type=string,JSONPath=`.spec.severity`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Violations",type=integer,JSONPath=`.status.violationCount`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// SecurityPolicy is the Schema for the securitypolicies API.
// It defines security rules to evaluate and enforce on Kubernetes workloads.
type SecurityPolicy struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of SecurityPolicy
	// +required
	Spec SecurityPolicySpec `json:"spec"`

	// status defines the observed state of SecurityPolicy
	// +optional
	Status SecurityPolicyStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// SecurityPolicyList contains a list of SecurityPolicy
type SecurityPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []SecurityPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SecurityPolicy{}, &SecurityPolicyList{})
}
