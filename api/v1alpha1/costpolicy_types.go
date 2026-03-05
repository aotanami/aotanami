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

// CostPolicySpec defines the desired state of CostPolicy.
// A CostPolicy configures cost monitoring thresholds and workload
// rightsizing rules for targeted namespaces.
type CostPolicySpec struct {
	// targetNamespaces restricts cost monitoring to specific namespaces. Empty means all.
	// +optional
	TargetNamespaces []string `json:"targetNamespaces,omitempty"`

	// resizeStrategy defines how workloads should be rightsized.
	// +kubebuilder:validation:Enum=conservative;moderate;aggressive
	// +kubebuilder:default=conservative
	// +optional
	ResizeStrategy string `json:"resizeStrategy,omitempty"`

	// budgetLimits defines cost budget thresholds for alerting.
	// +optional
	BudgetLimits BudgetLimits `json:"budgetLimits,omitempty"`

	// idleDetection configures idle workload detection.
	// +optional
	IdleDetection IdleDetectionConfig `json:"idleDetection,omitempty"`

	// notificationChannels lists NotificationChannel names for cost alerts.
	// +optional
	NotificationChannels []string `json:"notificationChannels,omitempty"`
}

// BudgetLimits defines cost thresholds.
type BudgetLimits struct {
	// dailyBudgetUSD is the maximum daily cost in USD before alerting.
	// +optional
	DailyBudgetUSD string `json:"dailyBudgetUSD,omitempty"`

	// monthlyBudgetUSD is the maximum monthly cost in USD before alerting.
	// +optional
	MonthlyBudgetUSD string `json:"monthlyBudgetUSD,omitempty"`

	// costIncreaseThresholdPercent triggers an alert when costs increase by this percentage.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	// +kubebuilder:default=20
	// +optional
	CostIncreaseThresholdPercent int32 `json:"costIncreaseThresholdPercent,omitempty"`
}

// IdleDetectionConfig configures idle workload detection.
type IdleDetectionConfig struct {
	// enabled toggles idle workload detection.
	// +kubebuilder:default=true
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// cpuThresholdPercent — a workload using less than this % CPU is considered idle.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=50
	// +kubebuilder:default=5
	// +optional
	CPUThresholdPercent int32 `json:"cpuThresholdPercent,omitempty"`

	// memoryThresholdPercent — a workload using less than this % memory is considered idle.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=50
	// +kubebuilder:default=5
	// +optional
	MemoryThresholdPercent int32 `json:"memoryThresholdPercent,omitempty"`

	// idleDurationMinutes — the workload must be idle for this many minutes before flagging.
	// +kubebuilder:validation:Minimum=5
	// +kubebuilder:default=60
	// +optional
	IdleDurationMinutes int32 `json:"idleDurationMinutes,omitempty"`
}

// CostPolicyStatus defines the observed state of CostPolicy.
type CostPolicyStatus struct {
	// phase indicates the current lifecycle phase.
	// +kubebuilder:validation:Enum=Pending;Active;Error
	// +optional
	Phase string `json:"phase,omitempty"`

	// estimatedMonthlyCostUSD is the current estimated monthly cost.
	// +optional
	EstimatedMonthlyCostUSD string `json:"estimatedMonthlyCostUSD,omitempty"`

	// rightsizingRecommendations is the count of pending rightsizing recommendations.
	// +optional
	RightsizingRecommendations int32 `json:"rightsizingRecommendations,omitempty"`

	// idleWorkloads is the count of detected idle workloads.
	// +optional
	IdleWorkloads int32 `json:"idleWorkloads,omitempty"`

	// lastEvaluated is the timestamp of the last cost evaluation.
	// +optional
	LastEvaluated *metav1.Time `json:"lastEvaluated,omitempty"`

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
// +kubebuilder:printcolumn:name="Strategy",type=string,JSONPath=`.spec.resizeStrategy`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Est. Monthly",type=string,JSONPath=`.status.estimatedMonthlyCostUSD`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// CostPolicy is the Schema for the costpolicies API.
// It configures cost monitoring, budget alerts, and workload rightsizing rules.
type CostPolicy struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec CostPolicySpec `json:"spec"`

	// +optional
	Status CostPolicyStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// CostPolicyList contains a list of CostPolicy
type CostPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []CostPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&CostPolicy{}, &CostPolicyList{})
}
