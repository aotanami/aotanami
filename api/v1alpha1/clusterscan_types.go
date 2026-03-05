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

// ClusterScanSpec defines the desired state of ClusterScan.
// A ClusterScan triggers security, compliance, and configuration scans
// on a schedule or on-demand.
type ClusterScanSpec struct {
	// schedule is a cron expression for periodic scans. If empty, the scan runs once.
	// +optional
	Schedule string `json:"schedule,omitempty"`

	// scanners lists which scanning modules to run.
	// +kubebuilder:validation:MinItems=1
	// +required
	Scanners []string `json:"scanners"`

	// scope restricts the scan to specific namespaces.
	// +optional
	Scope ScanScope `json:"scope,omitempty"`

	// complianceFrameworks lists compliance frameworks to evaluate against.
	// +kubebuilder:validation:Items:Enum=cis;nsa-cisa;pci-dss;soc2;hipaa
	// +optional
	ComplianceFrameworks []string `json:"complianceFrameworks,omitempty"`

	// suspend pauses scheduled scans when true.
	// +kubebuilder:default=false
	// +optional
	Suspend bool `json:"suspend,omitempty"`

	// historyLimit is the number of ScanReport resources to retain.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=10
	// +optional
	HistoryLimit int32 `json:"historyLimit,omitempty"`
}

// ScanScope defines the targeting scope for a scan.
type ScanScope struct {
	// namespaces to include. Empty means all namespaces.
	// +optional
	Namespaces []string `json:"namespaces,omitempty"`

	// excludeNamespaces to exclude from the scan.
	// +optional
	ExcludeNamespaces []string `json:"excludeNamespaces,omitempty"`
}

// ClusterScanStatus defines the observed state of ClusterScan.
type ClusterScanStatus struct {
	// phase indicates the current scan lifecycle.
	// +kubebuilder:validation:Enum=Pending;Running;Completed;Failed
	// +optional
	Phase string `json:"phase,omitempty"`

	// lastScheduleTime is when the scan was last triggered.
	// +optional
	LastScheduleTime *metav1.Time `json:"lastScheduleTime,omitempty"`

	// completedAt is when the last scan finished.
	// +optional
	CompletedAt *metav1.Time `json:"completedAt,omitempty"`

	// findingsCount is the total number of findings from the last scan.
	// +optional
	FindingsCount int32 `json:"findingsCount,omitempty"`

	// lastReportName is the name of the most recent ScanReport resource.
	// +optional
	LastReportName string `json:"lastReportName,omitempty"`

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
// +kubebuilder:printcolumn:name="Schedule",type=string,JSONPath=`.spec.schedule`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Findings",type=integer,JSONPath=`.status.findingsCount`
// +kubebuilder:printcolumn:name="Last Run",type=date,JSONPath=`.status.lastScheduleTime`

// ClusterScan is the Schema for the clusterscans API.
// It triggers and manages security and compliance scans across the cluster.
type ClusterScan struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec ClusterScanSpec `json:"spec"`

	// +optional
	Status ClusterScanStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// ClusterScanList contains a list of ClusterScan
type ClusterScanList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []ClusterScan `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ClusterScan{}, &ClusterScanList{})
}
