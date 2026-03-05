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

// ScanReportSpec defines the desired state of ScanReport.
// A ScanReport stores the results of a ClusterScan run.
type ScanReportSpec struct {
	// scanRef is the name of the ClusterScan that produced this report.
	// +required
	ScanRef string `json:"scanRef"`

	// findings is the list of issues discovered during the scan.
	// +optional
	Findings []Finding `json:"findings,omitempty"`

	// summary provides an overview of the scan results.
	// +optional
	Summary ScanSummary `json:"summary,omitempty"`

	// compliance contains compliance framework evaluation results.
	// +optional
	Compliance []ComplianceResult `json:"compliance,omitempty"`
}

// Finding represents a single issue discovered during a scan.
type Finding struct {
	// id is a unique identifier for this finding.
	// +required
	ID string `json:"id"`

	// severity of the finding.
	// +kubebuilder:validation:Enum=critical;high;medium;low;info
	// +required
	Severity string `json:"severity"`

	// category of the finding (e.g., security, misconfiguration, compliance).
	// +required
	Category string `json:"category"`

	// title is a short human-readable summary.
	// +required
	Title string `json:"title"`

	// description is a detailed explanation of the finding.
	// +required
	Description string `json:"description"`

	// resource identifies the affected Kubernetes resource.
	// +optional
	Resource AffectedResource `json:"resource,omitempty"`

	// recommendation is the suggested fix.
	// +optional
	Recommendation string `json:"recommendation,omitempty"`

	// remediated indicates whether this finding has been auto-remediated.
	// +kubebuilder:default=false
	// +optional
	Remediated bool `json:"remediated,omitempty"`
}

// AffectedResource identifies a Kubernetes resource associated with a finding.
type AffectedResource struct {
	// apiVersion of the resource.
	// +optional
	APIVersion string `json:"apiVersion,omitempty"`

	// kind of the resource.
	// +optional
	Kind string `json:"kind,omitempty"`

	// namespace of the resource.
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// name of the resource.
	// +optional
	Name string `json:"name,omitempty"`
}

// ScanSummary provides aggregate metrics for a scan.
type ScanSummary struct {
	// totalFindings is the total number of findings.
	// +optional
	TotalFindings int32 `json:"totalFindings,omitempty"`

	// critical count.
	// +optional
	Critical int32 `json:"critical,omitempty"`

	// high count.
	// +optional
	High int32 `json:"high,omitempty"`

	// medium count.
	// +optional
	Medium int32 `json:"medium,omitempty"`

	// low count.
	// +optional
	Low int32 `json:"low,omitempty"`

	// info count.
	// +optional
	Info int32 `json:"info,omitempty"`

	// resourcesScanned is the number of resources evaluated.
	// +optional
	ResourcesScanned int32 `json:"resourcesScanned,omitempty"`
}

// ComplianceResult captures compliance status for a specific framework.
type ComplianceResult struct {
	// framework identifies the compliance standard.
	// +required
	Framework string `json:"framework"`

	// passRate is the percentage of controls that passed (0-100).
	// +optional
	PassRate int32 `json:"passRate,omitempty"`

	// totalControls is the total number of controls evaluated.
	// +optional
	TotalControls int32 `json:"totalControls,omitempty"`

	// failedControls is the number of controls that failed.
	// +optional
	FailedControls int32 `json:"failedControls,omitempty"`
}

// ScanReportStatus defines the observed state of ScanReport.
type ScanReportStatus struct {
	// phase indicates whether the report is complete.
	// +kubebuilder:validation:Enum=Pending;Complete
	// +optional
	Phase string `json:"phase,omitempty"`

	// acknowledged indicates whether the report has been reviewed.
	// +kubebuilder:default=false
	// +optional
	Acknowledged bool `json:"acknowledged,omitempty"`

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
// +kubebuilder:printcolumn:name="Scan",type=string,JSONPath=`.spec.scanRef`
// +kubebuilder:printcolumn:name="Findings",type=integer,JSONPath=`.spec.summary.totalFindings`
// +kubebuilder:printcolumn:name="Critical",type=integer,JSONPath=`.spec.summary.critical`
// +kubebuilder:printcolumn:name="High",type=integer,JSONPath=`.spec.summary.high`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ScanReport is the Schema for the scanreports API.
// It stores findings from a ClusterScan run as a queryable Kubernetes resource.
type ScanReport struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec ScanReportSpec `json:"spec"`

	// +optional
	Status ScanReportStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// ScanReportList contains a list of ScanReport
type ScanReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []ScanReport `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ScanReport{}, &ScanReportList{})
}
