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

// CloudAccountConfigSpec defines the desired state of CloudAccountConfig.
// CloudAccountConfig onboards a cloud provider account for security scanning.
// Multiple accounts can exist per namespace (one per cloud account).
type CloudAccountConfigSpec struct {
	// provider identifies the cloud provider.
	// +kubebuilder:validation:Enum=aws;gcp;azure
	// +required
	Provider string `json:"provider"`

	// accountID is the cloud account identifier.
	// AWS: 12-digit Account ID, GCP: Project ID, Azure: Subscription ID.
	// +required
	AccountID string `json:"accountID"`

	// regions lists the cloud regions to scan.
	// Empty means all available regions for the provider.
	// +optional
	Regions []string `json:"regions,omitempty"`

	// credentials configures how to authenticate to the cloud provider.
	// +required
	Credentials CloudCredentials `json:"credentials"`

	// scanCategories selects which cloud scanner categories to run.
	// Empty means all categories.
	// +kubebuilder:validation:Items:Enum=cspm;ciem;network;dspm;supply-chain;cicd-pipeline
	// +optional
	ScanCategories []string `json:"scanCategories,omitempty"`

	// complianceFrameworks selects compliance frameworks to evaluate against.
	// +kubebuilder:validation:Items:Enum=soc2;pci-dss;hipaa;cis-aws;nist-800-53;iso-27001
	// +optional
	ComplianceFrameworks []string `json:"complianceFrameworks,omitempty"`

	// schedule is a cron expression for periodic cloud scans.
	// If empty, scans run only on creation or manual trigger.
	// +optional
	Schedule string `json:"schedule,omitempty"`

	// suspend pauses cloud scanning when true.
	// +kubebuilder:default=false
	// +optional
	Suspend bool `json:"suspend,omitempty"`

	// historyLimit is the number of ScanReport resources to retain per account.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=10
	// +optional
	HistoryLimit int32 `json:"historyLimit,omitempty"`
}

// CloudCredentials configures authentication to a cloud provider.
type CloudCredentials struct {
	// method specifies the credential mechanism.
	// irsa: IAM Roles for Service Accounts (EKS). Recommended.
	// workload-identity: GCP Workload Identity Federation.
	// pod-identity: EKS Pod Identity.
	// secret: Static credentials from a Kubernetes Secret (least preferred).
	// +kubebuilder:validation:Enum=irsa;workload-identity;pod-identity;secret
	// +required
	Method string `json:"method"`

	// roleARN is the IAM role ARN to assume.
	// Required for 'irsa' and when using cross-account access.
	// +optional
	RoleARN string `json:"roleARN,omitempty"`

	// secretRef references a Kubernetes Secret containing static credentials.
	// Required when method is 'secret'.
	// For AWS: keys "aws-access-key-id" and "aws-secret-access-key".
	// +optional
	SecretRef string `json:"secretRef,omitempty"`

	// externalID is the STS ExternalId for cross-account AssumeRole.
	// +optional
	ExternalID string `json:"externalID,omitempty"`

	// serviceAccountName is the Kubernetes ServiceAccount to use for IRSA/Workload Identity.
	// Defaults to the operator's service account.
	// +optional
	ServiceAccountName string `json:"serviceAccountName,omitempty"`
}

// CloudAccountConfigStatus defines the observed state of CloudAccountConfig.
type CloudAccountConfigStatus struct {
	// observedGeneration is the most recent generation observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// phase indicates the current lifecycle phase.
	// +kubebuilder:validation:Enum=Initializing;Active;Degraded;Error;Running;Completed;Failed
	// +optional
	Phase string `json:"phase,omitempty"`

	// lastScanTime is when the last scan was initiated.
	// +optional
	LastScanTime *metav1.Time `json:"lastScanTime,omitempty"`

	// completedAt is when the last scan finished.
	// +optional
	CompletedAt *metav1.Time `json:"completedAt,omitempty"`

	// findingsCount is the number of findings from the last scan.
	// +optional
	FindingsCount int32 `json:"findingsCount,omitempty"`

	// findingsSummary breaks down findings by severity.
	// +optional
	FindingsSummary FindingsSummary `json:"findingsSummary,omitempty"`

	// lastReportName is the name of the most recent ScanReport.
	// +optional
	LastReportName string `json:"lastReportName,omitempty"`

	// scannedRegions lists the regions that were scanned.
	// +optional
	ScannedRegions []string `json:"scannedRegions,omitempty"`

	// resourcesScanned is the number of cloud resources evaluated.
	// +optional
	ResourcesScanned int32 `json:"resourcesScanned,omitempty"`

	// conditions represent the current state of the resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// FindingsSummary provides a severity breakdown of scan findings.
type FindingsSummary struct {
	// +optional
	Critical int32 `json:"critical,omitempty"`
	// +optional
	High int32 `json:"high,omitempty"`
	// +optional
	Medium int32 `json:"medium,omitempty"`
	// +optional
	Low int32 `json:"low,omitempty"`
	// +optional
	Info int32 `json:"info,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Provider",type=string,JSONPath=`.spec.provider`
// +kubebuilder:printcolumn:name="Account",type=string,JSONPath=`.spec.accountID`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Findings",type=integer,JSONPath=`.status.findingsCount`
// +kubebuilder:printcolumn:name="Last Scan",type=date,JSONPath=`.status.lastScanTime`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// CloudAccountConfig is the Schema for the cloudaccountconfigs API.
// It onboards a cloud provider account for autonomous security scanning.
type CloudAccountConfig struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec CloudAccountConfigSpec `json:"spec"`

	// +optional
	Status CloudAccountConfigStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// CloudAccountConfigList contains a list of CloudAccountConfig.
type CloudAccountConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []CloudAccountConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&CloudAccountConfig{}, &CloudAccountConfigList{})
}
