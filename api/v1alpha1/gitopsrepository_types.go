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

// ManifestSourceType defines how manifests are structured in the repository.
// +kubebuilder:validation:Enum=raw;helm;kustomize;auto
type ManifestSourceType string

const (
	// ManifestSourceRaw indicates plain YAML/JSON Kubernetes manifests.
	ManifestSourceRaw ManifestSourceType = "raw"
	// ManifestSourceHelm indicates a Helm chart.
	ManifestSourceHelm ManifestSourceType = "helm"
	// ManifestSourceKustomize indicates Kustomize overlays.
	ManifestSourceKustomize ManifestSourceType = "kustomize"
	// ManifestSourceAuto indicates Zelyo Operator should auto-detect the source type.
	ManifestSourceAuto ManifestSourceType = "auto"
)

// GitOpsControllerType identifies the GitOps controller variant managing the repo.
// +kubebuilder:validation:Enum=none;argocd;flux;auto
type GitOpsControllerType string

const (
	// ControllerNone means no external GitOps controller — Zelyo Operator operates standalone.
	ControllerNone GitOpsControllerType = "none"
	// ControllerArgoCD indicates the repo is managed by ArgoCD.
	ControllerArgoCD GitOpsControllerType = "argocd"
	// ControllerFlux indicates the repo is managed by Flux.
	ControllerFlux GitOpsControllerType = "flux"
	// ControllerAuto means Zelyo Operator should auto-detect the controller from the cluster.
	ControllerAuto GitOpsControllerType = "auto"
)

// GitOpsRepositorySpec defines the desired state of GitOpsRepository.
// A GitOpsRepository represents an onboarded GitOps repository that Zelyo Operator
// uses for config drift detection and submitting remediation PRs.
type GitOpsRepositorySpec struct {
	// url is the Git repository URL (HTTPS or SSH).
	// +required
	URL string `json:"url"`

	// branch is the target branch for PRs and drift comparison.
	// +kubebuilder:default=main
	// +optional
	Branch string `json:"branch,omitempty"`

	// paths lists the directories within the repo containing Kubernetes manifests.
	// +kubebuilder:validation:MinItems=1
	// +required
	Paths []string `json:"paths"`

	// provider identifies the Git hosting provider.
	// +kubebuilder:validation:Enum=github;gitlab;bitbucket
	// +kubebuilder:default=github
	// +optional
	Provider string `json:"provider,omitempty"`

	// authSecret is the name of the Kubernetes Secret containing authentication credentials.
	// For GitHub App, use the GitHub App credentials. For PAT, use a token.
	// +required
	AuthSecret string `json:"authSecret"`

	// syncStrategy defines how Zelyo Operator syncs with the repository.
	// +kubebuilder:validation:Enum=poll;webhook
	// +kubebuilder:default=poll
	// +optional
	SyncStrategy string `json:"syncStrategy,omitempty"`

	// pollIntervalSeconds is how frequently to poll the repo for changes (when syncStrategy is poll).
	// +kubebuilder:validation:Minimum=30
	// +kubebuilder:default=300
	// +optional
	PollIntervalSeconds int32 `json:"pollIntervalSeconds,omitempty"`

	// namespaceMapping maps repository paths to Kubernetes namespaces for drift detection.
	// +optional
	NamespaceMapping []NamespaceMap `json:"namespaceMapping,omitempty"`

	// enableDriftDetection when true, enables comparing live cluster state against repo manifests.
	// +kubebuilder:default=true
	// +optional
	EnableDriftDetection bool `json:"enableDriftDetection,omitempty"`

	// sourceType defines how manifests are structured in this repository.
	// When set to "auto", Zelyo Operator scans paths for Chart.yaml (Helm) or
	// kustomization.yaml (Kustomize) and falls back to raw YAML.
	// +kubebuilder:default=auto
	// +optional
	SourceType ManifestSourceType `json:"sourceType,omitempty"`

	// controllerType identifies which GitOps controller manages this repo.
	// When set to "auto", Zelyo Operator probes the cluster for ArgoCD or Flux CRDs.
	// +kubebuilder:default=auto
	// +optional
	ControllerType GitOpsControllerType `json:"controllerType,omitempty"`

	// controllerRef is an explicit reference to an ArgoCD Application or Flux Kustomization.
	// When set, Zelyo Operator links directly to this resource instead of auto-discovering.
	// +optional
	ControllerRef *ControllerReference `json:"controllerRef,omitempty"`

	// helm contains Helm-specific configuration when sourceType is "helm".
	// +optional
	Helm *HelmSource `json:"helm,omitempty"`

	// kustomize contains Kustomize-specific configuration when sourceType is "kustomize".
	// +optional
	Kustomize *KustomizeSource `json:"kustomize,omitempty"`
}

// ControllerReference identifies a specific GitOps controller resource.
type ControllerReference struct {
	// type is the controller type (argocd or flux).
	// +kubebuilder:validation:Enum=argocd;flux
	// +required
	Type GitOpsControllerType `json:"type"`

	// name is the name of the controller resource (e.g., ArgoCD Application name).
	// +required
	Name string `json:"name"`

	// namespace is the namespace of the controller resource.
	// +required
	Namespace string `json:"namespace"`
}

// HelmSource holds configuration for Helm-chart-based GitOps repositories.
type HelmSource struct {
	// chartPath is the path to the Helm chart directory within the repo.
	// Defaults to the first element in spec.paths if not specified.
	// +optional
	ChartPath string `json:"chartPath,omitempty"`

	// valuesFiles lists paths to values files relative to the repo root.
	// Files are merged in order (last wins), matching Helm conventions.
	// +optional
	ValuesFiles []string `json:"valuesFiles,omitempty"`

	// releaseName is the Helm release name to match against live cluster resources.
	// +optional
	ReleaseName string `json:"releaseName,omitempty"`

	// releaseNamespace is the namespace where the Helm release is deployed.
	// +optional
	ReleaseNamespace string `json:"releaseNamespace,omitempty"`
}

// KustomizeSource holds configuration for Kustomize-based GitOps repositories.
type KustomizeSource struct {
	// overlayPaths lists the Kustomize overlay directories to build.
	// When empty, Zelyo Operator uses spec.paths as the overlay directories.
	// +optional
	OverlayPaths []string `json:"overlayPaths,omitempty"`

	// buildArgs specifies additional arguments for kustomize build.
	// +optional
	BuildArgs []string `json:"buildArgs,omitempty"`
}

// NamespaceMap maps a path in the GitOps repo to a Kubernetes namespace.
type NamespaceMap struct {
	// repoPath is the path within the git repository.
	// +required
	RepoPath string `json:"repoPath"`

	// namespace is the Kubernetes namespace this path corresponds to.
	// +required
	Namespace string `json:"namespace"`
}

// GitOpsRepositoryStatus defines the observed state of GitOpsRepository.
type GitOpsRepositoryStatus struct {
	// phase indicates the current lifecycle phase.
	// +kubebuilder:validation:Enum=Pending;Syncing;Synced;Discovering;Error
	// +optional
	Phase string `json:"phase,omitempty"`

	// lastSyncedCommit is the SHA of the last successfully synced commit.
	// +optional
	LastSyncedCommit string `json:"lastSyncedCommit,omitempty"`

	// lastSyncTime is when the repo was last synced.
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// discoveredManifests is the number of K8s manifests discovered in the repo.
	// +optional
	DiscoveredManifests int32 `json:"discoveredManifests,omitempty"`

	// driftCount is the number of resources with config drift from the repo.
	// +optional
	DriftCount int32 `json:"driftCount,omitempty"`

	// lastError describes the most recent sync error, if any.
	// +optional
	LastError string `json:"lastError,omitempty"`

	// observedGeneration is the most recent generation observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// detectedSourceType is the manifest source type that Zelyo Operator auto-detected.
	// Only populated when spec.sourceType is "auto".
	// +optional
	DetectedSourceType ManifestSourceType `json:"detectedSourceType,omitempty"`

	// detectedController is the GitOps controller that Zelyo Operator auto-detected.
	// Only populated when spec.controllerType is "auto".
	// +optional
	DetectedController GitOpsControllerType `json:"detectedController,omitempty"`

	// discoveredApplications is the number of ArgoCD/Flux applications
	// found that reference this repository.
	// +optional
	DiscoveredApplications int32 `json:"discoveredApplications,omitempty"`

	// conditions represent the current state of the resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="URL",type=string,JSONPath=`.spec.url`
// +kubebuilder:printcolumn:name="Branch",type=string,JSONPath=`.spec.branch`
// +kubebuilder:printcolumn:name="Source",type=string,JSONPath=`.status.detectedSourceType`
// +kubebuilder:printcolumn:name="Controller",type=string,JSONPath=`.status.detectedController`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Drifts",type=integer,JSONPath=`.status.driftCount`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// GitOpsRepository is the Schema for the gitopsrepositories API.
// It represents an onboarded GitOps repository for drift detection and PR-based remediation.
type GitOpsRepository struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec GitOpsRepositorySpec `json:"spec"`

	// +optional
	Status GitOpsRepositoryStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// GitOpsRepositoryList contains a list of GitOpsRepository
type GitOpsRepositoryList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []GitOpsRepository `json:"items"`
}

func init() {
	SchemeBuilder.Register(&GitOpsRepository{}, &GitOpsRepositoryList{})
}
