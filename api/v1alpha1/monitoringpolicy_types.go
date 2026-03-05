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

// MonitoringPolicySpec defines the desired state of MonitoringPolicy.
// A MonitoringPolicy configures real-time monitoring of Kubernetes events,
// pod logs, node conditions, and anomaly detection thresholds.
type MonitoringPolicySpec struct {
	// eventFilters configures which Kubernetes events to watch.
	// +optional
	EventFilters EventFilterConfig `json:"eventFilters,omitempty"`

	// logMonitoring configures pod log streaming and pattern matching.
	// +optional
	LogMonitoring LogMonitoringConfig `json:"logMonitoring,omitempty"`

	// nodeMonitoring configures node condition monitoring.
	// +optional
	NodeMonitoring NodeMonitoringConfig `json:"nodeMonitoring,omitempty"`

	// anomalyDetection configures the anomaly detection engine.
	// +optional
	AnomalyDetection AnomalyDetectionConfig `json:"anomalyDetection,omitempty"`

	// targetNamespaces restricts monitoring to specific namespaces. Empty means all.
	// +optional
	TargetNamespaces []string `json:"targetNamespaces,omitempty"`

	// notificationChannels lists NotificationChannel names for monitoring alerts.
	// +optional
	NotificationChannels []string `json:"notificationChannels,omitempty"`
}

// EventFilterConfig configures Kubernetes event filtering.
type EventFilterConfig struct {
	// types lists the event types to watch (Normal, Warning).
	// +kubebuilder:default={"Warning"}
	// +optional
	Types []string `json:"types,omitempty"`

	// reasons filters events by reason (e.g., OOMKilled, CrashLoopBackOff, FailedScheduling).
	// +optional
	Reasons []string `json:"reasons,omitempty"`

	// involvedObjectKinds filters events by the kind of involved object.
	// +optional
	InvolvedObjectKinds []string `json:"involvedObjectKinds,omitempty"`
}

// LogMonitoringConfig configures pod log monitoring.
type LogMonitoringConfig struct {
	// enabled toggles log monitoring.
	// +kubebuilder:default=true
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// patterns defines regex patterns to watch for in logs.
	// +optional
	Patterns []LogPattern `json:"patterns,omitempty"`

	// excludeContainers excludes specific container names from log monitoring.
	// +optional
	ExcludeContainers []string `json:"excludeContainers,omitempty"`
}

// LogPattern defines a pattern to match in pod logs.
type LogPattern struct {
	// name is a human-readable identifier for this pattern.
	// +required
	Name string `json:"name"`

	// regex is the regular expression pattern to match.
	// +required
	Regex string `json:"regex"`

	// severity assigned when this pattern matches.
	// +kubebuilder:validation:Enum=critical;high;medium;low;info
	// +kubebuilder:default=medium
	// +optional
	Severity string `json:"severity,omitempty"`
}

// NodeMonitoringConfig configures node condition monitoring.
type NodeMonitoringConfig struct {
	// enabled toggles node monitoring.
	// +kubebuilder:default=true
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// conditions lists node conditions to watch (e.g., MemoryPressure, DiskPressure, PIDPressure).
	// +kubebuilder:default={"MemoryPressure","DiskPressure","PIDPressure","NetworkUnavailable"}
	// +optional
	Conditions []string `json:"conditions,omitempty"`
}

// AnomalyDetectionConfig configures the anomaly detection engine.
type AnomalyDetectionConfig struct {
	// enabled toggles anomaly detection.
	// +kubebuilder:default=true
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// baselineDurationHours is how many hours of data to use for baseline calculation.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=168
	// +optional
	BaselineDurationHours int32 `json:"baselineDurationHours,omitempty"`

	// sensitivityPercent controls how sensitive anomaly detection is (lower = more sensitive).
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	// +kubebuilder:default=80
	// +optional
	SensitivityPercent int32 `json:"sensitivityPercent,omitempty"`
}

// MonitoringPolicyStatus defines the observed state of MonitoringPolicy.
type MonitoringPolicyStatus struct {
	// phase indicates the current lifecycle phase.
	// +kubebuilder:validation:Enum=Pending;Active;Error
	// +optional
	Phase string `json:"phase,omitempty"`

	// activeIncidents is the count of currently active incidents.
	// +optional
	ActiveIncidents int32 `json:"activeIncidents,omitempty"`

	// eventsProcessed is the total number of events processed.
	// +optional
	EventsProcessed int64 `json:"eventsProcessed,omitempty"`

	// lastEventTime is the timestamp of the last processed event.
	// +optional
	LastEventTime *metav1.Time `json:"lastEventTime,omitempty"`

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
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Active Incidents",type=integer,JSONPath=`.status.activeIncidents`
// +kubebuilder:printcolumn:name="Events Processed",type=integer,JSONPath=`.status.eventsProcessed`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// MonitoringPolicy is the Schema for the monitoringpolicies API.
// It configures real-time monitoring, event filtering, log analysis, and anomaly detection.
type MonitoringPolicy struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec MonitoringPolicySpec `json:"spec"`

	// +optional
	Status MonitoringPolicyStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// MonitoringPolicyList contains a list of MonitoringPolicy
type MonitoringPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []MonitoringPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&MonitoringPolicy{}, &MonitoringPolicyList{})
}
