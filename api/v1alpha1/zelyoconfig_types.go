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

// ZelyoConfigSpec defines the desired state of ZelyoConfig.
// ZelyoConfig is the global configuration resource for the Zelyo Operator operator.
// Only one ZelyoConfig resource should exist per cluster.
type ZelyoConfigSpec struct {
	// mode sets the default operating mode for the operator.
	// +kubebuilder:validation:Enum=audit;protect
	// +kubebuilder:default=audit
	// +optional
	Mode string `json:"mode,omitempty"`

	// llm configures the LLM provider for AI-powered diagnosis and remediation.
	// +required
	LLM LLMConfig `json:"llm"`

	// dashboard configures the embedded web dashboard.
	// +optional
	Dashboard DashboardConfig `json:"dashboard,omitempty"`

	// github configures the GitHub App integration for PR-based remediation.
	// +optional
	GitHub *GitHubConfig `json:"github,omitempty"`

	// tokenBudget configures token usage limits to control LLM API costs.
	// +optional
	TokenBudget TokenBudgetConfig `json:"tokenBudget,omitempty"`

	// multiCluster enables multi-cluster federation.
	// +optional
	MultiCluster *MultiClusterConfig `json:"multiCluster,omitempty"`

	// telemetry configures metrics and tracing export.
	// +optional
	Telemetry TelemetryConfig `json:"telemetry,omitempty"`
}

// LLMConfig configures the LLM provider.
type LLMConfig struct {
	// provider identifies the LLM service provider.
	// +kubebuilder:validation:Enum=openrouter;openai;anthropic;azure-openai;ollama;custom
	// +required
	Provider string `json:"provider"`

	// model is the model identifier (e.g., "anthropic/claude-sonnet-4-20250514", "gpt-4o").
	// +required
	Model string `json:"model"`

	// apiKeySecret is the name of the Kubernetes Secret containing the API key.
	// The key within the secret should be named "api-key".
	// +required
	APIKeySecret string `json:"apiKeySecret"`

	// endpoint is a custom API endpoint URL. Required for 'custom' and 'ollama' providers.
	// +optional
	Endpoint string `json:"endpoint,omitempty"`

	// temperature controls the randomness of LLM outputs (0.0 = deterministic, 1.0 = creative).
	// Valid range: 0.0 to 2.0. If not set, defaults to provider default.
	// +optional
	Temperature *float64 `json:"temperature,omitempty"`

	// maxTokensPerRequest limits the max tokens per individual LLM request.
	// +kubebuilder:validation:Minimum=100
	// +kubebuilder:default=4096
	// +optional
	MaxTokensPerRequest int32 `json:"maxTokensPerRequest,omitempty"`
}

// TokenBudgetConfig configures LLM token budget limits.
type TokenBudgetConfig struct {
	// hourlyTokenLimit is the max tokens per hour. 0 means unlimited.
	// +kubebuilder:default=50000
	// +optional
	HourlyTokenLimit int64 `json:"hourlyTokenLimit,omitempty"`

	// dailyTokenLimit is the max tokens per day. 0 means unlimited.
	// +kubebuilder:default=500000
	// +optional
	DailyTokenLimit int64 `json:"dailyTokenLimit,omitempty"`

	// monthlyTokenLimit is the max tokens per month. 0 means unlimited.
	// +kubebuilder:default=10000000
	// +optional
	MonthlyTokenLimit int64 `json:"monthlyTokenLimit,omitempty"`

	// alertThresholdPercent triggers a notification when usage reaches this percentage of the limit.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	// +kubebuilder:default=80
	// +optional
	AlertThresholdPercent int32 `json:"alertThresholdPercent,omitempty"`

	// enableCaching enables prompt/response caching to reduce redundant LLM calls.
	// +kubebuilder:default=true
	// +optional
	EnableCaching bool `json:"enableCaching,omitempty"`

	// batchingEnabled enables batching of multiple findings into single LLM calls.
	// +kubebuilder:default=true
	// +optional
	BatchingEnabled bool `json:"batchingEnabled,omitempty"`
}

// DashboardConfig configures the embedded dashboard.
type DashboardConfig struct {
	// enabled toggles the embedded dashboard.
	// +kubebuilder:default=true
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// port is the HTTP port for the dashboard.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +kubebuilder:default=8080
	// +optional
	Port int32 `json:"port,omitempty"`

	// basePath is the URL path prefix for the dashboard (e.g., "/dashboard").
	// +kubebuilder:default="/"
	// +optional
	BasePath string `json:"basePath,omitempty"`
}

// GitHubConfig configures GitHub App integration.
type GitHubConfig struct {
	// appID is the GitHub App installation ID.
	// +required
	AppID int64 `json:"appID"`

	// installationID is the GitHub App installation ID for the target organization.
	// +required
	InstallationID int64 `json:"installationID"`

	// privateKeySecret is the name of the Secret containing the GitHub App private key.
	// +required
	PrivateKeySecret string `json:"privateKeySecret"`
}

// MultiClusterConfig configures multi-cluster federation.
type MultiClusterConfig struct {
	// enabled toggles multi-cluster mode.
	// +kubebuilder:default=false
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// clusterName is the unique name of this cluster in the federation.
	// +optional
	ClusterName string `json:"clusterName,omitempty"`

	// hubEndpoint is the API endpoint of the hub cluster for aggregation.
	// +optional
	HubEndpoint string `json:"hubEndpoint,omitempty"`
}

// TelemetryConfig configures observability export.
type TelemetryConfig struct {
	// prometheusEnabled enables Prometheus metrics export.
	// +kubebuilder:default=true
	// +optional
	PrometheusEnabled bool `json:"prometheusEnabled,omitempty"`

	// otelEnabled enables OpenTelemetry tracing.
	// +kubebuilder:default=false
	// +optional
	OTELEnabled bool `json:"otelEnabled,omitempty"`

	// otelEndpoint is the OTLP collector endpoint.
	// +optional
	OTELEndpoint string `json:"otelEndpoint,omitempty"`
}

// ZelyoConfigStatus defines the observed state of ZelyoConfig.
type ZelyoConfigStatus struct {
	// observedGeneration is the most recent generation observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// phase indicates the current agent lifecycle phase.
	// +kubebuilder:validation:Enum=Initializing;Active;Degraded;Error
	// +optional
	Phase string `json:"phase,omitempty"`

	// mode is the currently active operating mode.
	// +optional
	ActiveMode string `json:"activeMode,omitempty"`

	// tokenUsage tracks current LLM token consumption.
	// +optional
	TokenUsage TokenUsageStatus `json:"tokenUsage,omitempty"`

	// lastReconciled is when the config was last reconciled.
	// +optional
	LastReconciled *metav1.Time `json:"lastReconciled,omitempty"`

	// conditions represent the current state of the resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// TokenUsageStatus tracks LLM token consumption.
type TokenUsageStatus struct {
	// tokensUsedToday is the token count for the current day.
	// +optional
	TokensUsedToday int64 `json:"tokensUsedToday,omitempty"`

	// tokensUsedThisMonth is the token count for the current month.
	// +optional
	TokensUsedThisMonth int64 `json:"tokensUsedThisMonth,omitempty"`

	// estimatedCostUSD is the estimated cost based on provider pricing.
	// +optional
	EstimatedCostUSD string `json:"estimatedCostUSD,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="LLM Provider",type=string,JSONPath=`.spec.llm.provider`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ZelyoConfig is the Schema for the zelyoconfigs API.
// It is the global configuration resource for the Zelyo Operator operator.
type ZelyoConfig struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec ZelyoConfigSpec `json:"spec"`

	// +optional
	Status ZelyoConfigStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// ZelyoConfigList contains a list of ZelyoConfig
type ZelyoConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []ZelyoConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ZelyoConfig{}, &ZelyoConfigList{})
}
