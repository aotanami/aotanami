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

// NotificationChannelSpec defines the desired state of NotificationChannel.
// A NotificationChannel configures a destination for alerts and reports.
type NotificationChannelSpec struct {
	// type identifies the notification provider.
	// +kubebuilder:validation:Enum=slack;msteams;pagerduty;alertmanager;telegram;whatsapp;webhook;email
	// +required
	Type string `json:"type"`

	// credentialSecret is the name of the Kubernetes Secret containing provider credentials.
	// The secret must exist in the same namespace as the NotificationChannel.
	// +required
	CredentialSecret string `json:"credentialSecret"`

	// severityFilter only sends notifications for findings at or above this severity level.
	// +kubebuilder:validation:Enum=critical;high;medium;low;info
	// +kubebuilder:default=medium
	// +optional
	SeverityFilter string `json:"severityFilter,omitempty"`

	// rateLimit configures notification throttling.
	// +optional
	RateLimit RateLimitConfig `json:"rateLimit,omitempty"`

	// slack contains Slack-specific configuration.
	// +optional
	Slack *SlackConfig `json:"slack,omitempty"`

	// msTeams contains Microsoft Teams-specific configuration.
	// +optional
	MSTeams *MSTeamsConfig `json:"msTeams,omitempty"`

	// pagerDuty contains PagerDuty-specific configuration.
	// +optional
	PagerDuty *PagerDutyConfig `json:"pagerDuty,omitempty"`

	// alertManager contains AlertManager-specific configuration.
	// +optional
	AlertManager *AlertManagerConfig `json:"alertManager,omitempty"`

	// telegram contains Telegram-specific configuration.
	// +optional
	Telegram *TelegramConfig `json:"telegram,omitempty"`

	// whatsApp contains WhatsApp-specific configuration.
	// +optional
	WhatsApp *WhatsAppConfig `json:"whatsApp,omitempty"`

	// webhook contains generic webhook configuration.
	// +optional
	Webhook *WebhookConfig `json:"webhook,omitempty"`

	// email contains email configuration.
	// +optional
	Email *EmailConfig `json:"email,omitempty"`
}

// RateLimitConfig configures notification throttling.
type RateLimitConfig struct {
	// maxPerHour is the maximum number of notifications per hour. 0 means unlimited.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:default=60
	// +optional
	MaxPerHour int32 `json:"maxPerHour,omitempty"`

	// aggregateSeconds groups alerts within this window into a single notification.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:default=30
	// +optional
	AggregateSeconds int32 `json:"aggregateSeconds,omitempty"`
}

// SlackConfig contains Slack-specific settings.
type SlackConfig struct {
	// channel is the Slack channel to send notifications to (e.g., #zelyo-operator-alerts).
	// +required
	Channel string `json:"channel"`
}

// MSTeamsConfig contains Microsoft Teams-specific settings.
type MSTeamsConfig struct {
	// webhookURL key in the credential secret that contains the Teams webhook URL.
	// +kubebuilder:default="webhook-url"
	// +optional
	WebhookURLKey string `json:"webhookURLKey,omitempty"`
}

// PagerDutyConfig contains PagerDuty-specific settings.
type PagerDutyConfig struct {
	// routingKey key in the credential secret for PagerDuty event routing.
	// +kubebuilder:default="routing-key"
	// +optional
	RoutingKeyKey string `json:"routingKeyKey,omitempty"`

	// severity mapping from Zelyo Operator severity to PagerDuty severity.
	// +kubebuilder:validation:Enum=critical;error;warning;info
	// +kubebuilder:default=error
	// +optional
	DefaultSeverity string `json:"defaultSeverity,omitempty"`
}

// AlertManagerConfig contains AlertManager-specific settings.
type AlertManagerConfig struct {
	// endpoint is the AlertManager API endpoint.
	// +required
	Endpoint string `json:"endpoint"`

	// tlsInsecureSkipVerify skips TLS verification. Use only in development.
	// +kubebuilder:default=false
	// +optional
	TLSInsecureSkipVerify bool `json:"tlsInsecureSkipVerify,omitempty"`
}

// TelegramConfig contains Telegram-specific settings.
type TelegramConfig struct {
	// chatID is the Telegram chat ID to send messages to.
	// +required
	ChatID string `json:"chatID"`
}

// WhatsAppConfig contains WhatsApp-specific settings.
type WhatsAppConfig struct {
	// phoneNumber is the WhatsApp phone number to send messages to (with country code).
	// +required
	PhoneNumber string `json:"phoneNumber"`
}

// WebhookConfig contains generic webhook settings.
type WebhookConfig struct {
	// url is the HTTP(S) endpoint to POST notifications to.
	// +required
	URL string `json:"url"`

	// headers are additional HTTP headers to include in requests.
	// +optional
	Headers map[string]string `json:"headers,omitempty"`

	// tlsInsecureSkipVerify skips TLS verification.
	// +kubebuilder:default=false
	// +optional
	TLSInsecureSkipVerify bool `json:"tlsInsecureSkipVerify,omitempty"`
}

// EmailConfig contains email notification settings.
type EmailConfig struct {
	// recipients is the list of email addresses to send notifications to.
	// +kubebuilder:validation:MinItems=1
	// +required
	Recipients []string `json:"recipients"`

	// smtpHost is the SMTP server hostname.
	// +required
	SMTPHost string `json:"smtpHost"`

	// smtpPort is the SMTP server port.
	// +kubebuilder:default=587
	// +optional
	SMTPPort int32 `json:"smtpPort,omitempty"`

	// fromAddress is the sender email address.
	// +required
	FromAddress string `json:"fromAddress"`
}

// NotificationChannelStatus defines the observed state of NotificationChannel.
type NotificationChannelStatus struct {
	// phase indicates the current channel state.
	// +kubebuilder:validation:Enum=Pending;Active;Error
	// +optional
	Phase string `json:"phase,omitempty"`

	// lastSentAt is the timestamp of the last notification sent.
	// +optional
	LastSentAt *metav1.Time `json:"lastSentAt,omitempty"`

	// notificationsSent is the total count of notifications sent.
	// +optional
	NotificationsSent int64 `json:"notificationsSent,omitempty"`

	// lastError describes the most recent error, if any.
	// +optional
	LastError string `json:"lastError,omitempty"`

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
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.type`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Sent",type=integer,JSONPath=`.status.notificationsSent`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// NotificationChannel is the Schema for the notificationchannels API.
// It configures a destination for Zelyo Operator alerts and reports.
type NotificationChannel struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec NotificationChannelSpec `json:"spec"`

	// +optional
	Status NotificationChannelStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// NotificationChannelList contains a list of NotificationChannel
type NotificationChannelList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []NotificationChannel `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NotificationChannel{}, &NotificationChannelList{})
}
