{{/*
Expand the name of the chart.
*/}}
{{- define "aotanami.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "aotanami.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "aotanami.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "aotanami.labels" -}}
helm.sh/chart: {{ include "aotanami.chart" . }}
{{ include "aotanami.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: aotanami
app.kubernetes.io/component: operator
{{- end }}

{{/*
Selector labels
*/}}
{{- define "aotanami.selectorLabels" -}}
app.kubernetes.io/name: {{ include "aotanami.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "aotanami.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "aotanami.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Webhook certificate secret name
*/}}
{{- define "aotanami.webhookCertSecret" -}}
{{- printf "%s-webhook-tls" (include "aotanami.fullname" .) }}
{{- end }}

{{/*
Webhook service name
*/}}
{{- define "aotanami.webhookServiceName" -}}
{{- printf "%s-webhook" (include "aotanami.fullname" .) }}
{{- end }}

{{/*
Metrics service name
*/}}
{{- define "aotanami.metricsServiceName" -}}
{{- printf "%s-metrics" (include "aotanami.fullname" .) }}
{{- end }}

{{/*
Namespace — always use release namespace
*/}}
{{- define "aotanami.namespace" -}}
{{- .Release.Namespace }}
{{- end }}
