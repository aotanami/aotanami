{{/*
Expand the name of the chart.
*/}}
{{- define "zelyo-operator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "zelyo-operator.fullname" -}}
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
{{- define "zelyo-operator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "zelyo-operator.labels" -}}
helm.sh/chart: {{ include "zelyo-operator.chart" . }}
{{ include "zelyo-operator.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: zelyo-operator
app.kubernetes.io/component: operator
{{- end }}

{{/*
Selector labels
*/}}
{{- define "zelyo-operator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "zelyo-operator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "zelyo-operator.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "zelyo-operator.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Webhook certificate secret name
*/}}
{{- define "zelyo-operator.webhookCertSecret" -}}
{{- printf "%s-webhook-tls" (include "zelyo-operator.fullname" .) }}
{{- end }}

{{/*
Webhook service name
*/}}
{{- define "zelyo-operator.webhookServiceName" -}}
{{- printf "%s-webhook" (include "zelyo-operator.fullname" .) }}
{{- end }}

{{/*
Metrics service name
*/}}
{{- define "zelyo-operator.metricsServiceName" -}}
{{- printf "%s-metrics" (include "zelyo-operator.fullname" .) }}
{{- end }}

{{/*
Namespace — always use release namespace
*/}}
{{- define "zelyo-operator.namespace" -}}
{{- .Release.Namespace }}
{{- end }}
