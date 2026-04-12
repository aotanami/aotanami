{{/*
Expand the name of the chart.
*/}}
{{- define "zelyo-policies.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "zelyo-policies.fullname" -}}
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
Chart label value.
*/}}
{{- define "zelyo-policies.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels applied to every CR.
*/}}
{{- define "zelyo-policies.labels" -}}
helm.sh/chart: {{ include "zelyo-policies.chart" . }}
app.kubernetes.io/name: {{ include "zelyo-policies.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: zelyo-operator
{{- with .Values.global.labels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Target namespace — uses global.namespace or falls back to release namespace.
*/}}
{{- define "zelyo-policies.namespace" -}}
{{- .Values.global.namespace | default .Release.Namespace }}
{{- end }}

{{/*
Resolve the effective profile for an environment.
If the env specifies a profile, use it; otherwise fall back to global.profile.
Usage: {{ include "zelyo-policies.resolveProfile" (dict "envProfile" .profile "globalProfile" $.Values.global.profile) }}
*/}}
{{- define "zelyo-policies.resolveProfile" -}}
{{- if .envProfile }}{{ .envProfile }}{{- else }}{{ .globalProfile }}{{- end }}
{{- end }}

{{/*
Map a profile name to a severity floor.
  starter  → high
  standard → medium
  strict   → low
*/}}
{{- define "zelyo-policies.profileSeverity" -}}
{{- if eq . "starter" }}high
{{- else if eq . "standard" }}medium
{{- else if eq . "strict" }}low
{{- else }}medium
{{- end }}
{{- end }}

{{/*
Generate the rules list for a SecurityPolicy based on the profile.
Outputs a YAML list of SecurityRule objects.

starter  — 4 core rules, all enforce: false (warn-only)
standard — all 8 rules, critical/high enforced, medium warned
strict   — all 8 rules, all enforced
*/}}
{{- define "zelyo-policies.profileRules" -}}
{{- if eq . "starter" }}
- name: security-context
  type: container-security-context
  enforce: false
- name: pod-security
  type: pod-security
  enforce: false
- name: resource-limits
  type: resource-limits
  enforce: false
- name: image-pinning
  type: image-vulnerability
  enforce: false
{{- else if eq . "standard" }}
- name: security-context
  type: container-security-context
  enforce: true
- name: pod-security
  type: pod-security
  enforce: true
- name: privilege-escalation
  type: privilege-escalation
  enforce: true
- name: resource-limits
  type: resource-limits
  enforce: true
- name: image-pinning
  type: image-vulnerability
  enforce: false
- name: secrets-exposure
  type: secrets-exposure
  enforce: false
- name: network-policy
  type: network-policy
  enforce: false
- name: rbac-audit
  type: rbac-audit
  enforce: false
{{- else if eq . "strict" }}
- name: security-context
  type: container-security-context
  enforce: true
- name: pod-security
  type: pod-security
  enforce: true
- name: privilege-escalation
  type: privilege-escalation
  enforce: true
- name: resource-limits
  type: resource-limits
  enforce: true
- name: image-pinning
  type: image-vulnerability
  enforce: true
- name: secrets-exposure
  type: secrets-exposure
  enforce: true
- name: network-policy
  type: network-policy
  enforce: true
- name: rbac-audit
  type: rbac-audit
  enforce: true
{{- else }}
{{- /* Default to standard */ -}}
- name: security-context
  type: container-security-context
  enforce: true
- name: pod-security
  type: pod-security
  enforce: true
- name: privilege-escalation
  type: privilege-escalation
  enforce: true
- name: resource-limits
  type: resource-limits
  enforce: true
- name: image-pinning
  type: image-vulnerability
  enforce: false
- name: secrets-exposure
  type: secrets-exposure
  enforce: false
- name: network-policy
  type: network-policy
  enforce: false
- name: rbac-audit
  type: rbac-audit
  enforce: false
{{- end }}
{{- end }}

{{/*
Collect enabled compliance frameworks valid for ClusterScan.
ClusterScan enum: cis, nsa-cisa, pci-dss, soc2, hipaa.
Note: nist-800-53 and iso-27001 are cloud-only and NOT valid here.
*/}}
{{- define "zelyo-policies.complianceFrameworks" -}}
{{- $frameworks := list }}
{{- if .Values.compliance.presets.cis }}
{{- $frameworks = append $frameworks "cis" }}
{{- end }}
{{- if .Values.compliance.presets.soc2 }}
{{- $frameworks = append $frameworks "soc2" }}
{{- end }}
{{- if .Values.compliance.presets.pciDss }}
{{- $frameworks = append $frameworks "pci-dss" }}
{{- end }}
{{- if .Values.compliance.presets.hipaa }}
{{- $frameworks = append $frameworks "hipaa" }}
{{- end }}
{{- toJson $frameworks }}
{{- end }}

{{/*
Collect enabled cloud compliance frameworks (uses cloud-specific names).
*/}}
{{- define "zelyo-policies.cloudComplianceFrameworks" -}}
{{- $frameworks := list }}
{{- if .Values.compliance.presets.soc2 }}
{{- $frameworks = append $frameworks "soc2" }}
{{- end }}
{{- if .Values.compliance.presets.pciDss }}
{{- $frameworks = append $frameworks "pci-dss" }}
{{- end }}
{{- if .Values.compliance.presets.hipaa }}
{{- $frameworks = append $frameworks "hipaa" }}
{{- end }}
{{- if .Values.compliance.presets.cis }}
{{- $frameworks = append $frameworks "cis-aws" }}
{{- end }}
{{- if .Values.compliance.presets.nist }}
{{- $frameworks = append $frameworks "nist-800-53" }}
{{- end }}
{{- if .Values.compliance.presets.iso27001 }}
{{- $frameworks = append $frameworks "iso-27001" }}
{{- end }}
{{- toJson $frameworks }}
{{- end }}
