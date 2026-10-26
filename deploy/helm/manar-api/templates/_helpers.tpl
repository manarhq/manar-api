{{/*
Expand the name of the chart.
*/}}
{{- define "manar-api.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "manar-api.fullname" -}}
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
{{- define "manar-api.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "manar-api.labels" -}}
helm.sh/chart: {{ include "manar-api.chart" . }}
{{ include "manar-api.selectorLabels" . }}
app.kubernetes.io/part-of: manar
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "manar-api.selectorLabels" -}}
app.kubernetes.io/name: {{ include "manar-api.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "manar-api.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "manar-api.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Name of the credentials Secret.
*/}}
{{- define "manar-api.secretName" -}}
{{- default (printf "%s-secrets" (include "manar-api.fullname" .)) .Values.secrets.name }}
{{- end }}

{{/*
Name of the agent-mTLS cert/key/CA Secret.
*/}}
{{- define "manar-api.agentMtlsCertsSecretName" -}}
{{- default (printf "%s-agent-mtls-certs" (include "manar-api.fullname" .)) .Values.agentMtls.certs.name }}
{{- end }}

{{/*
Container image: repository@digest when image.digest is set, else
repository:tag (tag defaults to the chart appVersion).
*/}}
{{- define "manar-api.image" -}}
{{- if .Values.image.digest }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) }}
{{- end }}
{{- end }}

{{/*
Labels for the migration Job and its pod. app.kubernetes.io/name differs from
selectorLabels, so the Deployment, Service, PDB and NetworkPolicy never select it.
*/}}
{{- define "manar-api.migrationLabels" -}}
helm.sh/chart: {{ include "manar-api.chart" . }}
app.kubernetes.io/name: {{ printf "%s-migrate" (include "manar-api.name" .) | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: migration
app.kubernetes.io/part-of: manar
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}
