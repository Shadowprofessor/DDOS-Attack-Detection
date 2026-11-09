{{/*
Expand the name of the chart.
*/}}
{{- define "ddos-defense.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "ddos-defense.fullname" -}}
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
Common labels
*/}}
{{- define "ddos-defense.labels" -}}
helm.sh/chart: {{ include "ddos-defense.name" . }}-{{ .Chart.Version | replace "+" "_" }}
{{ include "ddos-defense.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "ddos-defense.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ddos-defense.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
