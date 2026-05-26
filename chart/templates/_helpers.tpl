{{- define "assessment.name" -}}assessment{{- end -}}

{{- define "assessment.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "assessment.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "assessment.labels" -}}
app.kubernetes.io/name: {{ include "assessment.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "assessment.selectorLabels" -}}
app.kubernetes.io/name: {{ include "assessment.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "assessment.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}

{{- define "assessment.databaseSecretName" -}}
{{- if .Values.postgres.cnpg.enabled -}}
{{ include "assessment.fullname" . }}-pg-app
{{- else -}}
{{ include "assessment.fullname" . }}-external-db
{{- end -}}
{{- end -}}
