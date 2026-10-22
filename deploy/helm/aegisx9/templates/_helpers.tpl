{{- define "aegisx9.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "aegisx9.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "aegisx9.labels" -}}
app.kubernetes.io/name: {{ include "aegisx9.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: aegisx9
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "aegisx9.selectorLabels" -}}
app.kubernetes.io/name: {{ include "aegisx9.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "aegisx9.opsSelectorLabels" -}}
app.kubernetes.io/name: {{ include "aegisx9.name" . }}-ops
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "aegisx9.serviceAccountName" -}}
{{- default (include "aegisx9.fullname" .) .Values.serviceAccount.name -}}
{{- end -}}

{{- define "aegisx9.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ .Values.image.tag }}
{{- end -}}
{{- end -}}

{{/* Names of models routed through the federation broker, as a JSON array. */}}
{{- define "aegisx9.wifModels" -}}
{{- $names := list -}}
{{- range .Values.gateway.models -}}
{{- if .wif -}}
{{- $names = append $names .name -}}
{{- end -}}
{{- end -}}
{{- $names | toJson -}}
{{- end -}}

{{/* Restricted container security context shared by every container in the chart. */}}
{{- define "aegisx9.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: true
privileged: false
capabilities:
  drop: ["ALL"]
{{- end -}}

{{/* Environment of the budget jobs. The admin key comes from the Secret by reference. */}}
{{- define "aegisx9.opsJobEnv" -}}
env:
  - name: AEGISX9_GATEWAY_URL
    value: {{ printf "http://%s:%v" (include "aegisx9.fullname" .) .Values.service.port | quote }}
  - name: AEGISX9_BUDGET_PLAN
    value: /etc/aegisx9-budgets/plan.json
  - name: LITELLM_MASTER_KEY
    valueFrom:
      secretKeyRef:
        name: {{ .Values.existingSecret }}
        key: LITELLM_MASTER_KEY
{{- end -}}

{{/* Restricted pod security context shared by every pod in the chart. */}}
{{- define "aegisx9.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 10001
runAsGroup: 10001
fsGroup: 10001
seccompProfile:
  type: RuntimeDefault
{{- end -}}
