# *Kubernetes Security Configuration Tampering*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1685 | Disable or Modify Tools | https://attack.mitre.org/techniques/T1685 |



#### Description

Detects modifications to Kubernetes security-critical resources such as NetworkPolicies, Admission Controllers, and security-related pods (e.g., Gatekeeper, Falco, Calico) via the Kubernetes API. The rule monitors for delete, update, or patch verbs and triggers when non-authorized service accounts perform these actions against sensitive resources or security-related objects.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let Lookback = 1d;
let AllowedAdminUsers = dynamic([
	"system:serviceaccount:flux-system:kustomize-controller",
	"system:serviceaccount:argocd:argocd-application-controller"
]);
CloudAuditEvents
| where Timestamp > ago(Lookback)
| where DataSource =~ "Kubernetes Audit"
| extend Verb = tolower(coalesce(tostring(RawEventData.verb), OperationName))
| extend Resource = tolower(tostring(RawEventData.objectRef.resource))
| extend Namespace = tostring(RawEventData.objectRef.namespace), ObjectName = tostring(RawEventData.objectRef.name)
| extend User = tostring(RawEventData.user.username), SourceIp = tostring(RawEventData.sourceIPs[0])
| where Verb in ("delete", "update", "patch")
| where Resource in ("networkpolicies", "validatingwebhookconfigurations", "mutatingwebhookconfigurations", "pods", "deployments", "daemonsets")
| where ObjectName has_any ("defender", "azuredefender", "mdc", "security", "gatekeeper", "kyverno", "falco", "calico", "cilium", "network-policy", "admission")
	or Resource in ("networkpolicies", "validatingwebhookconfigurations", "mutatingwebhookconfigurations")
| where User !in (AllowedAdminUsers)
| project Timestamp, Detection="K8S defense evasion against security controls", User, SourceIp, Namespace, Resource, ObjectName, UserAgent, RawEventData
```
