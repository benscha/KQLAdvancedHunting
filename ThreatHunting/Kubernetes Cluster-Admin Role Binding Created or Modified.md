# *Kubernetes Cluster-Admin Role Binding Created or Modified*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1098 | Account Manipulation | https://attack.mitre.org/techniques/T1098 |
| T1098.003 | Additional Cloud Roles | https://attack.mitre.org/techniques/T1098/003 |

#### Description

Detects the creation or modification of RoleBindings or ClusterRoleBindings that grant 'cluster-admin' privileges. This behavior is a common indicator of privilege escalation or persistence within a Kubernetes cluster. The rule filters out known authorized service accounts used by common infrastructure tools like Flux and ArgoCD.

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
| where Verb in ("create", "update", "patch")
| where Resource in ("clusterrolebindings", "rolebindings")
| extend Namespace = tostring(RawEventData.objectRef.namespace), Binding = tostring(RawEventData.objectRef.name)
| extend User = tostring(RawEventData.user.username), SourceIp = tostring(RawEventData.sourceIPs[0])
| extend RequestObject = tostring(RawEventData.requestObject)
| where RequestObject has "cluster-admin" or Binding has "cluster-admin"
| where User !in (AllowedAdminUsers)
| project Timestamp, Detection="K8S cluster-admin binding change", User, SourceIp, Namespace, Binding, UserAgent, RequestObject, RawEventData
```
