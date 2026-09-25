# *Kubernetes Secret Enumeration by Non-Admin Identity*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1087 | Account Discovery | https://attack.mitre.org/techniques/T1087 |
| T1552.007 | Container API | https://attack.mitre.org/techniques/T1552/007 |

#### Description

Detects anomalous Kubernetes API activity where a non-administrative user or service account accesses or lists multiple secret objects across different namespaces within a short timeframe. This behavior is indicative of an attacker attempting to discover sensitive credentials stored within the cluster.

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
// Secret enumeration by non-admin identity
CloudAuditEvents
| where Timestamp > ago(Lookback)
| where DataSource =~ "Kubernetes Audit"
| extend Verb = tolower(coalesce(tostring(RawEventData.verb), OperationName))
| extend Resource = tolower(tostring(RawEventData.objectRef.resource))
| where Resource == "secrets"
| where Verb in ("get", "list", "watch")
| extend Namespace = tostring(RawEventData.objectRef.namespace), SecretName = tostring(RawEventData.objectRef.name)
| extend User = tostring(RawEventData.user.username), SourceIp = tostring(RawEventData.sourceIPs[0])
| where User !in (AllowedAdminUsers)
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), SecretCount=dcount(SecretName), Namespaces=dcount(Namespace), Secrets=make_set(SecretName, 20), UserAgents=make_set(UserAgent, 5) by User, SourceIp
| where SecretCount >= 5 or Namespaces >= 2
| project FirstSeen, LastSeen, Detection="K8S secret enumeration", User, SourceIp, SecretCount, Namespaces, Secrets, UserAgents
```
