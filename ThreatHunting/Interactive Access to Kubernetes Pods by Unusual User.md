# *Interactive Access to Kubernetes Pods by Unusual User*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1609| Container Administration Command | https://attack.mitre.org/techniques/T1609 |


#### Description

This rule monitors Kubernetes audit logs for interactive access events such as exec, attach, or port-forwarding against pods. It alerts on these activities when performed by entities other than known, legitimate service accounts like the Kustomize or ArgoCD controllers, which may indicate unauthorized administrative access or lateral movement within a cluster.

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
| extend Resource = tolower(tostring(RawEventData.objectRef.resource)), SubResource = tolower(tostring(RawEventData.objectRef.subresource))
| where Resource == "pods" and SubResource in ("exec", "attach", "portforward")
| extend Namespace = tostring(RawEventData.objectRef.namespace), PodName = tostring(RawEventData.objectRef.name)
| extend User = tostring(RawEventData.user.username), SourceIp = tostring(RawEventData.sourceIPs[0])
| where User !in (AllowedAdminUsers)
| project Timestamp, Detection="K8S interactive pod access", User, SourceIp, Namespace, PodName, SubResource, UserAgent, RawEventData
```
