# *Kubernetes Privileged or Host-Sensitive Workload Creation*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1610 | Deploy Container | https://attack.mitre.org/techniques/T1610 |
| T1611 | Escape to Host | https://attack.mitre.org/techniques/T1611 |

#### Description

This rule detects the creation, update, or patching of Kubernetes workloads that request privileged capabilities or sensitive host access, such as host networking, PID/IPC namespaces, access to container runtimes, or sensitive security contexts. These configurations can be abused by adversaries to achieve container escape or host compromise.

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
// Privileged workload or host access created/updated
CloudAuditEvents
| where Timestamp > ago(Lookback)
| where DataSource =~ "Kubernetes Audit"
| extend Verb = tolower(coalesce(tostring(RawEventData.verb), OperationName))
| extend Resource = tolower(tostring(RawEventData.objectRef.resource))
| where Verb in ("create", "update", "patch")
| where Resource in ("pods", "deployments", "daemonsets", "statefulsets", "replicasets", "jobs", "cronjobs")
| extend Namespace = tostring(RawEventData.objectRef.namespace), Workload = tostring(RawEventData.objectRef.name)
| extend User = tostring(RawEventData.user.username), SourceIp = tostring(RawEventData.sourceIPs[0])
| extend RequestObject = tostring(RawEventData.requestObject)
| where RequestObject has_any ("\"privileged\":true", "\"hostNetwork\":true", "\"hostPID\":true", "\"hostIPC\":true", "\"hostPath\"", "/var/run/docker.sock", "/run/containerd/containerd.sock", "/var/lib/kubelet", "\"SYS_ADMIN\"", "\"NET_ADMIN\"", "\"SYS_PTRACE\"")
| where User !in (AllowedAdminUsers)
| project Timestamp, Detection="K8S privileged or host-access workload", User, SourceIp, Namespace, Resource, Workload, UserAgent, RequestObject, RawEventData
```
