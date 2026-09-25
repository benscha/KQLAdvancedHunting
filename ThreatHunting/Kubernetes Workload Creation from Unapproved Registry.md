# *Kubernetes Workload Creation from Unapproved Registry*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1610 | Deploy Container | https://attack.mitre.org/techniques/T1610 |
| T1204.003 | Malicious Image | https://attack.mitre.org/techniques/T1204/003 |



#### Description

This rule monitors Kubernetes audit logs for the creation, update, or patching of core workload resources (pods, deployments, etc.) that utilize container images from unapproved registries. It enforces image registry allowlisting and ensures that workload modifications are performed by authorized service accounts.

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
let AllowedRegistries = dynamic([
	"mcr.microsoft.com/",
	"ghcr.io/your-org/"
]);
CloudAuditEvents
| where Timestamp > ago(Lookback)
| where DataSource =~ "Kubernetes Audit"
| extend Verb = tolower(coalesce(tostring(RawEventData.verb), OperationName))
| extend Resource = tolower(tostring(RawEventData.objectRef.resource))
| where Verb in ("create", "update", "patch")
| where Resource in ("pods", "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs")
| extend Namespace = tostring(RawEventData.objectRef.namespace), Workload = tostring(RawEventData.objectRef.name)
| extend User = tostring(RawEventData.user.username), SourceIp = tostring(RawEventData.sourceIPs[0])
| extend RequestObject = tostring(RawEventData.requestObject)
| extend Images = extract_all(@'"image"\s*:\s*"([^"]+)"', RequestObject)
| mv-expand Image = Images to typeof(string)
| extend ImageLower = tolower(Image)
| where not(ImageLower startswith tostring(AllowedRegistries[0]) or ImageLower startswith tostring(AllowedRegistries[1]) or ImageLower startswith tostring(AllowedRegistries[2]))
| where ImageLower has_any (":latest", "docker.io/", "public.ecr.aws/", "quay.io/") or User !in (AllowedAdminUsers)
| project Timestamp, Detection="K8S workload from unapproved registry", User, SourceIp, Namespace, Resource, Workload, Image, UserAgent, RawEventData
```
