# *Kubernetes Pod Accessing Service Account Tokens*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1613 | Container and Resource Discovery | https://attack.mitre.org/techniques/T1613 |
| T1059.013 | Container CLI/API | https://attack.mitre.org/techniques/T1059/023 |


#### Description

Detects instances where a process within a containerized application attempts to access Kubernetes service account tokens or related files (token, ca.crt, namespace). Accessing these files from non-authorized namespaces may indicate an attempt by a compromised container to gain unauthorized access to the Kubernetes API.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let Lookback = 1d;
let AllowedNamespaces = dynamic([
	"kube-system",
	"gatekeeper-system",
	"azure-arc",
	"calico-system",
	"cilium"
]);
CloudProcessEvents
| where Timestamp > ago(Lookback)
| where isnotempty(KubernetesPodName)
| extend Command = tolower(ProcessCommandLine)
| where Command has_any ("/var/run/secrets/kubernetes.io/serviceaccount/token", "serviceaccount/token", "serviceaccount/ca.crt", "serviceaccount/namespace")
| where KubernetesNamespace !in (AllowedNamespaces)
| project Timestamp, Detection="K8S service account token access", AzureResourceId, KubernetesNamespace, KubernetesPodName, ContainerName, ContainerImageName, AccountName, ParentProcessName, ProcessName, ProcessCommandLine, HostName
```
