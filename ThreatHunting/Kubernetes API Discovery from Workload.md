# *Kubernetes API Discovery from Workload*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1613 | Container and Resource Discovery | https://attack.mitre.org/techniques/T1613 |
| T1059.013 | Container CLI/API | https://attack.mitre.org/techniques/T1059/023 |


#### Description

Detects anomalous attempts by a containerized workload to perform Kubernetes API discovery or interact with the cluster control plane via common CLI tools (kubectl) or API endpoints (curl, internal SVC discovery). This behavior may indicate an attacker attempting to map the cluster infrastructure for further exploitation or lateral movement.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
// 6. Kubernetes API discovery from inside a workload
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
| where Command has_any ("kubernetes.default.svc", "kubectl get", "kubectl auth", "kubectl describe", "kubectl api-resources", "curl -k https://kubernetes", "https://10.")
| where KubernetesNamespace !in (AllowedNamespaces)
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Commands=make_set(ProcessCommandLine, 10), ProcessNames=make_set(ProcessName, 10) by AzureResourceId, KubernetesNamespace, KubernetesPodName, ContainerName, ContainerImageName, AccountName, HostName
| project FirstSeen, LastSeen, Detection="K8S API discovery from workload", AzureResourceId, KubernetesNamespace, KubernetesPodName, ContainerName, ContainerImageName, AccountName, HostName, ProcessNames, Commands
```
