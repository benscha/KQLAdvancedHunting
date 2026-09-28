# *Azure Kubernetes Service Pod Accessing Instance Metadata API*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1552.005 | Cloud Instance Metadata API | https://attack.mitre.org/techniques/T1552/005 |
| T1528 | Steal Application Access Token | https://attack.mitre.org/techniques/T1528 |

#### Description

This rule detects potentially malicious behavior where a Kubernetes pod in an AKS cluster attempts to access the Azure Instance Metadata Service (IMDS) at 169.254.169.254 or specifically requests Azure identity tokens. It then correlates this with Azure Activity logs to identify if the associated Managed Identity is performing operations from unauthorized IP addresses, signaling potential token theft or unauthorized use of cloud credentials.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let Lookback = 1d;
let AllowedNamespaces = dynamic(["kube-system", "gatekeeper-system", "calico-system"]);
let AksEgressRanges = dynamic(["20.0.0.10/32", "10.0.0.0/8"]);   // LB/NAT Gateway Outbound IPs + interne Ranges
let ClusterIdentities = datatable(ClusterResourceId:string, IdentityObjectId:string, IdentityType:string)[
    "/subscriptions/<sub>/resourcegroups/<rg>/providers/microsoft.containerservice/managedclusters/<aks>", "<kubelet-mi-objectid>", "Kubelet",
    "/subscriptions/<sub>/resourcegroups/<rg>/providers/microsoft.containerservice/managedclusters/<aks>", "<workload-mi-objectid>", "WorkloadIdentity"
];   // besser als Watchlist pflegen
let PodTokenAccess = CloudProcessEvents
| where Timestamp > ago(Lookback)
| where isnotempty(KubernetesPodName) and KubernetesNamespace !in (AllowedNamespaces)
| extend Cmd = tolower(ProcessCommandLine)
| where (Cmd has "169.254.169.254" and Cmd has_any ("metadata/identity", "oauth2"))
     or Cmd has "azure-identity-token"
| summarize FirstPodAccess = min(Timestamp),
            Pods = make_set(strcat(KubernetesNamespace, "/", KubernetesPodName), 20),
            TokenCmds = make_set(ProcessCommandLine, 10)
    by ClusterResourceId = tolower(AzureResourceId);
AzureActivity
| where TimeGenerated > ago(Lookback)
| join kind=inner (ClusterIdentities | extend ClusterResourceId = tolower(ClusterResourceId))
    on $left.Caller == $right.IdentityObjectId
| where isnotempty(CallerIpAddress) and not(ipv4_is_in_any_range(CallerIpAddress, AksEgressRanges))
| summarize FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
            Operations = make_set(OperationNameValue, 30),
            TargetResources = dcount(_ResourceId),
            CallerIps = make_set(CallerIpAddress, 10)
    by Caller, IdentityType, ClusterResourceId
| join kind=leftouter PodTokenAccess on ClusterResourceId
| extend Severity = iff(isnotempty(Pods) and FirstPodAccess <= LastSeen, "High", "Medium")
```
