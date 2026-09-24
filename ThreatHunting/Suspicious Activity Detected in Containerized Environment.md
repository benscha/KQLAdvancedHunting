# *Suspicious Activity Detected in Containerized Environment*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1611 | Escape to Host | https://attack.mitre.org/techniques/T1611 |
| T1552.001 | Credentials in Files | https://attack.mitre.org/techniques/T1552/001 |

#### Description

This rule monitors process execution within containers for a variety of high-fidelity suspicious behaviors, including container escape attempts, credential harvesting, resource hijacking (cryptomining), and unauthorized reconnaissance. It aggregates multiple distinct categories of malicious activity detected within a 30-minute window, triggering a 'Critical' severity alert when three or more distinct types of suspicious behaviors are identified for a specific container/pod.


#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
CloudProcessEvents
| where Timestamp > ago(1h)
| where ContainerName != "host" and isnotempty(ContainerId)
| extend AF = parse_json(tostring(AdditionalFields))
| extend Cat = case(
    ProcessCommandLine has "169.254.169.254" and FileName !endswith "xtables-nft-multi", "IMDS",
    ProcessCommandLine contains "secrets/kubernetes.io/serviceaccount", "SAToken",
    tostring(AF.UpperLayer) =~ "True" or tostring(AF.Memfd) =~ "True", "Drift",
    ProcessCommandLine has_any ("xmrig", "stratum+tcp", "allow_writes"), "Mining",
    ProcessCommandLine has_any ("modprobe", "insmod"), "KernelModule",
    ProcessCommandLine contains "ld.so.preload", "LdPreload",
    ProcessName in~ ("nmap", "masscan", "zmap", "kube-hunter", "peirates", "kubeletctl"), "Recon",
    ProcessCommandLine has_any (".git-credentials", ".aws/credentials", "AZURE_CREDENTIAL_FILE", "access_token",
                                "/etc/kubernetes/azure.json", ".kube/config"), "CredHunting",
    ProcessName =~ "chmod" and ProcessCommandLine has "+x", "MakeExecutable",
    ProcessCommandLine has_any ("/proc/1/root", "release_agent", "docker.sock", "nsenter"), "Escape",
    ProcessCommandLine contains "/dev/tcp/", "ReverseShell",
    "")
| where isnotempty(Cat)
| summarize Timestamp = min(Timestamp), LastSeen = max(Timestamp), ReportId = any(ReportId),
            Categories = make_set(Cat), CategoryCount = dcount(Cat),
            Evidence = make_set(ProcessCommandLine, 30)
    by AzureResourceId, KubernetesNamespace, KubernetesPodName, ContainerName, ContainerImageName, AccountName,
       TimeWindow = bin(Timestamp, 30m)
| where CategoryCount >= 3
| extend Severity = "Critical"
| project-away TimeWindow
```
