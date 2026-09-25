# *Crypto-miner or Scanning Tool Execution in Kubernetes Container*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1559.001 | Active Scanning: Scanning IP Blocks | https://attack.mitre.org/techniques/T1559/001 |



#### Description

Detects the execution of known cryptocurrency miners or network scanning toolkits within a Kubernetes container. This activity often indicates unauthorized resource usage, persistence attempts, or reconnaissance within a containerized environment.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let Lookback = 1d;
CloudProcessEvents
| where Timestamp > ago(Lookback)
| where isnotempty(KubernetesPodName)
| extend Command = tolower(ProcessCommandLine), Proc = tolower(ProcessName)
| where Proc has_any ("xmrig", "kinsing", "masscan", "zmap", "nmap", "pnscan", "sqlmap", "zgrab")
	or Command has_any ("stratum+tcp", "minexmr", "nanopool", "moneroocean", "xmrig", "kinsing", "masscan", "zmap", "--open-only", "-p- --min-rate")
| project Timestamp, Detection="K8S miner or scanning toolkit", AzureResourceId, KubernetesNamespace, KubernetesPodName, ContainerName, ContainerImageName, AccountName, ParentProcessName, ProcessName, ProcessCommandLine, HostName
```
