# *New Unusual Process Execution in Container*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059 | Command and Scripting Interpreter | https://attack.mitre.org/techniques/T1059 |
| T1059.004 | Unix Shell | https://attack.mitre.org/techniques/T1059/004 |

#### Description

Detects the execution of previously unseen processes within container environments. It identifies processes that have not been observed in the last 14 days and focuses on those running under shells like sh, bash, or zsh, flagging them with higher severity. This is useful for identifying unexpected or malicious behavior in container workloads.


#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### Possible false positives
- A system administrator or a dedicated service account runs a scheduled script, a software deployment patch, or a vulnerability scan across the network.
- Helpdesk Escalation or On-Call Shift Support
- IT Administrative "Jump Boxes"

## Defender XDR
```KQL
let Lookback = 14d;
let DetectWindow = 1h;
let Container = CloudProcessEvents
    | where Timestamp > ago(Lookback)
    | where ContainerName != "host" and isnotempty(ContainerId)
    | extend ImageRepo = tostring(split(ContainerImageName, ":")[0]);
let Known = Container
    | where Timestamp < ago(DetectWindow)
    | summarize by ImageRepo, ProcessName;
let ImagesWithHistory = Container
    | where Timestamp < ago(1d)
    | summarize by ImageRepo;       // nur Images mit mind. 1 Tag Historie bewerten (Rollouts ausklammern)
Container
| where Timestamp > ago(DetectWindow)
| join kind=inner ImagesWithHistory on ImageRepo
| join kind=leftanti Known on ImageRepo, ProcessName
| extend ShellParent = ParentProcessName in~ ("sh", "bash", "dash", "ash", "zsh", "busybox")
| extend Severity = iff(ShellParent, "High", "Medium")
| summarize Timestamp = min(Timestamp), ReportId = any(ReportId), NewProcesses = make_set(ProcessName, 20),
            CommandLines = make_set(ProcessCommandLine, 20), Severity = max(Severity)
    by AzureResourceId, KubernetesNamespace, KubernetesPodName, ContainerName, ImageRepo, AccountName
```
