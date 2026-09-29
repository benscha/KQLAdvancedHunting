# Suspicious Credential Access and Process Memory Enumeration in Kubernetes Containers*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1552 | Unsecured Credentials | https://attack.mitre.org/techniques/T1552 |
| T1555 | Credentials from Password Stores | https://attack.mitre.org/techniques/T1555 |
| T1003.007 | Proc Filesystemv | https://attack.mitre.org/techniques/T1003/007 |
| T1083 | File and Directory Discovery | https://attack.mitre.org/techniques/T1083 |

#### Description

Detects anomalous shell process execution originating from common web application processes within a containerized environment. The rule uses behavioral indicators such as parent-child process relationships, network-related command execution, file system reconnaissance, and suspicious utility usage to calculate a risk score for newly observed or suspicious shell activity.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let Lookback = 1d;
let AllowedImages = dynamic(["datadog", "dynatrace", "newrelic", "falco", "otel", "fluent", "ama-logs", "omsagent", "microsoft-defender"]);
CloudProcessEvents
| where Timestamp > ago(Lookback)
| where isnotempty(KubernetesPodName) or ContainerName == "host"
| where not(ContainerImageName has_any (AllowedImages))
| extend Cmd = tolower(ProcessCommandLine), P = tolower(ProcessName)
| extend Technique = case(
    Cmd matches regex @"/proc/(\d+|\*)/environ", "ProcEnvironOtherProcess",
    Cmd matches regex @"/proc/(\d+|\*)/root/", "ProcRootTraversal",
    Cmd matches regex @"/proc/(\d+|\*)/(mem|maps)\b" or P in ("gdb", "gcore"), "ProcessMemoryAccess",
    Cmd has_any ("/etc/kubernetes/azure.json", "/etc/kubernetes/kubelet.conf", "/var/lib/kubelet/kubeconfig",
                 "/var/lib/kubelet/pki", "/etc/kubernetes/pki", "/etc/kubernetes/certs"), "NodeCredentialFiles",
    Cmd has_any (".kube/config", ".azure/msal_token_cache", ".azure/accesstokens.json", ".docker/config.json",
                 ".aws/credentials", ".git-credentials"), "UserCredentialFiles",
    Cmd matches regex @"\b(env|printenv)\b.*\|\s*e?grep\b.*(key|secret|token|pass)", "EnvSecretGrep",
    "")
| where isnotempty(Technique)
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Techniques = make_set(Technique), Commands = make_set(ProcessCommandLine, 20),
            Parents = make_set(ParentProcessName, 10)
    by AzureResourceId, KubernetesNamespace, KubernetesPodName, ContainerName, ContainerImageName, HostName
| extend Severity = case(set_has_element(Techniques, "NodeCredentialFiles") or set_has_element(Techniques, "ProcRootTraversal"), "High",
                         array_length(Techniques) >= 2, "High",
                         "Medium")
| order by Severity asc, FirstSeen desc
```
