# Kubernetes Container Reverse Shell Execution*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.004 | Unix Shell | https://attack.mitre.org/techniques/T1059/004 |
| T1059.006 | Python | https://attack.mitre.org/techniques/T1059/006 |

#### Description

Detects common reverse shell patterns within containerized environments by monitoring process execution commands. The rule identifies the use of network device files (/dev/tcp, /dev/udp) or common networking utilities (netcat, socat, python, perl) with flags commonly used to redirect input/output streams to a remote network socket.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
// K8S-11  Reverse Shell Pattern (Container und Node)
CloudProcessEvents
| where Timestamp > ago(1h)
| where ProcessCommandLine contains "/dev/tcp/" or ProcessCommandLine contains "/dev/udp/"
     or (ProcessName in~ ("nc", "ncat", "netcat", "busybox") and ProcessCommandLine has_any (" -e ", " -c ", "/bin/sh", "/bin/bash"))
     or (ProcessName =~ "socat" and ProcessCommandLine has_any ("exec:", "EXEC:", "pty", "system:"))
     or (ProcessName startswith "python" and ProcessCommandLine has "socket" and ProcessCommandLine has_any ("pty.spawn", "subprocess", "dup2"))
     or (ProcessName =~ "perl" and ProcessCommandLine has "socket" and ProcessCommandLine has "exec")
| project Timestamp, ReportId, AzureResourceId, KubernetesNamespace, KubernetesPodName, ContainerName,
          ContainerImageName, AccountName, ParentProcessName, ProcessName, ProcessCommandLine
```
