# *Anomalous Increase in Unique Device Logon Count per User*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1611 | Escape to Host | https://attack.mitre.org/techniques/T1611 |
| T1059.004 | Unix Shell | https://attack.mitre.org/techniques/T1059/004 |

#### Description

Detects attempts to escape a Kubernetes container to the underlying host or gain privileged control over the container runtime. The rule monitors for suspicious process execution involving utilities used for container breakouts, such as mounting host filesystems, interacting with container sockets (docker.sock, containerd.sock), or manipulating kernel patterns and namespaces.


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
// K8S Container Escape
// MITRE: T1611 (Escape to Host)  |  Severity: High
CloudProcessEvents
| where Timestamp > ago(1h)
| where ContainerName != "host" and isnotempty(ContainerId)
| where (ProcessName =~ "nsenter" and ProcessCommandLine has_any ("-t 1", "--target 1", "--target=1"))
     or (ProcessName =~ "chroot" and ProcessCommandLine has_any ("/host", "/proc/1/root", "/rootfs"))
     or ProcessCommandLine has_any ("/proc/1/root", "release_agent", "/proc/sys/kernel/core_pattern",
                                    "notify_on_release", "docker.sock", "containerd.sock", "crio.sock")
     or (ProcessName =~ "mount" and ProcessCommandLine has_any ("/dev/sd", "/dev/nvme", "/dev/vd", "/dev/xvd", "cgroup"))
     or (ProcessName =~ "unshare" and ProcessCommandLine has_any ("-U", "--user", "-r", "--map-root-user"))
     or (ProcessName in~ ("ctr", "crictl", "docker", "runc"))
| project Timestamp, ReportId, AzureResourceId, KubernetesNamespace, KubernetesPodName, ContainerName,
          ContainerImageName, AccountName, ParentProcessName, ProcessName, ProcessCommandLine
```
