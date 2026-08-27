# *Suspicious Modification of Hosts File*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1565.001 | Data Manipulation: Stored Data Manipulation | https://attack.mitre.org/techniques/T565/001 |
| T1071.001 | Application Layer Protocol: Web Protocols | https://attack.mitre.org/techniques/T1071/001 |

#### Description

This rule detects modifications to the Windows hosts file by processes that are not in the approved exclusion list. It further refines the detection by filtering for hosts file hashes with low global prevalence or recent appearance in the environment, which is indicative of potential malicious activity like DNS hijacking or malware redirection.


#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

## Defender XDR
```KQL
let Lookback = 30d;
let ExcludedProcesses = dynamic(["vpnagent.exe", "myfunnyDummyBeerProxess.exe"]);
let HostsPath = @"C:\Windows\System32\drivers\etc\";
let HostsEvents = materialize(
    DeviceFileEvents
    | where Timestamp > ago(Lookback)
    | where FileName =~ "hosts"
    | where FolderPath has HostsPath
    | where ActionType in~ ("FileCreated", "FileModified")
    | where InitiatingProcessFileName !in~ (ExcludedProcesses)
    | project Timestamp, DeviceId, DeviceName, FileName, FolderPath, ActionType, SHA256, InitiatingProcessFileName, InitiatingProcessAccountName
);
let SuspiciousHashes = HostsEvents
| distinct SHA256
| invoke FileProfile(SHA256)
| where GlobalFirstSeen > ago(90d) and GlobalPrevalence < 1000
| project SHA256;
HostsEvents
| where SHA256 in~ (SuspiciousHashes)
```
