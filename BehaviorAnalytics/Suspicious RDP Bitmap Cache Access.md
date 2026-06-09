# *NTLM Network Logon Anomalies (Lateral Movement)*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1005 | Data from Local System | https://attack.mitre.org/techniques/T1005/ |
| T1083 | File and Directory Discovery | https://attack.mitre.org/techniques/T1083/ |


#### Description

This detection rule monitors for unauthorized access, reading, or exfiltration of Remote Desktop Protocol (RDP) Bitmap Cache files. When an RDP session is established, Windows caches screen fragments locally within the user profile to optimize performance, and these files persist after the session ends. Threat actors and forensic tools target these cache files to reconstruct visual fragments of past administrative sessions, potentially exposing sensitive data such as passwords, internal applications, and network paths. To ensure high-fidelity detection with a near-zero false positive rate, this rule focuses strictly on the dedicated cache directory path while explicitly omitting legitimate RDP clients and enterprise session managers. Any other process interacting with this folder is considered highly anomalous and indicative of credential harvesting or internal reconnaissance.
Rule Details
The query operates on the Microsoft Defender for Endpoint and Microsoft Sentinel platform, specifically leveraging the Device File Events log source with a designated severity level of High.
How the Query Works and Logic Breakdown
Instead of relying on easily alterable file extensions, the query tightly monitors the absolute path where Windows stores these artifacts, specifically looking for the Terminal Server Client Cache directory. Legitimate applications that natively interact with this folder—such as the standard Windows RDP client, Azure Virtual Desktop, and common enterprise connection managers like Rocket Remote Desktop, Royal TS, or mRemoteNG—are explicitly excluded to prevent false positives. The query isolates critical file system behaviors by focusing on specific action types, targeting unauthorized viewing or parsing through file read operations, copying data out of the directory via file creation, and attempts to mask the artifacts before exfiltration through file renaming.
Recommended Response Playbook
When this alert is triggered, analysts should immediately isolate the affected source device to prevent potential lateral movement or data exfiltration. The next step involves inspecting the initiating process command line to identify the specific tool or script used to access the cache, looking closely for unauthorized archiving tools, scripting engines, or unknown binaries. Security teams must then validate the actions of the involved user account to determine if there is a legitimate administrative reason to perform low-level file forensics on RDP artifacts. Finally, if the affected client endpoint was used by administrators, organizations should assume that historical session content may have been compromised and initiate a credential rotation protocol for any high-privilege accounts used on that host.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
// Definition of allowed RDP managers and system processes
let AllowedRDPManagers = pack_array(
    "mstsc.exe",                  // Standard Windows Client
    "msrdc.exe",                  // Windows 365 / Azure Virtual Desktop Client
    "RocketRemoteDesktop.exe",    // Rocket Remote Desktop
    "RTS2App.exe",                // Royal TS
    "mRemoteNG.exe",              // mRemoteNG
    "RDCMan.exe",                 // Microsoft Remote Desktop Connection Manager
    "svchost.exe"                // System profile handling
);
// Monitor direct file interactions within the specific cache path
DeviceFileEvents
| where Timestamp > ago(14d)
// Focus strictly on the sensitive folder path
| where FolderPath has @"\Microsoft\Terminal Server Client\Cache"
// Any process interacting with this folder that is not an allowed RDP manager is highly suspicious
| where not(InitiatingProcessFileName in~ (AllowedRDPManagers))
// Focus on reading existing cache files or creating copies elsewhere (Exfiltration)
| where ActionType in~ ("FileRead", "FileCreated", "FileRenamed")
| order by Timestamp desc

```
