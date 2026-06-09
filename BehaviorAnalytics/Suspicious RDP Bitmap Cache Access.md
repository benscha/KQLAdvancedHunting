# *Suspicious RDP Bitmap Cache Access*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1005 | Data from Local System | https://attack.mitre.org/techniques/T1005/ |
| T1083 | File and Directory Discovery | https://attack.mitre.org/techniques/T1083/ |


#### Description

This rule monitors for unauthorized access to RDP Bitmap Cache files, which attackers target to visually reconstruct past administrative sessions and harvest sensitive data. By explicitly excluding legitimate RDP managers like mstsc.exe or Royal TS, any interaction from alternative processes serves as a high-fidelity indicator of internal reconnaissance or credential harvesting. The detection triggers immediately when an unapproved binary reads, copies, or renames these cache artifacts.

Upon an alert, immediately isolate the affected host to prevent potential lateral movement. Analyze the initiating process command line for suspicious scripts or unauthorized tools, and verify if there is any valid administrative justification for low-level file forensics. If a compromise is confirmed, promptly rotate credentials for all privileged accounts that have historically logged into that endpoint.

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
