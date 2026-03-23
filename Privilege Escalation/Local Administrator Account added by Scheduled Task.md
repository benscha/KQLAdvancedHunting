# *Local Administrator Account added by Scheduled Task*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1053.005 | Scheduled Tasks | https://attack.mitre.org/techniques/T1053/005/ |
| T1136.001 | Local Account | https://attack.mitre.org/techniques/T1136/001/ |

#### Description
Inspiration: Inspired by Paula Januszkiewicz’s session at Swiss Microsoft Security Summit 2026

Description: This rule monitors for the unauthorized addition of local administrators through scheduled tasks. It detects the use of net.exe, net1.exe, and PowerShell when triggered by svchost.exe or taskeng.exe. By specifically filtering for group manipulation commands (e.g., "Add-LocalGroupMember" or "/add"), it identifies potential privilege escalation or persistence techniques where attackers attempt to gain permanent administrative access.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- Swiss Microsoft Security Day 2026 - Session by Paula Januszkiewicz
## Sentinel

```KQL
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("taskeng.exe", "svchost.exe") 
     and FileName in~ ("net.exe", "net1.exe", "powershell.exe", "pwsh.exe", "cmd.exe")
| where ProcessCommandLine has_any ("Administratoren", "Administrators", "LocalGroup", "Add-LocalGroupMember")
| where ProcessCommandLine has_any ("add", "-Member", "/add")
| sort by Timestamp desc
```
