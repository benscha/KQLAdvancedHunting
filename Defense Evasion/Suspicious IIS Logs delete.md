# *Suspicious IIS Log Deletion by Command-Line Interpreters*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1070.004 | Indicator Removal: File Deletion | https://attack.mitre.org/techniques/T1070/004/ |
| T1059.001 | Command and Scripting Interpreter: PowerShell | https://attack.mitre.org/techniques/T1059/001/ |
| TA0005 | Defense Evasion  | https://attack.mitre.org/tactics/TA0005/ |

#### Description
Detects the deletion of IIS log files by common command-line interpreters such as cmd.exe or PowerShell. This activity can be indicative of an adversary attempting to remove forensic evidence after compromising an IIS web server.

#### Risk
Defense Evasion

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- https://threatview.io

## Defender XDR
```KQL
DeviceFileEvents
| where ActionType == "FileDeleted"
| where InitiatingProcessFileName has_any  (@"\cmd.exe", @"\powershell_ise.exe", @"\powershell.exe", @"\pwsh.exe")
    or InitiatingProcessCommandLine has_any ("cmd.exe", "powershell.exe", "powershell_ise.exe", "pwsh.dll")
| where FolderPath contains  @"\inetpub\logs\" 
```



