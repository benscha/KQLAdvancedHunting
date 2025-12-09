# *PowerShell LOLBAS Execution with Public Network Connection*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.001 | Command and Scripting Interpreter: PowerShell | https://attack.mitre.org/techniques/T1059/001/ |


#### Description
This rule detects PowerShell processes that are initiated by a LOLBAS binary and subsequently establish an outbound network connection to a public IP address. It leverages an external LOLBAS JSON data source to identify suspicious parent processes. This behavior could indicate an adversary using a Living Off The Land Binary or Script (LOLBAS) to execute PowerShell for malicious purposes, such as command and control or data exfiltration.

#### Risk
Defense Evasion

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- https://lolbas-project.github.io

## Defender XDR
```KQL
let timeWindow = 2m;
// Load LOLBAS JSON from external source
let lolbas = externaldata(Name:string, Category:string, Description:string, Commands:string)
[@"https://lolbas-project.github.io/api/lolbas.json"]
with(format="multijson");
// Join DeviceProcessEvents with LOLBAS list
let suspiciousProcesses = DeviceProcessEvents
| where FileName in ("powershell.exe","pwsh.exe","pwsh.dll")
| join kind=inner (lolbas) on $left.InitiatingProcessFileName == $right.Name
    | project Timestamp, DeviceId, DeviceName, ProcessId, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName, LOLBAS_Category = Category, LOLBAS_Description = Description, TimeWindowStart = Timestamp - timeWindow, TimeWindowEnd = Timestamp + timeWindow, SHA1;
suspiciousProcesses
| join kind=leftouter (
    DeviceNetworkEvents
    | project NetworkTimestamp = Timestamp, DeviceId, InitiatingProcessId,RemoteIP, RemotePort, RemoteUrl, Protocol, ActionType, LocalIP, LocalPort, RemoteIPType
) on DeviceId, $left.ProcessId == $right.InitiatingProcessId
| where isnotempty( RemoteIP) and RemoteIPType == "Public"
| where NetworkTimestamp between (TimeWindowStart .. TimeWindowEnd)
```


