# *EDR Chocking Detection*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1685 | Disable or Modify Tools | https://attack.mitre.org/techniques/T1685 |
| T1686 | Disable or Modify System Firewall | https://attack.mitre.org/techniques/T1686/ | 

#### Description

This rule detects attempts to manipulate Quality of Service (QoS) policies on Windows systems, specifically targeting Endpoint Detection and Response (EDR) processes. It looks for command-line executions of 'New-NetQosPolicy' or 'Set-NetQosPolicy' where the command line also contains the name of a known EDR process. Additionally, it monitors registry modifications related to QoS policies (under HKEY_LOCAL_MACHINE or HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\QoS) where the registry value data contains an EDR process name. This activity could indicate an adversary attempting to degrade or interfere with EDR functionality by manipulating network QoS settings to prioritize or de-prioritize EDR traffic.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### Reference
- https://www.zerosalarium.com/2026/06/edrchoker-choking-telemetry-stream-block-edr.html?m=1

## Defender XDR
```KQL
let EDR_Processes = dynamic([
    "SenseIR.exe", "MsSense.exe", "MsMpEng.exe", "WinDefend.exe",
    "falcon-sensor.exe", "CSFalconService.exe",
    "SentinelService.exe", "SentinelAgent.exe",
    "CortexXDR.exe", "cyvera.exe", "pmsu.exe",
    "cb.exe", "carbonblack.exe",
    "edragent.exe", "HarfangLab.exe", "elastic-agent.exe"
]);
DeviceProcessEvents
| where ProcessCommandLine has "New-NetQosPolicy"
    or ProcessCommandLine has "Set-NetQosPolicy"
| where ProcessCommandLine has_any(EDR_Processes)
| extend SuspectActivity = "QoS Policy Creation via Command Line"
| extend AccountName = InitiatingProcessAccountName
| project TimeGenerated, DeviceName, AccountName,
    InitiatingProcessFileName, ProcessCommandLine, SuspectActivity,
    DeviceId
| union (
    DeviceRegistryEvents
    | where RegistryKey startswith @"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\QoS\"
        or RegistryKey startswith @"HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\QoS\"
    | where RegistryValueName in ("Application Name", "DSCP Value", "Throttle Rate")
    | where tostring(RegistryValueData) has_any(EDR_Processes)
    | extend SuspectActivity = strcat("QoS Registry Manipulation targeting: ", tostring(RegistryValueData))
    | extend AccountName = InitiatingProcessAccountName
    | project TimeGenerated, DeviceName, AccountName,
        InitiatingProcessFileName,
        ProcessCommandLine = "N/A (Registry Modification)",
        SuspectActivity, DeviceId
)
| order by TimeGenerated desc
```
