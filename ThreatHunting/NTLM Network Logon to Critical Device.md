# *NTLM Network Logon to Critical Device*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1078 | Valid Accounts | https://attack.mitre.org/techniques/T1078 |

#### Description

This rule detects NTLM network logon events to devices identified as critical (criticality score >= 3). This could indicate an adversary attempting to move laterally or access sensitive systems using NTLM authentication, which is generally less secure than Kerberos.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let NetworkLogons = DeviceLogonEvents
	| where Timestamp > ago(4h)
	| where LogonType == "Network"
	| where Protocol == "NTLM"
	| extend ShortDeviceName = toupper(split(DeviceName, ".")[0]);
NetworkLogons
| join kind=inner (	ExposureGraphNodes
	| where Categories has "device"
	| where isnotnull(NodeProperties.rawData.criticalityLevel)
	| extend ShortNodeName = toupper(split(NodeName, ".")[0])
	| extend TargetCriticalityScore = toint(NodeProperties.rawData.criticalityLevel.criticalityLevel)
	| extend TargetCriticalityRule = tostring(NodeProperties.rawData.criticalityLevel.ruleName)
	| project ShortNodeName, TargetCriticalityScore, TargetCriticalityRule
) on $left.ShortDeviceName == $right.ShortNodeName
| where TargetCriticalityScore >= 3
```
