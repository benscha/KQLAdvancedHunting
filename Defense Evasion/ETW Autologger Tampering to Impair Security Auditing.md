# *ETW Autologger Tampering to Impair Security Auditing*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1562.006 | Indicator Blocking | https://attack.mitre.org/techniques/T1562/006/ |


#### Description
Detects attempts to tamper with Event Tracing for Windows (ETW) Autologger settings, specifically targeting security-relevant loggers. This rule identifies modifications, creations, or deletions of registry keys and values under `Control\WMI\Autologger` that could disable or redirect logging for critical security events. It focuses on actions that set 'Start', 'Enabled', 'EnableFlags', 'FileMax', or 'MaxFileSize' to a disabling value (0) or delete the corresponding keys/values, while filtering out legitimate system processes.

#### Risk
Defense Evasion

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- 

## Defender XDR
```KQL
// Detect ETW Autologger tampering to blind security auditing
// Covers: value modification, key/value deletion, provider-level disabling
// MITRE: T1562.006 – Impair Defenses: Indicator Blocking
let SensitiveAutologgers = dynamic([
	"EventLog-Security",
	"EventLog-System",
	"EventLog-Application",
	"DefenderApiLogger",
	"DefenderAuditLogger",
	"Microsoft-Windows-Threat-Intelligence",
	"SenseEventLog",
	"WdiContextLog"
]);
let LegitWriters = dynamic([
	"TrustedInstaller.exe",
	"msiexec.exe",
	"svchost.exe"
]);
DeviceRegistryEvents
| where TimeGenerated > ago(7d)
// Only write/delete actions – no reads
| where ActionType in (
	"RegistryValueSet",
	"RegistryKeyCreated",
	"RegistryKeyDeleted",
	"RegistryValueDeleted"
)
| where RegistryKey has @"\Control\WMI\Autologger\"
| where RegistryValueName in~ ("Start", "Enabled", "EnableFlags", "FileMax", "MaxFileSize")
	or ActionType in ("RegistryKeyDeleted", "RegistryValueDeleted")
| where RegistryValueData in ("0", "0x0", "0x00000000", "00000000")
	or ActionType in ("RegistryKeyDeleted", "RegistryValueDeleted")
// Focus on security-relevant Autologgers (optionally comment out for a broader search)
| where RegistryKey has_any (SensitiveAutologgers)
| where not(
	InitiatingProcessFileName in~ (LegitWriters)
	and InitiatingProcessFolderPath startswith @"C:\Windows\System32\"
	and InitiatingProcessParentFileName in~ ("services.exe", "wininit.exe")
)
| extend ProcessRisk = case(
	InitiatingProcessFolderPath !startswith @"C:\Windows\", "High – Non-System Path",
	InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"), "High – Scripting Engine",
	InitiatingProcessFileName in~ ("reg.exe", "regsvr32.exe", "regasm.exe"), "Medium – Reg Tool",
	"Low – System Binary"
)
| project
	TimeGenerated,
	DeviceName,
	InitiatingProcessAccountUpn,
	ActionType,
	RegistryKey,
	RegistryValueName,
	RegistryValueData,
	InitiatingProcessFileName,
	InitiatingProcessFolderPath,
	InitiatingProcessCommandLine,  
	InitiatingProcessParentFileName,
	ProcessRisk
| sort by TimeGenerated desc

```
