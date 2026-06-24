# *Unofficial WinGet Source Added*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1105 | Ingress Tool Transfer | https://attack.mitre.org/techniques/T1105/ |
| T1059 | Command and Scripting Interpreter | https://attack.mitre.org/techniques/T1059/ |

#### Description

This rule detects when a new WinGet package source is added from an unofficial URL, either via the `winget.exe` command-line interface or through PowerShell using WinGet DSC (Desired State Configuration) cmdlets. Adversaries may add custom package sources to distribute malicious software or maintain persistence

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let OfficialSources = dynamic([
	"winget.azureedge.net",
	"cdn.winget.microsoft.com"
]);
let AppInstallerPolicyKey = "SOFTWARE\\Policies\\Microsoft\\Windows\\AppInstaller";
// CLI source add
let CliSourceAdd =
	DeviceProcessEvents
	| where FileName =~ "winget.exe"
	| where ProcessCommandLine has_all ("source", "add")
	// Filter direkt auf der CommandLine anwenden, um False Positives bei offiziellen Quellen zu verhindern
	| where not(ProcessCommandLine has_any (OfficialSources))
	// Regex angepasst für -n OR --name und -a OR --arg
	| extend SourceName = extract(@"(?i)(?:--name|-n)\s+(\S+)", 1, ProcessCommandLine)
	| extend SourceUrl  = extract(@"(?i)(?:--arg|-a)\s+(\S+)", 1, ProcessCommandLine)
	| extend SignalType = "CLI_SourceAdd"
	| extend RegistryKey = "", RegistryValueName = "", RegistryValueData = "";
// DSC / PowerShell COM
let DscSourceAdd =
	DeviceProcessEvents
	| where FileName in~ ("powershell.exe", "pwsh.exe")
	| where ProcessCommandLine has_any ("Microsoft.WinGet.DSC", "WinGetPackageSource", "Add-WinGetSource")
	| where ProcessCommandLine has_any ("Add-WinGetSource", "Ensure", "Add")
	| where not(ProcessCommandLine has_any (OfficialSources))
	| extend SourceName = extract(@"(?i)Name\s*=\s*['""]?(\S+?)['""]?[\s,\)]", 1, ProcessCommandLine)
	| extend SourceUrl  = extract(@"(?i)Argument\s*=\s*['""]?(\S+?)['""]?[\s,\)]", 1, ProcessCommandLine)
	| extend SignalType = "DSC_SourceAdd"
	| extend RegistryKey = "", RegistryValueName = "", RegistryValueData = "";
// Registry AdditionalSources changes
let RegAdditionalSources =
	DeviceRegistryEvents
	| where RegistryKey has AppInstallerPolicyKey
	| where RegistryKey has "AdditionalSources"
	| where ActionType in ("RegistryKeyCreated", "RegistryValueSet")
	| extend SourceName = extract(@"AdditionalSources\\(\d+)", 1, RegistryKey)
	| extend SourceUrl  = tostring(RegistryValueData)
	// Falls die Registry-Daten eine offizielle Quelle enthalten, ausschliessen
	| where not(SourceUrl has_any (OfficialSources))
	| extend SignalType = "Reg_AdditionalSources"
	| extend ProcessCommandLine = InitiatingProcessCommandLine;
// Policy enable additional sources
let RegEnableAdditional =
	DeviceRegistryEvents
	| where RegistryKey has AppInstallerPolicyKey
	| where RegistryValueName =~ "EnableAdditionalSources"
	| where ActionType == "RegistryValueSet"
	| where tolong(RegistryValueData) == 1
	| extend SourceName = "", SourceUrl = ""
	| extend SignalType = "Reg_PolicyManipulation_EnableAdditionalSources"
	| extend ProcessCommandLine = InitiatingProcessCommandLine;
// Policy disable hash validation
let RegHashOverride =
	DeviceRegistryEvents
	| where RegistryKey has AppInstallerPolicyKey
	| where RegistryValueName =~ "EnableHashOverride"
	| where ActionType == "RegistryValueSet"
	| where tolong(RegistryValueData) == 1
	| extend SourceName = "", SourceUrl = ""
	| extend SignalType = "Reg_PolicyManipulation_EnableHashOverride"
	| extend ProcessCommandLine = InitiatingProcessCommandLine;
union
	CliSourceAdd,
	DscSourceAdd,
	RegAdditionalSources,
	RegEnableAdditional,
	RegHashOverride
| project
	Timestamp,
	DeviceName,
	AccountName,
	SignalType,
	SourceName,
	SourceUrl,
	RegistryKey,
	RegistryValueName,
	RegistryValueData,
	ProcessCommandLine,
	ReportId,
	DeviceId
| sort by Timestamp desc
```
