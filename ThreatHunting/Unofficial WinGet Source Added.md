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
// Signal via CLI: winget source add
let CliSourceAdd =
	DeviceProcessEvents
	| where FileName =~ "winget.exe"
	| where ProcessCommandLine has_all ("source", "add")
	| extend SourceName = extract(@"(?i)--name\s+(\S+)", 1, ProcessCommandLine)
	| extend SourceUrl  = extract(@"(?i)--arg\s+(\S+)",  1, ProcessCommandLine)
	| where not(SourceUrl has_any (OfficialSources))
	| extend SignalType = "CLI_SourceAdd";
// Signal via DSC / PowerShell COM
let DscSourceAdd =
	DeviceProcessEvents
	| where FileName in~ ("powershell.exe", "pwsh.exe")
	| where ProcessCommandLine has_any ("Microsoft.WinGet.DSC", "WinGetPackageSource", "Add-WinGetSource")
	| where ProcessCommandLine has_any ("Add-WinGetSource", "Ensure", "Add")
	| where not(ProcessCommandLine has_any (OfficialSources))
	| extend SourceName = extract(@"(?i)Name\s*=\s*['""]?(\S+?)['""]?[\s,\)]", 1, ProcessCommandLine)
	| extend SourceUrl  = extract(@"(?i)Argument\s*=\s*['""]?(\S+?)['""]?[\s,\)]", 1, ProcessCommandLine)
	| extend SignalType = "DSC_SourceAdd";
union CliSourceAdd, DscSourceAdd
| project
	Timestamp,
	DeviceName,
	AccountName,
	InitiatingProcessFileName,
	SignalType,
	SourceName,
	SourceUrl,
	ProcessCommandLine,
	ReportId,
	DeviceId
| sort by Timestamp desc
```
