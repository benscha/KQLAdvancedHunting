# *SQL Server Engine Process Spawned Suspicious Shell or LOLBin*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.001 | Command and Scripting Interpreter: PowerShell | https://attack.mitre.org/techniques/T1059/001 |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | https://attack.mitre.org/techniques/T1059/003 |
| T1505.001 | Exfiltration Over Web Service | https://attack.mitre.org/techniques/T1059/001 |

#### Description

This rule detects when the SQL Server process (sqlservr.exe) or SQL Agent process (sqlagent.exe) spawns known command-line shells, interpreters, or Living-off-the-Land Binaries (LOLBins). It uses a scoring mechanism to evaluate command-line arguments for indicators of malicious activity such as reverse shells, encoded PowerShell, remote file downloads, or host reconnaissance, flagging instances as either high-confidence malicious behavior or suspicious activity requiring further investigation.

#### Author
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### Reference
- https://www.hackingarticles.in/mssql-for-pentester-command-execution-with-xp_cmdshell/

## Defender XDR
```KQL
// MSSQL xp_cmdshell / SQL Server Command Execution Detection
let LookBack = 7d;
let SqlEngine = dynamic(["sqlservr.exe", "sqlagent.exe", "sqlagent90.exe"]);
let ShellAndLolbins = dynamic([
"cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe", "wscript.exe",
"cscript.exe", "rundll32.exe", "regsvr32.exe", "bitsadmin.exe",
"certutil.exe", "curl.exe", "nc.exe", "ncat.exe", "wget.exe",
"python.exe", "python3.exe", "net.exe", "net1.exe", "reg.exe"
]);
let KnownGood = dynamic([
"wmic logicaldisk",					    // Disk monitoring
"haimportdatabasename",					// AlwaysOn / HA rename
"get-foldersize.ps1"					// Maintenance script
]);
DeviceProcessEvents
| where Timestamp > ago(LookBack)
// Match if parent or grandparent process is the SQL engine or SQL agent
| where InitiatingProcessFileName in~ (SqlEngine) or InitiatingProcessParentFileName in~ (SqlEngine)
| where FileName in~ (ShellAndLolbins)
| extend Cmd = tolower(ProcessCommandLine)
| extend IsPwsh = FileName in~ ("powershell.exe", "pwsh.exe")
// Encoded PowerShell: flag -e/-ec/-enc with a long Base64 string to avoid hitting -ExecutionPolicy
| extend SigEncoded  = IsPwsh and Cmd matches regex @"\s-e[a-z]*\s+[a-z0-9+/]{40,}"
| extend SigRevShell = Cmd has_any ("tcpclient", "getstream") or Cmd contains "net.sockets"
| extend SigNetcat   = Cmd contains "nc.exe" or Cmd contains "ncat.exe" or Cmd contains "-e cmd" or Cmd contains "-e powershell"
| extend SigRemoteHta = Cmd contains "mshta" and Cmd has_any ("http://", "https://")
| extend SigDownload = Cmd has_any ("downloadstring", "downloadfile", "bitsadmin", "certutil", "wget") or Cmd contains "invoke-webrequest" or Cmd contains "start-bitstransfer"
| extend SigIex      = (Cmd contains "iex(" or Cmd contains "invoke-expression") and (Cmd contains "http" or Cmd contains "downloadstring")
| extend HighCount = toint(SigEncoded) + toint(SigRevShell) + toint(SigNetcat) + toint(SigRemoteHta) + toint(SigDownload) + toint(SigIex)
// Low-confidence indicators (requires at least 2 matches to trigger)
| extend SigHidden = Cmd contains "-w hidden" or Cmd contains "-windowstyle hidden"
| extend SigRecon  = Cmd has_any ("whoami", "ipconfig", "hostname", "systeminfo") or Cmd contains "net user" or Cmd contains "net localgroup"
| extend LowCount = toint(SigHidden) + toint(SigRecon)
// Filter to keep only actual attack signatures
| where HighCount >= 1 or LowCount >= 2
| extend Indicators = set_difference(pack_array(
    iff(SigEncoded,   "EncodedPowerShell", ""),
    iff(SigRevShell,  "PowerShellReverseShell", ""),
    iff(SigNetcat,    "NetcatShell", ""),
    iff(SigRemoteHta, "RemoteHTA", ""),
    iff(SigDownload,  "RemoteToolDownload", ""),
    iff(SigIex,       "DownloadCradle", ""),
    iff(SigHidden,    "HiddenWindow", ""),
    iff(SigRecon,     "HostRecon", "")
), dynamic([""]))
| extend Verdict = iff(HighCount >= 1,
    "High: SQL engine spawned an attack tool",
    "Suspicious: multiple low-severity indicators, investigation required")
| project
Timestamp,
DeviceName,
SqlServiceAccount  = InitiatingProcessAccountName,
GrandparentProcess = InitiatingProcessParentFileName,
ParentProcess      = InitiatingProcessFileName,
LaunchedProcess    = FileName,
ProcessCommandLine,
Indicators,
Verdict,
DeviceId,
ReportId
| order by Timestamp desc
```
