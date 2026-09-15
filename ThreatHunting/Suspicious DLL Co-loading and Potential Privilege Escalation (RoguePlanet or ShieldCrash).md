# *Suspicious DLL Co-loading and Potential Privilege Escalation (RoguePlanet/ShieldCrash)*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1574.001 | DLL | https://attack.mitre.org/techniques/T1574/001 |


#### Description

Detects suspicious co-loading of 'MpClient.dll' and 'cldapi.dll' by non-standard processes. This behavior pattern is associated with specific DLL search order hijacking or side-loading techniques (e.g., RoguePlanet/ShieldBreak/ShieldCrash chain) used to execute malicious code. The rule includes logic to identify potential follow-on privilege escalation if a child process is spawned under the SYSTEM account shortly after the DLL loads.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR 
```KQL
//Suspicious co-loading of MpClient.dll and cldapi.dll (RoguePlanet/ShieldBreak/ShieldCrash chain)
let lookback = 1d;
let timeWindowSeconds = 300; // 5 Minuten
let TrustedFolderPaths = dynamic([
    @"c:\windows\system32\\",
    @"c:\windows\syswow64\\",
    @"c:\program files\windows defender\\",
    @"c:\programdata\microsoft\windows defender\\"
]);
let TrustedProcessNames = dynamic([
    "msmpeng.exe","mpcmdrun.exe","nissrv.exe","securityhealthservice.exe",
    "onedrive.exe","filecoauth.exe","dropbox.exe","googledrivefs.exe"
]);
let MpClientLoads = DeviceImageLoadEvents
| where Timestamp > ago(lookback)
| where FileName =~ "MpClient.dll"
| where InitiatingProcessFileName !in~ (TrustedProcessNames)
| where not(InitiatingProcessFolderPath has_any (TrustedFolderPaths))
| project MpTime = Timestamp, DeviceId, DeviceName, InitiatingProcessId,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessSHA256,
          InitiatingProcessAccountName, InitiatingProcessIntegrityLevel;
let CldApiLoads = DeviceImageLoadEvents
| where Timestamp > ago(lookback)
| where FileName =~ "cldapi.dll"
| where InitiatingProcessFileName !in~ (TrustedProcessNames)
| project CldTime = Timestamp, DeviceId, InitiatingProcessId;
let Correlated = MpClientLoads
| join kind=inner CldApiLoads on DeviceId, InitiatingProcessId
| where abs(datetime_diff('second', MpTime, CldTime)) <= timeWindowSeconds
| extend DeltaSeconds = abs(datetime_diff('second', MpTime, CldTime));
// Fidelity-Boost: prüfen ob derselbe Prozess kurz danach einen Kindprozess
// als SYSTEM startet, starkes Indiz für erfolgreiche Eskalation statt nur Versuch
let EscalatedChildren = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where AccountName =~ "system"
| project ChildTime = Timestamp, DeviceId, InitiatingProcessId, ChildProcessFileName = FileName,
          ChildProcessCommandLine = ProcessCommandLine;
Correlated
| join kind=leftouter EscalatedChildren on DeviceId, InitiatingProcessId
| where isempty(ChildProcessFileName) or ChildTime between (MpTime .. (MpTime + 10m))
| extend Escalated = iif(isnotempty(ChildProcessFileName), true, false)
| extend Severity = iif(Escalated, "High", "Medium")
| project Timestamp = MpTime, DeviceId, DeviceName, InitiatingProcessFileName,
          InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256,
          InitiatingProcessAccountName, InitiatingProcessIntegrityLevel,
          DeltaSeconds, Escalated, ChildProcessFileName, ChildProcessCommandLine, Severity
| extend HostCustomEntity = DeviceName,
          AccountCustomEntity = InitiatingProcessAccountName,
          ProcessCustomEntity = InitiatingProcessFileName,
          FileHashCustomEntity = InitiatingProcessSHA256
```
