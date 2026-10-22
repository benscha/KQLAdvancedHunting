# *Suspicious Windows Policy and Security Registry Tampering*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1112 | Modify Registry | https://attack.mitre.org/techniques/T1112 |
| T1562.001 | Impair Defenses: Disable or Modify Tools | https://attack.mitre.org/techniques/T1562/001 |
| T1548.002 | Abuse Elevation Control Mechanism: Bypass User Account Control | https://attack.mitre.org/techniques/T1548/002 |



#### Description

This query detects suspicious modifications of restrictive Windows policy values in the registry, such as ConsentPromptBehaviorAdmin, DisableTaskMgr, DisableRegistryTools, DisableCMD and a range of Explorer restrictions like NoRun, NoControlPanel or NoDrives. It monitors RegistryValueSet events in DeviceRegistryEvents, normalizes the hive (including HKCU reported with the user SID) and matches each write against a policy table that defines the dangerous value per setting and whether the setting is considered critical. Machine wide settings such as UAC prompt behaviour are only evaluated in HKLM, and writes that do not change the previous value are discarded.

A write is only kept when the execution context is suspicious: the writing process runs from a user writable or temporary path, its direct parent is an Office application or a script host, or it is PowerShell started with an encoded command argument. Writes are grouped per device, account, hive and actor into sessions using the CorrelationWindow, where sibling reg.exe processes sharing the same shell or script host parent are treated as one actor. A session is reported when it contains at least one critical write or at least MinimumDistinctRestrictions different settings. This pattern is typical for ransomware, scareware and malware that locks down the desktop or weakens UAC. Lookback, CorrelationWindow, MinimumDistinctRestrictions and the risky path regex can be tuned; legitimate scripts or installers executed from ProgramData or Temp are the most likely false positive source.

#### Author
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
// Derived from Sigma ccc946a3-f65a-432a-bb6f-efc6acc1fd27
let Lookback = 1h;
let CorrelationWindow = 10m;
let MinimumDistinctRestrictions = 3;
let PolicyRules = datatable(
    PolicyPath:string, ValueName:string, DangerousMode:string, Critical:bool
)
[
    @"software\microsoft\windows\currentversion\policies\system", "consentpromptbehavioradmin", "zero-machine", true,
    @"software\microsoft\windows\currentversion\policies\system", "disableregistrytools", "one-or-two", true,
    @"software\microsoft\windows\currentversion\policies\system", "disabletaskmgr", "one", true,
    @"software\policies\microsoft\windows\system", "disablecmd", "one-or-two", true,
    @"software\microsoft\windows\currentversion\policies\system", "disablechangepassword", "one", false,
    @"software\microsoft\windows\currentversion\policies\system", "disablelockworkstation", "one", false,
    @"software\policies\microsoft\windows\explorer", "disablenotificationcenter", "one", false,
    @"software\microsoft\windows\currentversion\policies\explorer", "hidescahealth", "one", false,
    @"software\microsoft\windows\currentversion\policies\explorer", "hidescanetwork", "one", false,
    @"software\microsoft\windows\currentversion\policies\explorer", "hidescavolume", "one", false,
    @"software\microsoft\windows\currentversion\policies\system", "inactivitytimeoutsecs", "zero-machine", false,
    @"software\microsoft\windows\currentversion\policies\explorer", "noclose", "one", false,
    @"software\microsoft\windows\currentversion\policies\explorer", "nocontrolpanel", "one", false,
    @"software\microsoft\windows\currentversion\policies\explorer", "nodesktop", "one", false,
    @"software\microsoft\windows\currentversion\policies\system", "nodispbackgroundpage", "one", false,
    @"software\microsoft\windows\currentversion\policies\system", "nodispcpl", "one", false,
    @"software\microsoft\windows\currentversion\policies\explorer", "nodrives", "nonzero", false,
    @"software\microsoft\windows\currentversion\policies\explorer", "nofilemenu", "one", false,
    @"software\microsoft\windows\currentversion\policies\explorer", "nofind", "one", false,
    @"software\microsoft\windows\currentversion\policies\explorer", "nologoff", "one", false,
    @"software\microsoft\windows\currentversion\policies\explorer", "nopropertiesmydocuments", "one", false,
    @"software\microsoft\windows\currentversion\policies\explorer", "norun", "one", false,
    @"software\microsoft\windows\currentversion\policies\explorer", "nosettaskbar", "one", false,
    @"software\microsoft\windows\currentversion\policies\explorer", "notraycontextmenu", "one", false,
    @"software\microsoft\windows\currentversion\policies\explorer", "startmenulogoff", "one", false,
    @"software\microsoft\windows\currentversion\policies\system", "shutdownwithoutlogon", "one-machine", false
];
let PolicyValueNames = toscalar(PolicyRules | summarize make_set(ValueName));
let SuspiciousParentNames = dynamic([
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "mshta.exe", "wscript.exe", "cscript.exe"
]);
let PowerShellNames = dynamic(["powershell.exe", "pwsh.exe", "pwsh.dll"]);
let RiskyWriterPathRegex =
    @"(?i)^[a-z]:\\(?:users\\[^\\]+\\(?:downloads|desktop|appdata\\(?:local|locallow|roaming))|users\\public|windows\\temp|programdata|perflogs)(?:\\|$)";
// Matches -e, -en ... -encodedcommand and -ec with "-", "/", en dash, em dash or horizontal bar as prefix.
let EncodedCommandRegex =
    @"(?i)(?:^|\s)[-/\x{2013}\x{2014}\x{2015}](?:ec|e(?:n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?)\s+\S+";
DeviceRegistryEvents
// Overlap by one correlation window so sessions across run boundaries are complete.
| where Timestamp >= ago(Lookback + CorrelationWindow)
| where ActionType == "RegistryValueSet"
// Cheap prefilters before any string transformation or regex.
| where RegistryValueName in~ (PolicyValueNames)
| where RegistryKey has "Policies"
| where RegistryValueType in~ ("Dword", "REG_DWORD")
| extend NormalizedKey = tolower(RegistryKey),
         ValueName = tolower(RegistryValueName)
// HKCU may be reported with the user SID (HKEY_CURRENT_USER\S-1-5-21-...\Software).
| extend TargetHive = extract(
    @"^(hkey_local_machine|hkey_current_user(?:\\s-1-[0-9-]+)?|hkey_users\\s-1-[0-9-]+)\\software\\",
    1, NormalizedKey)
| where isnotempty(TargetHive)
| extend PolicyPath = substring(NormalizedKey, strlen(TargetHive) + 1)
| lookup kind=inner PolicyRules on PolicyPath, ValueName
| extend NumericData = tolong(trim(@"\s+", RegistryValueData)),
         PreviousNumericData = tolong(trim(@"\s+", PreviousRegistryValueData))
| where isnotnull(NumericData)
| where
    (DangerousMode == "one" and NumericData == 1)
    or (DangerousMode == "one-or-two" and NumericData in (1, 2))
    or (DangerousMode == "nonzero" and NumericData != 0)
    or (DangerousMode == "zero-machine" and NumericData == 0
        and TargetHive == "hkey_local_machine")
    or (DangerousMode == "one-machine" and NumericData == 1
        and TargetHive == "hkey_local_machine")
// Unknown previous data is retained; known numerical no-op writes are removed.
| where isnull(PreviousNumericData) or PreviousNumericData != NumericData
| extend OriginalFileName = column_ifexists("InitiatingProcessVersionInfoOriginalFileName", "")
| extend IsPowerShell = InitiatingProcessFileName in~ (PowerShellNames)
             or OriginalFileName in~ (PowerShellNames)
| extend WriterInRiskyPath = InitiatingProcessFolderPath matches regex RiskyWriterPathRegex,
         SuspiciousDirectParent = InitiatingProcessParentFileName in~ (SuspiciousParentNames),
         EncodedPowerShell = IsPowerShell
             and InitiatingProcessCommandLine matches regex EncodedCommandRegex
| where WriterInRiskyPath or SuspiciousDirectParent or EncodedPowerShell
| extend ContextReason = case(
    WriterInRiskyPath, "Registry writer executing from a risky path",
    SuspiciousDirectParent, "Office or script-host direct parent",
    "PowerShell with an encoded-command argument")
// Sibling reg.exe processes can share a cmd/PowerShell/script-host parent.
| extend UseParentActor = InitiatingProcessFileName =~ "reg.exe"
    and InitiatingProcessParentFileName in~ (
        "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe")
    and InitiatingProcessParentId > 0
    and isnotnull(InitiatingProcessParentCreationTime)
| extend ActorId = case(
    UseParentActor,
        strcat("parent:", InitiatingProcessParentId, ":", InitiatingProcessParentCreationTime),
    isnotempty(InitiatingProcessUniqueId),
        strcat("process:", InitiatingProcessUniqueId),
    isnotnull(InitiatingProcessCreationTime),
        strcat("process:", InitiatingProcessId, ":", InitiatingProcessCreationTime),
    strcat("event:", DeviceName, ":", Timestamp, ":", ReportId))
| sort by DeviceId asc, InitiatingProcessAccountSid asc, TargetHive asc, ActorId asc, Timestamp asc
| extend SessionStart = row_window_session(
    Timestamp, CorrelationWindow, CorrelationWindow,
    DeviceId != prev(DeviceId)
        or InitiatingProcessAccountSid != prev(InitiatingProcessAccountSid)
        or TargetHive != prev(TargetHive)
        or ActorId != prev(ActorId))
| summarize
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    CriticalWrites = countif(Critical),
    ChangedSettings = make_set(ValueName, 64),
    RegistryEvidence = make_set(
        pack("Key", RegistryKey, "Name", RegistryValueName,
             "Data", RegistryValueData, "PreviousData", PreviousRegistryValueData), 64),
    ContextReasons = make_set(ContextReason, 8),
    arg_max(Timestamp, ReportId, DeviceName, RegistryKey, RegistryValueName,
        RegistryValueData, PreviousRegistryValueData,
        InitiatingProcessFileName, InitiatingProcessFolderPath,
        InitiatingProcessCommandLine, InitiatingProcessSHA1, InitiatingProcessSHA256,
        InitiatingProcessAccountName, InitiatingProcessAccountDomain,
        InitiatingProcessId, InitiatingProcessCreationTime,
        InitiatingProcessParentFileName, InitiatingProcessParentId,
        InitiatingProcessParentCreationTime)
    by DeviceId, InitiatingProcessAccountSid, TargetHive, ActorId, SessionStart
// Only report sessions that ended inside the current run window;
// sessions that ended in the overlap were evaluated by the previous run.
| where LastSeen >= ago(Lookback)
| extend DistinctSettings = array_length(ChangedSettings)
| where CriticalWrites > 0 or DistinctSettings >= MinimumDistinctRestrictions
| extend DetectionReason = iff(
    CriticalWrites > 0,
    "High-impact registry tampering with suspicious execution context",
    "Multiple restrictive registry settings with suspicious execution context")
| project
    Timestamp, DeviceId, DeviceName, ReportId,
    DetectionReason, FirstSeen, LastSeen, DistinctSettings, CriticalWrites,
    ChangedSettings, RegistryEvidence, ContextReasons, TargetHive, ActorId,
    RegistryKey, RegistryValueName, RegistryValueData, PreviousRegistryValueData,
    InitiatingProcessAccountSid, InitiatingProcessAccountDomain, InitiatingProcessAccountName,
    InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
    InitiatingProcessSHA1, InitiatingProcessSHA256, InitiatingProcessId,
    InitiatingProcessCreationTime, InitiatingProcessParentFileName,
    InitiatingProcessParentId, InitiatingProcessParentCreationTime
```
