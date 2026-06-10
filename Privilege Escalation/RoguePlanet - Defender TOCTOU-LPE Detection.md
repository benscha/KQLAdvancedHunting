# *RoguePlanet / Defender TOCTOU-LPE Detection*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1068 | Exploitation for Privilege Escalation | https://attack.mitre.org/techniques/T1068/ |
| T1564.004 | NTFS File Attributes | https://attack.mitre.org/techniques/T1564/004/ |

#### Description
This rule detects low-privileged users exploiting a time-of-check to time-of-use (TOCTOU) flaw in Windows Defender to gain administrative control (Local Privilege Escalation).
It monitors the behavioral attack chain: a standard user creates a directory shortcut (NTFS Junction) — often combined with an ISO mount. This tricks the highly privileged Defender service (MsMpEng.exe) into dropping or modifying files inside protected system folders, ultimately triggering a highly suspicious command shell (cmd.exe/PowerShell) running with SYSTEM privilege

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- https://angelica.gitbook.io/hacktricks/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation

## Sentinel

```KQL
// RoguePlanet / Defender TOCTOU-LPE Detection
let DefenderProcesses = dynamic([
    "MsMpEng.exe", "MpCmdRun.exe", "NisSrv.exe", "SecurityHealthService.exe"
]);
let SuspiciousChildProcs = dynamic([
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"
]);
// SYSTEM-level shell spawned from Defender process ---
let DefenderSystemSpawn = DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (DefenderProcesses)
| where FileName in~ (SuspiciousChildProcs)
| where AccountName =~ "SYSTEM" or AccountSid == "S-1-5-18"
| where not (
    ProcessCommandLine has_any ("MpCmdRun", "-RemoveDefinitions", "-SignatureUpdate",
                                "UpdateSignatures", "Restore", "-ScanType")
)
// FP-Exclude: Defender Diagnostic Bundle (support folder + known diagnostic cmdlets)
| where not (ProcessCommandLine has @"Windows Defender\Support\")
| where not (ProcessCommandLine has_any (
    "Get-AppxPackage",
    "Get-NetFirewallDynamicKeywordAddress",
    "SecurityHealthAppx.txt"
))
| extend Signal = "SYSTEM_shell_from_Defender"
| project Timestamp, DeviceName, DeviceId,
    ParentProcess = InitiatingProcessFileName,
    SpawnedProcess = FileName,
    CommandLine = ProcessCommandLine,
    AccountName, AccountSid,
    InitiatingProcessCommandLine,
    TargetPath = "",
    FileName,
    Signal;
// NTFS Junction Point via cmd ---
let JunctionCreation = DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "cmd.exe"
| where ProcessCommandLine has_all ("mklink", "/J")
// FP-Exclude: Junctions within userspace (OneDrive redirects, dev tools like Claude Code)
| where ProcessCommandLine has_any (@"C:\Windows\", @"C:\Program Files", @"C:\Program Files (x86)")
| extend Signal = "NTFS_Junction_Created_cmd"
| project Timestamp, DeviceName, DeviceId,
    AccountName, AccountSid,
    TargetPath = extract(@"mklink\s+/[jJ]\s+[\""]?([^\s\"">]+)", 1, ProcessCommandLine),
    CommandLine = ProcessCommandLine,
    FileName,
    InitiatingProcessCommandLine = InitiatingProcessCommandLine,
    Signal;
// NTFS Junction Point via PowerShell ---
let JunctionCreationPS = DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
    "Junction", "CreateJunction", "[System.IO.Directory]::CreateDirectory",
    "New-Item -ItemType Junction", "cmd /c mklink"
)
// FP-Exclude: node_modules junctions and other dev tool patterns in userspace
| where ProcessCommandLine has_any (@"C:\Windows\", @"C:\Program Files", @"C:\Program Files (x86)")
    or (ProcessCommandLine has "Junction" and ProcessCommandLine has @"C:\Windows")
| extend Signal = "NTFS_Junction_Created_PS"
| project Timestamp, DeviceName, DeviceId,
    AccountName, AccountSid,
    TargetPath = "",
    CommandLine = ProcessCommandLine,
    FileName,
    InitiatingProcessCommandLine = InitiatingProcessCommandLine,
    Signal;
// ISO mount by standard user ---
let ISOMount = DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "Explorer.exe" or InitiatingProcessFileName =~ "Explorer.exe"
| where ProcessCommandLine has ".iso"
| extend Signal = "ISO_Mount_UserContext"
| project Timestamp, DeviceName, DeviceId,
    AccountName, AccountSid,
    TargetPath = "",
    CommandLine = ProcessCommandLine,
    FileName,
    InitiatingProcessCommandLine = InitiatingProcessCommandLine,
    Signal;
// VDS ISO mount via Registry ---
let ISORegistry = DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has @"SYSTEM\MountedDevices"
| where InitiatingProcessFileName =~ "svchost.exe"
| where InitiatingProcessCommandLine has "vds"
| extend Signal = "VDS_ISO_Mount_Registry"
| project Timestamp, DeviceName, DeviceId,
    AccountName = InitiatingProcessAccountName,
    AccountSid = InitiatingProcessAccountSid,
    TargetPath = RegistryKey,
    CommandLine = InitiatingProcessCommandLine,
    FileName = InitiatingProcessFileName,
    InitiatingProcessCommandLine = InitiatingProcessCommandLine,
    Signal;
// MsMpEng writes outside of Quarantine into system paths ---
let DefenderWriteSystemPath = DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "MsMpEng.exe"
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath has_any (
    @"C:\Windows\System32",
    @"C:\Windows\SysWOW64",
    @"C:\Windows\Tasks"
)
| where not (FileName has_any (".vdm", ".cat", ".sig", "mpasbase", "mpavbase"))
// FP-Exclude: Defender's own drivers and PS modules during engine updates
| where not (FolderPath has_any (
    @"\drivers\wd\",
    @"\Modules\ConfigDefender\",
    @"\Modules\ConfigDefenderPerformance\"
))
| extend Signal = "MsMpEng_Unexpected_Write"
| project Timestamp, DeviceName, DeviceId,
    AccountName = InitiatingProcessAccountName,
    AccountSid = InitiatingProcessAccountSid,
    TargetPath = FolderPath,
    CommandLine = InitiatingProcessCommandLine,
    FileName,
    InitiatingProcessCommandLine = InitiatingProcessCommandLine,
    Signal;
// Junction + ISO on the same device within 10 minutes ---
let JunctionAll = union JunctionCreation, JunctionCreationPS;
let Correlated = JunctionAll
| join kind=inner (
    ISOMount
    | project ISOTime = Timestamp, DeviceName, ISOUser = AccountName
) on DeviceName
| where abs(datetime_diff('minute', Timestamp, ISOTime)) <= 10
| extend Signal = "Junction_and_ISO_Correlated"
| project Timestamp, DeviceName, DeviceId,
    AccountName, AccountSid,
    TargetPath,
    CommandLine,
    FileName,
    InitiatingProcessCommandLine,
    Signal;
union
    DefenderSystemSpawn,
    JunctionAll,
    ISORegistry,
    DefenderWriteSystemPath,
    Correlated
| extend RiskScore = case(
    Signal == "SYSTEM_shell_from_Defender",     100,
    Signal == "Junction_and_ISO_Correlated",     85,
    Signal == "MsMpEng_Unexpected_Write",        80,
    Signal == "NTFS_Junction_Created_cmd",       40,
    Signal == "NTFS_Junction_Created_PS",        40,
    Signal == "ISO_Mount_UserContext",           15,
    Signal == "VDS_ISO_Mount_Registry",          15,
    0
)
| extend SeverityTier = case(
    RiskScore >= 80, "Critical",
    RiskScore >= 40, "Medium",
    "Low"
)
| where RiskScore > 0
| sort by RiskScore desc, Timestamp desc
| project Timestamp, DeviceName, DeviceId,
    Signal, SeverityTier, RiskScore,
    AccountName, CommandLine,
    TargetPath, FileName
```
