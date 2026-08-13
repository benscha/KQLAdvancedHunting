# *Windows privilege escalation using dangerous token privileges*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1003.001 | OS Credential Dumping: LSASS Memory | https://attack.mitre.org/techniques/T1003/001 |
| T1543.003 | Create or Modify System Process: Windows Service | https://attack.mitre.org/techniques/T1543/003 |


#### Description
This rule monitors for high-impact Windows privilege escalation behaviors often associated with token manipulation and administrative privilege abuse. It detects multiple techniques including: dumping sensitive registry hives (SAM/SYSTEM/SECURITY), modifying system accessibility binaries to create backdoors, taking ownership of files in System32 followed by binary overwriting, adding accounts to local admin groups under SYSTEM context, dumping LSASS memory, anomalous child processes spawned by winlogon, and service path hijacking. It specifically looks for suspicious activities where non-trusted installers interact with sensitive system paths or processes.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- https://www.hackingarticles.in/windows-privilege-escalation-serestoreprivilege/
- https://www.hackingarticles.in/windows-privilege-escalation-setcbprivilege/
- https://www.hackingarticles.in/windows-privilege-escalation-setakeownershipprivilege/
- https://www.hackingarticles.in/windows-privilege-escalation-sedebugprivilege/)

## Sentinel

```KQL
// Detection for Windows privilege escalation using dangerous token privileges
// Targets end actions for SeRestore, SeBackup, SeTcb, SeTakeOwnership, and SeDebug
let Lookback = 14d;
// Binaries launched by winlogon before auth
let AccessibilityBins = dynamic([
    "utilman.exe", "osk.exe", "sethc.exe", "narrator.exe", "magnify.exe", "displayswitch.exe", "atbroker.exe"
]);
let SensitiveHives = dynamic(["\\sam", "\\system", "\\security"]);
// Legitimate installers replacing files in system32
let TrustedInstallers = dynamic([
    "trustedinstaller.exe", "tiworker.exe", "msiexec.exe", "wuauclt.exe", "poqexec.exe",
    "wuaucltcore.exe", "winreupdateinstaller.exe", "setuphost.exe", "setuphost.exe",
    "cbs.exe", "dism.exe", "sedlauncher.exe", "wsappx.exe"
]);
let SuspiciousChildren = dynamic([
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "net.exe", "net1.exe"
]);
// Registry hive dumps (SAM/SYSTEM/SECURITY) via reg save
let RegHiveDump =
    DeviceProcessEvents
    | where Timestamp > ago(Lookback)
    | where FileName in~ ("reg.exe", "reg")
    | where ProcessCommandLine has "save"
    | where ProcessCommandLine matches regex @"(?i)\bhk(lm|ey_local_machine)\\(sam|system|security)(\s|""|$)"
    | extend Technique = "SeRestore/SeBackup - Registry hive dump (SAM/SYSTEM/SECURITY)"
    | extend Tier = "Tier0"
    | extend Verdict = "Suspicious: reg save of a hive root, typical of credential theft (secretsdump/pypykatz)";
// Accessibility binary swaps in System32
let AccessibilitySwap =
    DeviceFileEvents
    | where Timestamp > ago(Lookback)
    | where ActionType in ("FileCreated", "FileModified", "FileRenamed")
    | where FolderPath startswith @"C:\Windows\System32\"
    | extend TargetBin = tolower(FileName)
    | where TargetBin in (AccessibilityBins)
    | extend Initiator = tolower(InitiatingProcessFileName)
    | where Initiator !in (TrustedInstallers)
    | extend Technique = "SeRestore/SeTakeOwnership - Accessibility binary swap (System32)"
    | extend Tier = "Tier0"
    | extend Verdict = strcat("Suspicious: ", TargetBin, " in System32 modified by ", Initiator, " - login-screen backdoor (SYSTEM shell before auth)")
    | project Timestamp, DeviceId, DeviceName,
        AccountName = InitiatingProcessAccountName,
        FileName, FolderPath, ActionType,
        InitiatingProcessFileName, InitiatingProcessCommandLine,
        InitiatingProcessAccountDomain, InitiatingProcessSHA256,
        Technique, Tier, Verdict;
// Takeown + icacls followed by binary overwrite in System32
let TakeownWindow = 30m;
let PermChanges =
    DeviceProcessEvents
    | where Timestamp > ago(Lookback)
    | where (FileName in~ ("takeown.exe") and ProcessCommandLine has @"\system32")
        or (FileName in~ ("icacls.exe") and ProcessCommandLine has "/grant" and ProcessCommandLine has @"\system32")
    | extend Tool = tolower(FileName)
    | extend TargetPath = tolower(extract(@"(c:\\windows\\system32\\[^\s""]+\.\w+)", 1, tolower(ProcessCommandLine)))
    | where isnotempty(TargetPath)
    | extend GrantsToUserOnly = (Tool == "icacls.exe"
        and ProcessCommandLine has "/grant"
        and ProcessCommandLine !has "administrators"
        and ProcessCommandLine !has "administratoren"
        and ProcessCommandLine !has "system")
    | summarize
        Tools = make_set(Tool, 8),
        CmdLines = make_set(ProcessCommandLine, 8),
        GrantsToNonAdmin = max(GrantsToUserOnly),
        PermFirstSeen = min(Timestamp),
        PermLastSeen = max(Timestamp)
        by DeviceId, DeviceName, AccountName = InitiatingProcessAccountName, TargetPath
    | where array_length(Tools) >= 2;
let BinaryOverwrite =
    DeviceFileEvents
    | where Timestamp > ago(Lookback)
    | where ActionType in ("FileModified", "FileCreated", "FileRenamed")
    | where FolderPath startswith @"C:\Windows\System32\"
    | extend TargetPath = tolower(FolderPath)
    | extend WriteInitiator = tolower(InitiatingProcessFileName)
    | where WriteInitiator !in (TrustedInstallers)
    | project DeviceId, TargetPath, WriteTime = Timestamp,
        WriteInitiator, WriteCmd = InitiatingProcessCommandLine,
        WriteSHA256 = InitiatingProcessSHA256;
let TakeownIcacls =
    PermChanges
    | join kind=inner BinaryOverwrite on DeviceId, TargetPath
    | where WriteTime between (PermFirstSeen .. (PermLastSeen + TakeownWindow))
    | extend Technique = "SeTakeOwnership - takeown+icacls + binary overwrite (System32)"
    | extend Tier = "Tier0"
    | extend Verdict = strcat("Suspicious: ", TargetPath, " overwritten by ", WriteInitiator, " after ownership takeover - binary hijack for SYSTEM execution")
    | extend Timestamp = PermFirstSeen
    | extend FileName = strcat_array(Tools, " + ")
    | extend ProcessCommandLine = strcat(strcat_array(CmdLines, "  ||  "), "  >>>  OVERWRITE: ", WriteCmd)
    | extend InitiatingProcessFileName = WriteInitiator
    | extend InitiatingProcessCommandLine = WriteCmd
    | extend InitiatingProcessAccountDomain = ""
    | extend InitiatingProcessSHA256 = WriteSHA256;
// SeTcb local admin addition under SYSTEM context
let TcbLocalAdminAdd =
    DeviceProcessEvents
    | where Timestamp > ago(Lookback)
    | where FileName in~ ("net.exe", "net1.exe")
    | where ProcessCommandLine has "localgroup"
    | where ProcessCommandLine has_any ("administrators", "administratoren", "administrateurs")
    | where ProcessCommandLine has "/add"
    | where not(ProcessCommandLine has_any ("local service", "network service", "lokaler dienst", "netzwerkdienst"))
    | where InitiatingProcessAccountName in~ ("system", "lokales system", "systeme")
        or InitiatingProcessParentFileName in~ ("services.exe", "tcb.exe")
    | extend Technique = "SeTcb - Self-addition to the local administrators group under SYSTEM"
    | extend Tier = "Tier0"
    | extend Verdict = "Suspicious: net localgroup administrators /add in SYSTEM context, typical of tcb-lpe token abuse";
// LSASS dumping
let LsassDump =
    DeviceProcessEvents
    | where Timestamp > ago(Lookback)
    | where
        (ProcessCommandLine has "lsass" and ProcessCommandLine has_any ("-ma", "-mm", "/ma"))
        or (ProcessCommandLine has "comsvcs.dll" and ProcessCommandLine has_cs "MiniDump")
        or (FileName in~ ("procdump.exe", "procdump64.exe") and ProcessCommandLine has "lsass")
    | extend Technique = "SeDebug - LSASS memory dump (credential dumping)"
    | extend Tier = "Tier0"
    | extend Verdict = "Suspicious: LSASS dump - extraction of NTLM hashes/Kerberos keys from memory";
// Winlogon spawning unusual child processes
let WinlogonChild =
    DeviceProcessEvents
    | where Timestamp > ago(Lookback)
    | where InitiatingProcessFileName in~ ("winlogon.exe")
    | extend Child = tolower(FileName)
    | where Child in (SuspiciousChildren)
    | extend Technique = "SeDebug - Anomalous child process of winlogon.exe (token theft/migration)"
    | extend Tier = "Tier0"
    | extend Verdict = strcat("Suspicious: winlogon.exe launches ", Child, " - indicates token duplication or Meterpreter migration to SYSTEM");
// Service binPath hijack to dynamic/user paths
let ServiceBinPathHijack =
    DeviceProcessEvents
    | where Timestamp > ago(Lookback)
    | where FileName in~ ("sc.exe")
    | where ProcessCommandLine has "config"
    | where ProcessCommandLine has "binpath"
    | where ProcessCommandLine has_any (@"\temp\", @"\users\", @"\programdata\", @"\public\", @"\appdata\", @"\downloads\")
    | extend Technique = "SeRestore - Service binPath hijack to an atypical path"
    | extend Tier = "Tier1"
    | extend Verdict = "Suspicious: existing service redirected to a binary in a write-friendly path - SYSTEM code execution via SCM";
// Combine process-based rules
let ProcessBased =
    union RegHiveDump, TakeownIcacls, TcbLocalAdminAdd, LsassDump, WinlogonChild, ServiceBinPathHijack
    | project Timestamp, DeviceId, DeviceName,
        AccountName = coalesce(AccountName, InitiatingProcessAccountName),
        FileName, ProcessCommandLine,
        InitiatingProcessFileName, InitiatingProcessCommandLine,
        InitiatingProcessAccountDomain, InitiatingProcessSHA256,
        Technique, Tier, Verdict;
// Final union and FileProfile enrichment
ProcessBased
| union AccessibilitySwap
| extend Kill_Chain = "Privilege Escalation -> SYSTEM"
| project
    Timestamp,
    DeviceName,
    DeviceId,
    Account = AccountName,
    Domain = InitiatingProcessAccountDomain,
    Tier,
    Technique,
    Verdict,
    Process = FileName,
    CommandLine = ProcessCommandLine,
    ParentProcess = InitiatingProcessFileName,
    ParentCommandLine = InitiatingProcessCommandLine,
    ParentSHA256 = InitiatingProcessSHA256
| invoke FileProfile(ParentSHA256, 1000)
| project
    Timestamp, DeviceName, DeviceId, Account, Domain, Tier, Technique, Verdict,
    Process, CommandLine, ParentProcess, ParentCommandLine, ParentSHA256,
    ParentGlobalPrevalence = GlobalPrevalence,
    ParentFirstSeen = GlobalFirstSeen,
    ParentSigner = Signer,
    ParentSignatureState = SignatureState,
    ParentIsMicrosoftSigned = IsRootSignerMicrosoft
| sort by Timestamp desc
```
