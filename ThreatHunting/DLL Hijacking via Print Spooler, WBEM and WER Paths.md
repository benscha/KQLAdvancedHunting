# *DLL Hijacking via Print Spooler, WBEM and WER Paths*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1574.001 | Hijack Execution Flow: DLL Search Order Hijacking | https://attack.mitre.org/techniques/T1574/001 |
| T1068 | Exploitation for Privilege Escalation | https://attack.mitre.org/techniques/T1068 |



#### Description

This rule monitors DeviceFileEvents and DeviceImageLoadEvents in Microsoft Defender for Endpoint to detect a specific DLL hijacking pattern that privileged Windows components are known to be vulnerable to. It first looks, over the preceding two hours, for file write, creation, or rename activity targeting three well known hijackable DLL names: Printconfig.dll under the Print Spooler driver directory, tzres.dll under the WBEM folder, and phoneinfo.dll, each written to the exact system32 path where the vulnerable component expects to load them from. The write must originate from a process running at low, medium, or untrusted integrity and from an account that is not SYSTEM, LOCAL SERVICE, or NETWORK SERVICE, since a write from one of those accounts would already be the privileged context rather than the staging step, and the written file must carry a recorded SHA1 hash. The query then checks DeviceImageLoadEvents over the following hour for the same device, path, and SHA1 being loaded by a process running as SYSTEM, LOCAL SERVICE, or NETWORK SERVICE within a 30 minute correlation window after the write. A match means a low privileged write was followed by a privileged image load of the exact same payload, which is the hallmark of successful DLL hijacking and local privilege escalation rather than a benign file operation. The query labels the result with an AttackPath column naming which of the three known hijack paths fired. The CorrelationWindow parameter can be widened if the scheduled service that loads the DLL runs less frequently, and the lookback windows should stay aligned with the query's run interval. Because the detection relies on the write and load SHA1 matching, environments where endpoint protection strips or fails to populate SHA1 on one of the two event types will produce false negatives, and the allowlist of SYSTEM like SIDs should be reviewed if other service accounts legitimately load these DLLs in the environment.

#### Author
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let SuspiciousWrites =
    DeviceFileEvents
    | where Timestamp >= ago(2h)
    | where ActionType in ("FileCreated", "FileModified", "FileRenamed")
    | where FileName in~ ("Printconfig.dll", "tzres.dll", "phoneinfo.dll")
    | where FolderPath matches regex @"(?i)^[a-z]:\\windows\\system32\\(spool\\drivers\\(x64|w32x86)\\3\\printconfig\.dll|wbem\\tzres\.dll|phoneinfo\.dll)$"
    | where InitiatingProcessIntegrityLevel in~ ("Low", "Medium", "Untrusted")
    | where isnotempty(InitiatingProcessAccountSid)
    | where InitiatingProcessAccountSid !in ("S-1-5-18", "S-1-5-19", "S-1-5-20")
    | where isnotempty(SHA1)
    | project DeviceId,
        DllPath = tolower(FolderPath),
        PayloadSHA1 = tolower(SHA1),
        WriteTime = Timestamp,
        WriteAction = ActionType,
        WriterAccountSid = InitiatingProcessAccountSid,
        WriterAccount = strcat(InitiatingProcessAccountDomain, @"\", InitiatingProcessAccountName),
        WriterProcess = InitiatingProcessFileName,
        WriterCommandLine = InitiatingProcessCommandLine,
        WriterIntegrity = InitiatingProcessIntegrityLevel,
        WriterProcessUniqueId = InitiatingProcessUniqueId;
DeviceImageLoadEvents
| where Timestamp >= ago(1h)
| where FileName in~ ("Printconfig.dll", "tzres.dll", "phoneinfo.dll")
| where InitiatingProcessAccountSid in ("S-1-5-18", "S-1-5-19", "S-1-5-20")
| where isnotempty(SHA1)
| project Timestamp, DeviceId, DeviceName, ReportId, FileName,
    DllPath = tolower(FolderPath),
    PayloadSHA1 = tolower(SHA1),
    LoaderProcess = InitiatingProcessFileName,
    LoaderCommandLine = InitiatingProcessCommandLine,
    LoaderAccountSid = InitiatingProcessAccountSid,
    LoaderProcessUniqueId = InitiatingProcessUniqueId
| join kind=inner SuspiciousWrites on DeviceId, DllPath, PayloadSHA1
| where Timestamp >= WriteTime and Timestamp <= WriteTime + 30m
| summarize arg_max(WriteTime, *) by Timestamp, DeviceId, ReportId
| extend AttackPath = case(
    FileName =~ "Printconfig.dll", "Print Spooler DLL hijacking",
    FileName =~ "tzres.dll", "WBEM DLL hijacking",
    "WER phoneinfo.dll hijacking")
| project Timestamp, DeviceId, DeviceName, ReportId, AttackPath,
    DllPath, PayloadSHA1, WriteTime, WriteAction,
    WriterAccount, WriterAccountSid, WriterProcess, WriterCommandLine,
    WriterIntegrity, WriterProcessUniqueId,
    LoaderProcess, LoaderCommandLine, LoaderAccountSid, LoaderProcessUniqueId
```
