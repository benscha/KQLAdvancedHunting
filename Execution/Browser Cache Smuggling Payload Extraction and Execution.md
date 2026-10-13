# *Browser Cache Smuggling Payload Extraction and Execution*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1204.004 | User Execution: Malicious Copy and Paste | https://attack.mitre.org/techniques/T1204/004 |
| T1059 | Command and Scripting Interpreter | https://attack.mitre.org/techniques/T1059 |



#### Description

This query detects the process chain used in browser cache smuggling attacks, where a malicious payload is delivered through the browser cache (for example disguised as an image) and then extracted and executed by a script interpreter or archive tool, typically triggered by a ClickFix style copy and paste lure.

Microsoft Defender for Endpoint does not expose general file read telemetry in DeviceFileEvents, so the query uses a proxy: a process from a list of common readers (shells, script hosts, archive tools, curl, certutil and similar) whose command line mentions a browser cache location (Firefox cache2 entries or the Cache_Data folder used by all Chromium based browsers). This process and its direct child processes form the anchor family. The query then looks for files created, modified or renamed by that family within the pivot window, excluding the cache folders themselves, and finally for a process execution of such a file on the same device, either by full path or by file name when started by a member of the anchor family. This also covers relative invocations such as changing into a directory and starting a file by name.

The output includes the ExecutableLike flag, which marks payloads with executable or script extensions and helps with triage. Because the cache access is inferred from the command line, the query does not prove that the cache was actually read, and fileless variants that never write a payload to disk are not covered. These are best handled by a separate, simpler rule on the cache path in the command line alone. Tune the Lookback, PivotWindow and Readers parameters to your environment and add exclusions for backup, cleanup or support scripts that legitimately touch browser cache folders. With a one hour rule frequency the lookback overlaps by 15 minutes, so deduplicate alerts by ReportId.


#### Author
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let Lookback = 75m;
let PivotWindow = 10m;
let CacheRegex = @"(?i)(cache2[\\/]entries|[\\/]Cache_Data)";
let Readers = dynamic(["cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","python.exe","pythonw.exe","node.exe","tar.exe","expand.exe","7z.exe","xcopy.exe","robocopy.exe","certutil.exe","curl.exe"]);
let ExecutableExt = @"(?i)\.(exe|dll|ps1|js|jse|vbs|vbe|wsf|hta|bat|cmd|scr|msi|jar|lnk|cpl)$";
let Anchors = DeviceProcessEvents
    | where Timestamp > ago(Lookback)
    | where FileName in~ (Readers)
    | where ProcessCommandLine matches regex CacheRegex
    | where isnotempty(ProcessUniqueId)
    | project DeviceId, DeviceName, AnchorTime = Timestamp, AnchorId = ProcessUniqueId, AnchorCmd = ProcessCommandLine;
let AnchorIds = toscalar(Anchors | summarize make_set(AnchorId));
// Process family: anchor plus direct child processes
let Family = Anchors
    | project DeviceId, DeviceName, AnchorTime, AnchorCmd, AnchorId, MemberId = AnchorId
    | union (
        DeviceProcessEvents
        | where Timestamp > ago(Lookback + PivotWindow)
        | where InitiatingProcessUniqueId in (AnchorIds)
        | project DeviceId, MemberId = ProcessUniqueId, AnchorId = InitiatingProcessUniqueId
        | join kind=inner (Anchors) on DeviceId, AnchorId
        | project DeviceId, DeviceName, AnchorTime, AnchorCmd, AnchorId, MemberId
    );
let FamilyIds = toscalar(Family | summarize make_set(MemberId));
let Writes = materialize(
    DeviceFileEvents
    | where Timestamp > ago(Lookback + PivotWindow)
    | where InitiatingProcessUniqueId in (FamilyIds)
    | where ActionType in ("FileCreated", "FileModified", "FileRenamed")
    | where not(FolderPath matches regex CacheRegex)
    | project DeviceId, WriterId = InitiatingProcessUniqueId, WriteTime = Timestamp,
        PayloadPath = strcat(FolderPath, "\\", FileName), PayloadName = FileName
    | join kind=inner (Family) on DeviceId, $left.WriterId == $right.MemberId
    | where WriteTime between (AnchorTime .. (AnchorTime + PivotWindow))
    | extend ExecutableLike = PayloadName matches regex ExecutableExt
    | project DeviceId, DeviceName, AnchorCmd, WriteTime, PayloadPath, PayloadName, ExecutableLike
);
let WriteDevices = toscalar(Writes | summarize make_set(DeviceId));
Writes
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(Lookback + 2 * PivotWindow)
    | where DeviceId in (WriteDevices)
    | project DeviceId, ReportId, ExecutionTime = Timestamp,
        ExecPath = strcat(FolderPath, "\\", FileName),
        ExecCmd = ProcessCommandLine,
        ExecAccount = AccountName,
        ExecParentId = InitiatingProcessUniqueId
) on DeviceId
| where ExecutionTime between (WriteTime .. (WriteTime + PivotWindow))
| where ExecPath =~ PayloadPath
    or ExecCmd contains PayloadPath
    // relative invocations (e.g. "cd /d %TEMP% && start a.exe"), limited to children of the anchor family
    or (ExecParentId in (FamilyIds) and ExecCmd contains PayloadName)
| project Timestamp = ExecutionTime, ReportId, DeviceId, DeviceName, ExecAccount,
    Evidence = "Cache path mentioned in process command line; file read is not observable",
    ExecutableLike, AnchorCmd, PayloadPath, WriteTime, ExecPath, ExecCmd
```
