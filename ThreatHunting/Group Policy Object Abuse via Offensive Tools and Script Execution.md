# *Group Policy Object Abuse via Offensive Tools and Script Execution*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1484.001 | Domain Policy Modification: Group Policy Modification | https://attack.mitre.org/techniques/T1484/001 |
| T1053.005 | Scheduled Task/Job: Scheduled Task | https://attack.mitre.org/techniques/T1053/005 |
| T1136.001 | Create Account: Local Account | https://attack.mitre.org/techniques/T1136/001 |



#### Description

This query monitors DeviceProcessEvents and DeviceEvents for signs of Group Policy Object abuse, a technique attackers use to push persistence, local admin rights, or arbitrary scripts to every computer or user in scope of a GPO. The ProcessSignals branch looks for command lines containing GPO related flags such as --gpo or -gpo-id, or for process creation initiated by gpscript.exe, then matches the command line against known command line patterns of SharpGPOAbuse, StandIn, and pyGPOAbuse, three public offensive tools that programmatically add scheduled tasks, logon scripts, or local administrators through a GPO. The TaskSignals branch looks at scheduled task creation or update events whose initiating process is svchost.exe running the gpsvc service, which is how GPO client side extensions register scheduled tasks on a target machine, and extracts the task action for further inspection. Both branches feed the extracted command line or task action into the RiskyPayload function, which decodes base64 encoded PowerShell (-EncodedCommand and its abbreviations), strips UTF-16LE padding, and flags account creation via net user and net localgroup or their PowerShell equivalents, mshta execution of remote or inline HTA content, and download and in-memory execution patterns such as Invoke-WebRequest combined with Invoke-Expression. The Lookback variable controls the scan window and should be tuned to the scheduling interval of the detection rule. Analysts should expect some noise from legitimate GPO administration tooling and should validate that AccountDomain and InitiatingProcessCommandLine correspond to expected change management activity before escalating.

#### Author
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let Lookback = 1h;
let RiskyPayload = (Text:string) {
    // ASCII UTF-16LE payloads used by pyGPOAbuse -powershell.
    let Encoded = extract(
        @"(?i)-(?:e|en|enc|encodedcommand)\s+[""']?([a-z0-9+/]{20,}={0,2})",
        1, Text);
    let Decoded = replace_string(base64_decode_tostring(Encoded), "\u0000", "");
    let C = tolower(strcat(Text, " ", Decoded));
    case(
        C matches regex @"\bnet(?:1)?(?:\.exe)?\s+user\b[^;&|\r\n]*\s/add\b"
            and C matches regex @"\bnet(?:1)?(?:\.exe)?\s+localgroup\b[^;&|\r\n]*\s/add\b",
            "Account creation and local group modification",
        C contains "new-localuser" and C contains "add-localgroupmember",
            "PowerShell account creation and group modification",
        C matches regex @"\bmshta(?:\.exe)?\b"
            and (C contains "http://" or C contains "https://"
                or C contains "javascript:" or C contains "vbscript:"),
            "Remote or inline HTA execution",
        (C contains "downloadstring" or C contains "invoke-webrequest"
            or C matches regex @"\biwr\b")
            and (C matches regex @"\biex\b" or C contains "invoke-expression"),
            "Download and in-memory execution",
        ""
    )
};
let ProcessSignals =
    DeviceProcessEvents
    | where Timestamp > ago(Lookback)
    | where ActionType == "ProcessCreated"
    | where ProcessCommandLine contains "--gpo"
        or ProcessCommandLine contains "-gpo-id"
        or InitiatingProcessFileName =~ "gpscript.exe"
        or InitiatingProcessCommandLine has_any ("sysvol", "history")
    | extend C = tolower(ProcessCommandLine)
    | extend ToolOperation = case(
        C contains "--gponame"
            and (C contains "--addcomputertask" or C contains "--addusertask"
                or C contains "--addcomputerscript" or C contains "--adduserscript"
                or C contains "--addlocaladmin" or C contains "--adduserrights"),
            "SharpGPOAbuse-compatible GPO write operation",
        C contains "--gpo" and C contains "--filter"
            and (C contains "--localadmin"
                or (C contains "--tasktype" and C contains "--taskname"
                    and C contains "--command")),
            "StandIn-compatible GPO write operation",
        C contains "pygpoabuse" and C contains "-gpo-id",
            "pyGPOAbuse invocation on a monitored Windows host",
        ""
    )
    | extend GpoScriptContext =
        InitiatingProcessFileName =~ "gpscript.exe"
        or InitiatingProcessCommandLine matches regex
            @"(?i)\\(?:sysvol\\[^\\]+\\policies|group policy\\history)\\\{[0-9a-f-]{36}\}\\(?:machine|user)\\scripts\\"
    | where isnotempty(ToolOperation) or GpoScriptContext
    | extend PayloadReason = RiskyPayload(ProcessCommandLine)
    | where isnotempty(ToolOperation)
        or (GpoScriptContext and isnotempty(PayloadReason))
    | extend DetectionReason = iff(
        isnotempty(ToolOperation), ToolOperation,
        strcat("GPO script execution: ", PayloadReason))
    | project Timestamp, DeviceId, DeviceName, ReportId, DetectionReason,
        AccountDomain, AccountName, AccountSid,
        FileName, ProcessCommandLine, InitiatingProcessFileName,
        InitiatingProcessCommandLine,
        TaskName = "", TaskAction = "";
let TaskSignals =
    DeviceEvents
    | where Timestamp > ago(Lookback)
    | where ActionType in ("ScheduledTaskCreated", "ScheduledTaskUpdated")
    | where InitiatingProcessFileName =~ "svchost.exe"
    | where InitiatingProcessCommandLine has "gpsvc"
    | extend AF = parse_json(tostring(AdditionalFields))
    | extend TaskName = tostring(AF.TaskName),
        TaskContent = tostring(AF.TaskContent)
    | extend TaskJson = parse_json(TaskContent)
    | extend TaskAction = coalesce(
        tostring(TaskJson.Actions.Exec),
        tostring(TaskJson.Task.Actions.Exec),
        tostring(parse_xml(TaskContent).Task.Actions.Exec))
    | extend PayloadReason = RiskyPayload(TaskAction)
    | where isnotempty(PayloadReason)
    | extend DetectionReason = strcat(
        "GPO scheduled task registration: ", PayloadReason)
    | project Timestamp, DeviceId, DeviceName, ReportId, DetectionReason,
        AccountDomain, AccountName, AccountSid,
        FileName, ProcessCommandLine, InitiatingProcessFileName,
        InitiatingProcessCommandLine, TaskName, TaskAction;
union ProcessSignals, TaskSignals
```
