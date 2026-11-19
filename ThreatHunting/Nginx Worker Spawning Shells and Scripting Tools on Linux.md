# *Nginx Worker Spawning Shells and Scripting Tools on Linux*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1505.003 | Server Software Component: Web Shell | https://attack.mitre.org/techniques/T1505/003 |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | https://attack.mitre.org/techniques/T1059/004 |
| T1190 | Exploit Public-Facing Application | https://attack.mitre.org/techniques/T1190 |



#### Description

This query monitors Linux endpoints onboarded to Microsoft Defender for Endpoint and looks for signs that the nginx web server is being abused for code execution. It scans DeviceProcessEvents for processes started directly by nginx or nginx-debug worker processes, and for shell processes launched by nginx that in turn start a scripting or networking tool such as python, perl, php, nc, socat, curl or wget. Such a process chain is typical for a web shell or for an exploited web application that runs commands on the host. Processes whose command line contains common reverse shell fragments, such as /dev/tcp, bash -i, mkfifo, base64 -d or piping into sh or bash, are labeled separately and receive a more specific attack method. The query also reviews DeviceFileEvents for files that nginx writes to /tmp, /dev/shm or /var/tmp, which can indicate payload staging. The lookback window is one day and is set in the lookback parameter. The lists of shells, interpreters and reverse shell patterns are defined as let variables and can be extended or reduced for the environment. Possible false positives include legitimate nginx hooks, health checks or deployment scripts that call shells, and applications that cache temporary files in the listed directories, so the results should be correlated with the web application logs and the affected host before action is taken. Blind spots include payloads that run in memory without spawning a child process, and nginx modules or interpreters embedded in the worker process, which do not appear as separate process events.

#### Author
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let lookback = 1d;
let correlationWindow = 2h;
let correlationBin = correlationWindow / 2.0;
// Set to false if FolderPath contains only the directory in the corresponding table.
let fileFolderPathIncludesFileName = true;
let processFolderPathIncludesFileName = true;
let nginxParents = dynamic(["nginx", "nginx-debug"]);
let shellNames = dynamic(["sh", "bash", "dash", "ash", "zsh", "ksh"]);
let suspiciousTools = dynamic([
    "python", "python3", "perl", "ruby", "php", "node", "lua", "awk", "gawk",
    "nc", "ncat", "netcat", "socat", "openssl", "telnet", "curl", "wget",
    "ssh", "sftp", "busybox"
]);
let reverseShellPatterns = @"/dev/tcp|\bbash\s+-i\b|\bmkfifo\b|\bbase64\s+-d\b|(^|\s)-e\s+/bin/(sh|bash)\b|\|\s*(sh|bash)\b";
let isTempPath = (path:string) {
    path == "/tmp" or path startswith_cs "/tmp/"
        or path == "/var/tmp" or path startswith_cs "/var/tmp/"
        or path == "/dev/shm" or path startswith_cs "/dev/shm/"
};
let fullPath = (folderPath:string, fileName:string, pathIncludesFileName:bool) {
    iff(
        pathIncludesFileName,
        trim_end("/", folderPath),
        iff(
            isnotempty(fileName),
            strcat(trim_end("/", folderPath), "/", fileName),
            ""
        )
    )
};
let processDetections =
    DeviceProcessEvents
    | where Timestamp >= ago(lookback)
    | where ActionType == "ProcessCreated"
    | where InitiatingProcessFileName in~ (nginxParents)
        or (
            InitiatingProcessFileName in~ (shellNames)
            and InitiatingProcessParentFileName in~ (nginxParents)
        )
    | where FileName in~ (shellNames) or FileName in~ (suspiciousTools)
    | extend PatternMatched = ProcessCommandLine matches regex reverseShellPatterns
    | extend AttackMethod = case(
        PatternMatched,
            "Possible reverse shell pattern in nginx-related process",
        InitiatingProcessFileName in~ (nginxParents),
            "Shell or tool started by nginx",
        "Shell or tool started by an nginx child shell"
    )
    | project
        Timestamp,
        DeviceName,
        AttackMethod,
        Reason = strcat(
            "Initiator=", InitiatingProcessFileName,
            " | Parent=", InitiatingProcessParentFileName,
            " | Child=", FileName,
            iff(PatternMatched, " | Suspicious command-line pattern", "")
        ),
        Detail = tostring(ProcessCommandLine),
        Context = tostring(InitiatingProcessCommandLine);
let writtenTempFiles = materialize(
    DeviceFileEvents
    | where Timestamp >= ago(lookback + correlationWindow)
    | where ActionType in ("FileCreated", "FileModified")
    | where InitiatingProcessFileName in~ (nginxParents)
    | where isTempPath(FolderPath)
    | extend FullFilePath = fullPath(
        FolderPath,
        FileName,
        fileFolderPathIncludesFileName
    )
    | project
        DeviceId,
        DeviceName,
        WriteTime = Timestamp,
        FullFilePath,
        OriginalFolderPath = FolderPath,
        WrittenFileName = FileName,
        WriteAction = ActionType,
        WriterCmd = InitiatingProcessCommandLine
);
let tempFileDetections =
    writtenTempFiles
    | where WriteTime >= ago(lookback)
    | project
        Timestamp = WriteTime,
        DeviceName,
        AttackMethod = "Temp file created or modified by nginx",
        Reason = strcat(
            "Action=", WriteAction,
            " | FolderPath=", OriginalFolderPath,
            " | FileName=", iff(isempty(WrittenFileName), "<missing>", WrittenFileName)
        ),
        Detail = tostring(FullFilePath),
        Context = tostring(WriterCmd);
let directTempExecutions =
    writtenTempFiles
    | where isnotempty(DeviceId)
        and isnotempty(WrittenFileName)
        and isnotempty(FullFilePath)
    | join kind=inner (
        DeviceProcessEvents
        | where Timestamp >= ago(lookback)
        | where ActionType == "ProcessCreated"
        | where isnotempty(DeviceId) and isnotempty(FolderPath)
        | where isTempPath(FolderPath)
        | extend FullExecPath = fullPath(
            FolderPath,
            FileName,
            processFolderPathIncludesFileName
        )
        | where isnotempty(FullExecPath)
        | project
            DeviceId,
            FullExecPath,
            ExecTime = Timestamp,
            ExecReportId = ReportId,
            ExecCmd = ProcessCommandLine,
            ExecInitiator = InitiatingProcessFileName,
            ExecParent = InitiatingProcessParentFileName
    ) on DeviceId, $left.FullFilePath == $right.FullExecPath
    | where ExecTime >= WriteTime
        and ExecTime <= WriteTime + correlationWindow
    | summarize arg_max(
        WriteTime,
        DeviceName,
        WriteAction,
        WriterCmd,
        ExecCmd,
        ExecInitiator,
        ExecParent
    ) by DeviceId, ExecTime, ExecReportId, FullFilePath
    | project
        Timestamp = ExecTime,
        DeviceName,
        AttackMethod = "Nginx-created or modified temp path later started on the same device",
        Reason = strcat(
            "Path=", FullFilePath,
            " | File action=", WriteAction,
            " | Process initiator=", ExecInitiator,
            " | Parent=", ExecParent
        ),
        Detail = tostring(ExecCmd),
        Context = tostring(WriterCmd);
let tempFileReferences =
    writtenTempFiles
    | where isnotempty(DeviceId)
        and isnotempty(WrittenFileName)
        and isnotempty(FullFilePath)
    | extend TimeKey = bin(WriteTime, correlationBin)
    | join kind=inner (
        DeviceProcessEvents
        | where Timestamp >= ago(lookback)
        | where ActionType == "ProcessCreated"
        | where isnotempty(DeviceId) and isnotempty(ProcessCommandLine)
        | where ProcessCommandLine has_any ("tmp", "shm")
        | where ProcessCommandLine contains_cs "/tmp/"
            or ProcessCommandLine contains_cs "/dev/shm/"
        | extend
            FullExecPath = fullPath(
                FolderPath,
                FileName,
                processFolderPathIncludesFileName
            ),
            TimeKey = range(
                bin(Timestamp - correlationWindow, correlationBin),
                bin(Timestamp, correlationBin),
                correlationBin
            )
        | mv-expand TimeKey to typeof(datetime)
        | project
            DeviceId,
            ExecTime = Timestamp,
            TimeKey,
            ExecReportId = ReportId,
            FullExecPath,
            ExecCmd = ProcessCommandLine,
            ExecInitiator = InitiatingProcessFileName,
            ExecParent = InitiatingProcessParentFileName
    ) on DeviceId, TimeKey
    | where ExecTime >= WriteTime
        and ExecTime <= WriteTime + correlationWindow
    | where ExecCmd contains_cs FullFilePath
    | where FullExecPath != FullFilePath
    | summarize arg_max(
        WriteTime,
        DeviceName,
        WriteAction,
        WriterCmd,
        ExecCmd,
        ExecInitiator,
        ExecParent
    ) by DeviceId, ExecTime, ExecReportId, FullFilePath
    | project
        Timestamp = ExecTime,
        DeviceName,
        AttackMethod = "Nginx-created or modified temp path mentioned in a later command line",
        Reason = strcat(
            "Path substring=", FullFilePath,
            " | File action=", WriteAction,
            " | Process initiator=", ExecInitiator,
            " | Parent=", ExecParent
        ),
        Detail = tostring(ExecCmd),
        Context = tostring(WriterCmd);
union processDetections, tempFileDetections, directTempExecutions, tempFileReferences
```
