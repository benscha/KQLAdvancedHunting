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

#### optimized/extended Version
```KQL
let lookback = 1d;
let correlationWindow = 2h;
let correlationBin = correlationWindow / 2.0;
let deviceInfoLookback = 7d;
let pidTimeTolerance = 1s;
// Set to false if FolderPath in the respective table only contains the folder.
let fileFolderPathIncludesFileName = true;
let processFolderPathIncludesFileName = true;
// App servers as an additional root; telemetry branch toggle.
let includeAppServers = true;
let includeTempTelemetry = false;
// Reference correlation only for nginx writers (app servers produce many legitimate hits here,
// e.g., ImageMagick or virus scans on upload temp files).
let referenceWriterClasses = dynamic(["nginx-self", "nginx-tree"]);
let nginxParents = dynamic(["nginx", "nginx-debug", "openresty"]);
let appServerRegex = @"(?i)^(php-fpm[\d.]*|php[\d.]*-fpm|php-cgi[\d.]*|uwsgi)$";
// Lists contain normalized base names (leading letters only).
let shellNames = dynamic(["sh", "bash", "dash", "ash", "zsh", "ksh"]);
let suspiciousTools = dynamic([
    "python", "perl", "ruby", "php", "node", "lua", "awk", "gawk", "mawk", "nawk",
    "nc", "ncat", "netcat", "socat", "openssl", "telnet", "curl", "wget",
    "ssh", "sftp", "scp", "ftp", "tftp", "busybox", "chmod"
]);
let reconTools = dynamic([
    "id", "whoami", "uname", "hostname", "ifconfig", "ip", "netstat", "ss",
    "getent", "printenv", "crontab", "ps"
]);
// Extended reverse shell / download-and-execute patterns
let reverseShellPatterns = @"/dev/(tcp|udp)/|\b(ba)?sh\s+-i\b|\bmkfifo\b|\bmknod\b|\bbase64\s+(-d|--decode)\b|(^|\s)-e\s+\S*(ba)?sh\b|\bn(c|cat|etcat)\b.*\s-c\s|\|\s*(/usr)?(/bin/)?(ba|da)?sh\b|pty\.spawn|socket\.socket|fsockopen|-rsocket|use\s+Socket|\bexec:|\bs_client\b|\bexec\s+\d+<>|0<&\d+";
// nginx-owned temp paths (adjust to match your configuration)
let nginxOwnTempRegex = @"^/tmp/(nginx/)?(client_body|client|proxy|fastcgi|uwsgi|scgi)_temp(/|$)|^/tmp/nginx\.pid$";
// Characters allowed before and after a path reference
let boundaryChars = dynamic(["", " ", "\t", "'", "\"", ";", "|", "&", "(", ")", "<", ">", "=", "`"]);
// ---------------------------------------------------------------- Helper functions
let isTempPath = (path:string) {
    path == "/tmp" or path startswith_cs "/tmp/"
        or path == "/var/tmp" or path startswith_cs "/var/tmp/"
        or path == "/dev/shm" or path startswith_cs "/dev/shm/"
};
let fullPath = (folderPath:string, fileName:string, pathIncludesFileName:bool) {
    iff(
        pathIncludesFileName,
        trim_end("/", folderPath),
        iff(isnotempty(fileName), strcat(trim_end("/", folderPath), "/", fileName), "")
    )
};
// python3.11 -> python, nc.openbsd -> nc, php-fpm8.2 -> php
let normalizeBin = (name:string) {
    extract(@"^([a-z]+)", 1, tolower(name))
};
// Classification of the root process
let webParentClass = (name:string) {
    case(
        name in~ (nginxParents), "nginx",
        includeAppServers and name matches regex appServerRegex, "appserver",
        ""
    )
};
// Checks the first occurrence of needle in cmd for clean character boundaries.
// Limitation: only the first occurrence is checked.
let refWithBoundary = (cmd:string, needle:string, allowSlashBefore:bool) {
    let pos = indexof(cmd, needle);
    let before = iff(pos > 0, substring(cmd, pos - 1, 1), "");
    let after = substring(cmd, pos + strlen(needle), 1);
    isnotempty(needle) and pos >= 0
        and (before in (boundaryChars) or (allowSlashBefore and before == "/"))
        and after in (boundaryChars)
};
// ---------------------------------------------------------------- Linux devices
let linuxDevices = materialize(
    DeviceInfo
    | where Timestamp >= ago(deviceInfoLookback)
    | where OSPlatform == "Linux"
    | distinct DeviceId
);
// ---------------------------------------------------------------- Process tree
// Level 1: direct children of nginx or app servers
let level1 = materialize(
    DeviceProcessEvents
    | where Timestamp >= ago(lookback + correlationWindow)
    | where ActionType == "ProcessCreated"
    | where InitiatingProcessFileName in~ (nginxParents)
        or (includeAppServers and InitiatingProcessFileName matches regex appServerRegex)
    | where DeviceId in (linuxDevices)
    | extend RootClass = webParentClass(InitiatingProcessFileName)
    | where isnotempty(RootClass)
    // Exclude re-exec / binary upgrade of nginx or php-fpm itself
    | where FileName !~ InitiatingProcessFileName and not(FileName in~ (nginxParents))
    | project
        Timestamp, DeviceId, DeviceName, ReportId, ProcessId, ProcessCreationTime,
        FileName, FolderPath, ProcessCommandLine, AccountName,
        InitiatingProcessId, InitiatingProcessCreationTime, InitiatingProcessFileName,
        InitiatingProcessCommandLine, InitiatingProcessParentFileName,
        RootClass,
        RootName = InitiatingProcessFileName,
        Depth = 1,
        Chain = strcat(InitiatingProcessFileName, " > ", FileName)
);
// Load only devices with hits at level 1 for deeper levels
let treeDevices = level1 | distinct DeviceId;
let treeProc = materialize(
    DeviceProcessEvents
    | where Timestamp >= ago(lookback + correlationWindow)
    | where ActionType == "ProcessCreated"
    | where DeviceId in (treeDevices)
    | project
        Timestamp, DeviceId, DeviceName, ReportId, ProcessId, ProcessCreationTime,
        FileName, FolderPath, ProcessCommandLine, AccountName,
        InitiatingProcessId, InitiatingProcessCreationTime, InitiatingProcessFileName,
        InitiatingProcessCommandLine, InitiatingProcessParentFileName
);
let level2 =
    level1
    | project P_DeviceId = DeviceId, P_Pid = ProcessId, P_Start = ProcessCreationTime,
        RootClass, RootName, P_Chain = Chain
    | join kind=inner treeProc
        on $left.P_DeviceId == $right.DeviceId, $left.P_Pid == $right.InitiatingProcessId
    | where InitiatingProcessCreationTime between ((P_Start - pidTimeTolerance) .. (P_Start + pidTimeTolerance))
    | extend Depth = 2, Chain = strcat(P_Chain, " > ", FileName)
    | project-away P_DeviceId, P_Pid, P_Start, P_Chain;
let level3 =
    level2
    | project P_DeviceId = DeviceId, P_Pid = ProcessId, P_Start = ProcessCreationTime,
        RootClass, RootName, P_Chain = Chain
    | join kind=inner treeProc
        on $left.P_DeviceId == $right.DeviceId, $left.P_Pid == $right.InitiatingProcessId
    | where InitiatingProcessCreationTime between ((P_Start - pidTimeTolerance) .. (P_Start + pidTimeTolerance))
    | extend Depth = 3, Chain = strcat(P_Chain, " > ", FileName)
    | project-away P_DeviceId, P_Pid, P_Start, P_Chain;
// Full tree (including unreported processes, important for writer attribution).
// Deduplication in case a process is reached via multiple paths (e.g., exec without fork).
let spawnedTree = materialize(
    union level1, level2, level3
    | summarize arg_min(Depth, *) by DeviceId, ReportId, Timestamp
);
// ---------------------------------------------------------------- Detection A: Process tree
let processDetections =
    spawnedTree
    | where Timestamp >= ago(lookback)
    | extend ChildBase = normalizeBin(FileName)
    | extend
        PatternMatched = ProcessCommandLine matches regex reverseShellPatterns,
        IsShell = ChildBase in (shellNames),
        IsTool = ChildBase in (suspiciousTools),
        IsRecon = ChildBase in (reconTools)
    // nginx: report everything. App servers: only pattern, tools, or recon (shells alone are
    // normal for PHP exec()/system(), since those always run via /bin/sh).
    | where RootClass == "nginx" or PatternMatched or IsTool or IsRecon
    | extend Severity = case(
        PatternMatched, "High",
        RootClass == "nginx" and (IsShell or IsTool or IsRecon), "High",
        "Medium"
    )
    | extend AttackMethod = case(
        PatternMatched, "Reverse shell pattern in web server process tree",
        RootClass == "nginx", "Process started in nginx process tree",
        "Tool or recon command started in app server process tree"
    )
    | project
        Timestamp, DeviceId, DeviceName, ReportId, AccountName, Severity, AttackMethod,
        Reason = strcat(
            "Root=", RootName,
            " | Depth=", tostring(Depth),
            " | Chain=", Chain,
            iff(PatternMatched, " | Suspicious command-line pattern", "")
        ),
        Detail = tostring(ProcessCommandLine),
        Context = tostring(InitiatingProcessCommandLine);
// ---------------------------------------------------------------- Temp writes
let tempWrites = materialize(
    DeviceFileEvents
    | where Timestamp >= ago(lookback + correlationWindow)
    | where ActionType in ("FileCreated", "FileModified", "FileRenamed")
    | where DeviceId in (linuxDevices)
    | where isTempPath(FolderPath)
    | where InitiatingProcessFileName in~ (nginxParents)
        or (includeAppServers and InitiatingProcessFileName matches regex appServerRegex)
        or DeviceId in (treeDevices)
    | extend FullFilePath = fullPath(FolderPath, FileName, fileFolderPathIncludesFileName)
    | where isnotempty(FullFilePath) and isnotempty(FileName)
    | project
        DeviceId, DeviceName,
        WriteTime = Timestamp,
        WriteReportId = ReportId,
        FullFilePath,
        FileDir = extract(@"^(.*)/[^/]*$", 1, FullFilePath),
        OriginalFolderPath = FolderPath,
        WrittenFileName = FileName,
        WriteAction = ActionType,
        WriterName = InitiatingProcessFileName,
        WriterCmd = InitiatingProcessCommandLine,
        WriterPid = InitiatingProcessId,
        WriterStart = InitiatingProcessCreationTime
);
// Writes by nginx / app server itself
let selfWrites =
    tempWrites
    | extend WriterClass = webParentClass(WriterName)
    | where isnotempty(WriterClass)
    | extend WriterClass = strcat(WriterClass, "-self"), WriterChain = WriterName;
// Writes by processes in the tree (e.g., nginx > sh > curl -o /tmp/x)
let treeWrites =
    spawnedTree
    | project T_DeviceId = DeviceId, T_Pid = ProcessId, T_Start = ProcessCreationTime, RootClass, Chain
    | join kind=inner tempWrites
        on $left.T_DeviceId == $right.DeviceId, $left.T_Pid == $right.WriterPid
    | where WriterStart between ((T_Start - pidTimeTolerance) .. (T_Start + pidTimeTolerance))
    | extend WriterClass = strcat(RootClass, "-tree"), WriterChain = Chain
    | project-away T_DeviceId, T_Pid, T_Start, RootClass, Chain;
let writtenTempFiles = materialize(
    union selfWrites, treeWrites
    | project DeviceId, DeviceName, WriteTime, WriteReportId, FullFilePath, FileDir,
        OriginalFolderPath, WrittenFileName, WriteAction, WriterClass, WriterChain, WriterCmd
);
// Process events only for devices with relevant writes
let writerDevices = writtenTempFiles | distinct DeviceId;
let execProc = materialize(
    DeviceProcessEvents
    | where Timestamp >= ago(lookback)
    | where ActionType == "ProcessCreated"
    | where DeviceId in (writerDevices)
    | project Timestamp, DeviceId, ReportId, FileName, FolderPath, ProcessCommandLine,
        AccountName, InitiatingProcessFileName, InitiatingProcessParentFileName
);
// ---------------------------------------------------------------- Detection B: Execution
let directTempExecutions =
    writtenTempFiles
    | join kind=inner (
        execProc
        | where isnotempty(FolderPath) and isTempPath(FolderPath)
        | extend FullExecPath = fullPath(FolderPath, FileName, processFolderPathIncludesFileName)
        | where isnotempty(FullExecPath)
        | project DeviceId, FullExecPath,
            ExecTime = Timestamp, ExecReportId = ReportId,
            ExecCmd = ProcessCommandLine, ExecAccount = AccountName,
            ExecInitiator = InitiatingProcessFileName, ExecParent = InitiatingProcessParentFileName
    ) on DeviceId, $left.FullFilePath == $right.FullExecPath
    | where ExecTime between (WriteTime .. (WriteTime + correlationWindow))
    | summarize arg_max(WriteTime, DeviceName, WriteAction, WriterClass, WriterChain, WriterCmd,
        ExecCmd, ExecAccount, ExecInitiator, ExecParent)
        by DeviceId, ExecTime, ExecReportId, FullFilePath
    | project
        Timestamp = ExecTime, DeviceId, DeviceName, ReportId = ExecReportId,
        AccountName = ExecAccount,
        Severity = "High",
        AttackMethod = "Temp file written in web server context later executed",
        Reason = strcat(
            "Path=", FullFilePath,
            " | Writer=", WriterClass, " (", WriterChain, ")",
            " | File action=", WriteAction,
            " | Process initiator=", ExecInitiator,
            " | Parent=", ExecParent
        ),
        Detail = tostring(ExecCmd),
        Context = tostring(WriterCmd);
// ---------------------------------------------------------------- Detection C: Reference
let tempFileReferences =
    writtenTempFiles
    | where WriterClass in (referenceWriterClasses)
    | extend TimeKey = bin(WriteTime, correlationBin)
    | join kind=inner (
        execProc
        | where isnotempty(ProcessCommandLine)
        | where ProcessCommandLine has_any ("tmp", "shm")
        // without trailing slash so "cd /tmp && ..." is also captured
        | where ProcessCommandLine contains_cs "/tmp" or ProcessCommandLine contains_cs "/dev/shm"
        | extend
            FullExecPath = fullPath(FolderPath, FileName, processFolderPathIncludesFileName),
            TimeKey = range(
                bin(Timestamp - correlationWindow, correlationBin),
                bin(Timestamp, correlationBin),
                correlationBin
            )
        | mv-expand TimeKey to typeof(datetime)
        | project DeviceId, TimeKey,
            ExecTime = Timestamp, ExecReportId = ReportId, FullExecPath,
            ExecCmd = ProcessCommandLine, ExecAccount = AccountName,
            ExecInitiator = InitiatingProcessFileName, ExecParent = InitiatingProcessParentFileName
    ) on DeviceId, TimeKey
    | where ExecTime between (WriteTime .. (WriteTime + correlationWindow))
    | where FullExecPath != FullFilePath
    // absolute reference with character boundaries
    | extend AbsRef = refWithBoundary(ExecCmd, FullFilePath, false)
    // relative reference: "cd <dir>" plus file name (also "./name")
    | extend RelRef = not(AbsRef)
        and (refWithBoundary(ExecCmd, strcat("cd ", FileDir), false)
            or refWithBoundary(ExecCmd, strcat("cd ", FileDir, "/"), false))
        and refWithBoundary(ExecCmd, WrittenFileName, true)
    | where AbsRef or RelRef
    | summarize arg_max(WriteTime, DeviceName, WriteAction, WriterClass, WriterChain, WriterCmd,
        ExecCmd, ExecAccount, ExecInitiator, ExecParent, AbsRef)
        by DeviceId, ExecTime, ExecReportId, FullFilePath
    | project
        Timestamp = ExecTime, DeviceId, DeviceName, ReportId = ExecReportId,
        AccountName = ExecAccount,
        Severity = "Medium",
        AttackMethod = "Temp file written in nginx context referenced in later command line",
        Reason = strcat(
            "Path=", FullFilePath,
            " | Match=", iff(AbsRef, "absolute", "relative (cd + filename)"),
            " | Writer=", WriterClass, " (", WriterChain, ")",
            " | File action=", WriteAction,
            " | Process initiator=", ExecInitiator,
            " | Parent=", ExecParent
        ),
        Detail = tostring(ExecCmd),
        Context = tostring(WriterCmd);
// ---------------------------------------------------------------- Optional telemetry
let tempFileDetections =
    writtenTempFiles
    | where includeTempTelemetry
    | where WriteTime >= ago(lookback)
    | where WriterClass == "nginx-self"
    | where not(FullFilePath matches regex nginxOwnTempRegex)
    | summarize
        arg_max(WriteTime, WriteReportId, DeviceName, WriteAction, WriterCmd),
        FileCount = count(),
        SampleFiles = make_set(WrittenFileName, 10)
        by DeviceId, FileDir, Hour = bin(WriteTime, 1h)
    | project
        Timestamp = WriteTime, DeviceId, DeviceName, ReportId = WriteReportId,
        AccountName = "",
        Severity = "Informational",
        AttackMethod = "Temp file created or modified by nginx",
        Reason = strcat(
            "Dir=", FileDir,
            " | Files in hour=", tostring(FileCount),
            " | Last action=", WriteAction
        ),
        Detail = tostring(SampleFiles),
        Context = tostring(WriterCmd);
// ---------------------------------------------------------------- Output
union processDetections, directTempExecutions, tempFileReferences, tempFileDetections
| project Timestamp, DeviceId, DeviceName, ReportId, AccountName,
    Severity, AttackMethod, Reason, Detail, Context

```
