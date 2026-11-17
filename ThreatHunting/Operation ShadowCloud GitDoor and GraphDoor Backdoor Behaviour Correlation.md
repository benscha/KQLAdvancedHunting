# *Operation ShadowCloud GitDoor and GraphDoor Backdoor Behaviour Correlation*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1574.001 | DLL | https://attack.mitre.org/techniques/T1574/001 |
| T1102.002 | Bidirectional Communication | https://attack.mitre.org/techniques/T1102/002 |
| T1056.001 | Keylogging | https://attack.mitre.org/techniques/T1056/001 |



#### Description

This query hunts for the GitDoor and GraphDoor backdoors described in Operation ShadowCloud by correlating several weak behavioural signals on the same process instance, identified by DeviceId, process ID and process creation time. It combines DeviceImageLoadEvents, DeviceFileEvents, DeviceEvents and DeviceNetworkEvents. The first signal is DLL side-loading: one of the known loader DLLs (for example version.dll, winmm.dll, libcef.dll or python3x.dll) is loaded from the same folder as the host executable, and an encrypted payload named config.ini was written to that folder within the staging window. If the config.ini was dropped by MeshAgent (MeshCentral), an extra point is added. The second signal is a named pipe called p followed by the process's own PID, which the malware uses for plug-in to backdoor IPC. The third signal covers host artefacts such as the keylogger output logs.dat in the SystemCertificates cache, the autostart lock file log.lock in AppData\Roaming and the GraphDoor working directory ProgramData\Intel_Log. The fourth signal is outbound traffic to cloud services abused as C2: the GitHub API, Microsoft Graph and Entra ID token endpoints, and Ably.

An alert is raised when at least two independent behaviours occur on the same process, or immediately on a hit against the published hash, IP or domain IOCs. The variant is classified as GitDoor (GitHub plus Ably) or GraphDoor (Graph or Intel_Log). Tune Lookback and StagingLookback to your schedule, and extend LoaderDlls and the IOC lists as new reporting appears. Legitimate software that ships a config.ini next to common runtime DLLs and also talks to Microsoft Graph can reach the threshold and may need allowlisting.

#### Author
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### Reference
- https://thehackernews.com/2026/11/new-gitdoor-and-graphdoor-backdoors.html


## Defender XDR
```KQL
// Operation ShadowCloud - GitDoor / GraphDoor backdoors (Kaspersky Securelist, Nov 2026)
// https://securelist.com/operation-shadowcloud-gitdoor/122004/
// https://securelist.com/operation-shadowcloud-graphdoor/122005/
//
// Logic    : Alerts only when >= 2 independent behaviours are observed on the SAME process
//            instance (DeviceId + PID + process start time), or on a hard IOC hit.
let Lookback = 1d;
let StagingLookback = 7d;
// Loader DLL names hard-coded in the moveDir.ts plug-in + observed loaders
let LoaderDlls = dynamic(["jli.dll","sbiedll.dll","python39.dll","python38.dll","python33.dll","python311.dll","winmm.dll","libcef.dll","krita.dll","nvdahelperremote.dll","appvisvsubsystems64.dll","corefoundation.dll","vcruntime140.dll","msvcp140.dll","snmpapi.dll","msimg32.dll","version.dll","sqlite.dll","msedge_elf.dll"]);
let IocMd5 = dynamic(["74b025084026d8d9a64661bf995d835b","32151547d912488ac5242731057170a3","e9d4081fac4a5111e6856f333d490439","e63ec733393e4e7e3424cbff918003a3","91bee19d31d32346cd4d1febb4308606","9a5e0ab7466594dcf46943c413db7b81","14ec33ea808e697870d00c5e434c2952","552f0a9cc5fc3755721fa49be05e8035","3896d44bc6d517291c60ee3f70543a31","b930fb3ab14fe45b378d5acfa6e0a763","6a54f8008ee659b6923abf5dba2b2cc1"]);
let IocIps = dynamic(["27.102.66.162","104.194.154.28","216.73.158.72","122.147.252.16","103.106.230.33","123.58.205.105","223.165.4.203","172.86.66.19","103.214.68.20","216.146.25.173","103.137.63.39","103.227.224.189","104.194.152.173","66.42.52.137","153.75.94.148","45.59.124.164","104.194.153.161","153.75.95.27","216.73.158.117","154.205.154.209","43.134.62.111","38.54.17.113","38.52.17.113"]);
let IocDomains = dynamic(["buildersemp.sharepoint.com","cskautogo.sharepoint.com","twnic.top","ekmt.tw"]);
// FolderPath / InitiatingProcessFolderPath may or may not include the file name -> normalise to directory
let DirOf = (p:string, f:string) {
    tolower(iff(p endswith strcat("\\", f), substring(p, 0, strlen(p) - strlen(f) - 1), trim_end(@"\\", p)))
};
// Staging: encrypted payload "config.ini" dropped next to the side-load host (optionally by MeshAgent)
let Staging = DeviceFileEvents
    | where Timestamp > ago(StagingLookback)
    | where FileName =~ "config.ini"
    | where ActionType in ("FileCreated", "FileRenamed", "FileModified")
    | extend StageDir = DirOf(FolderPath, FileName)
    | extend ByMeshAgent = toint(InitiatingProcessFileName has "meshagent"
        or InitiatingProcessVersionInfoProductName has "MeshCentral"
        or InitiatingProcessVersionInfoCompanyName has "MeshCentral")
    | summarize ByMeshAgent = max(ByMeshAgent), Dropper = make_set(InitiatingProcessFileName, 5) by DeviceId, StageDir;
// Known loader DLL side-loaded from the host's own folder, with config.ini staged in that folder
let S_Sideload = DeviceImageLoadEvents
    | where Timestamp > ago(Lookback)
    | where FileName in~ (LoaderDlls)
    | extend DllDir = DirOf(FolderPath, FileName), StageDir = DirOf(InitiatingProcessFolderPath, InitiatingProcessFileName)
    | where DllDir == StageDir
    | join kind=inner Staging on DeviceId, StageDir
    | project Timestamp, ReportId, DeviceId, DeviceName, InitiatingProcessId, InitiatingProcessCreationTime,
        InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName,
        Signal = "Sideload+config.ini", MeshAgentStaged = toint(ByMeshAgent), Detail = strcat(FileName, " | dropper=", tostring(Dropper));
// Named pipe \\.\pipe\p<OwnPID> used for plug-in -> backdoor IPC
let S_Pipe = DeviceEvents
    | where Timestamp > ago(Lookback)
    | where ActionType == "NamedPipeEvent"
    | extend PipeName = tostring(parse_json(AdditionalFields).PipeName)
    | where PipeName matches regex @"(?i)\\p\d{2,7}$"
    | where extract(@"(?i)\\p(\d+)$", 1, PipeName) == tostring(InitiatingProcessId)
    | project Timestamp, ReportId, DeviceId, DeviceName, InitiatingProcessId, InitiatingProcessCreationTime,
        InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName,
        Signal = "Pipe p<OwnPID>", MeshAgentStaged = toint(0), Detail = PipeName;
// Host artefacts (keylogger output, GraphDoor work dir, autostart lock file)
let S_Artefact = DeviceFileEvents
    | where Timestamp > ago(Lookback)
    | where FileName in~ ("logs.dat", "log.lock") or FolderPath has @"\ProgramData\Intel_Log\"
    | where ActionType in ("FileCreated", "FileModified")
    | where (FileName =~ "logs.dat" and FolderPath has @"\Microsoft\SystemCertificates\Cache\")
        or (FileName =~ "log.lock" and FolderPath endswith @"\AppData\Roaming\log.lock")
        or FolderPath has @"\ProgramData\Intel_Log\"
    | project Timestamp, ReportId, DeviceId, DeviceName, InitiatingProcessId, InitiatingProcessCreationTime,
        InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName,
        Signal = "Artefact", MeshAgentStaged = toint(0), Detail = FolderPath;
// Cloud C2 channels (GitHub API, Entra token/Graph, Ably REST/realtime/pusher)
let S_Cloud = DeviceNetworkEvents
    | where Timestamp > ago(Lookback)
    | where RemoteUrl has_any ("api.github.com", "graph.microsoft.com", "login.microsoftonline.com", "ably.io", "ably.net")
    | where ActionType in ("ConnectionSuccess", "HttpConnectionInspected", "SslConnectionInspected")
    | extend Svc = case(RemoteUrl has "github", "GitHub", RemoteUrl has "ably", "Ably", "MSGraph")
    | project Timestamp, ReportId, DeviceId, DeviceName, InitiatingProcessId, InitiatingProcessCreationTime,
        InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName,
        Signal = strcat("CloudC2:", Svc), MeshAgentStaged = toint(0), Detail = RemoteUrl;
// IOC: known infrastructure / hashes -> alerts on its own
let S_IocNet = DeviceNetworkEvents
    | where Timestamp > ago(Lookback)
    | where RemoteIP in (IocIps) or RemoteUrl has_any (IocDomains)
    | project Timestamp, ReportId, DeviceId, DeviceName, InitiatingProcessId, InitiatingProcessCreationTime,
        InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName,
        Signal = "IOC", MeshAgentStaged = toint(0), Detail = coalesce(RemoteUrl, RemoteIP);
let S_IocFile = union
    (DeviceImageLoadEvents | where Timestamp > ago(Lookback) | where MD5 in (IocMd5)),
    (DeviceFileEvents | where Timestamp > ago(Lookback) | where MD5 in (IocMd5))
    | project Timestamp, ReportId, DeviceId, DeviceName, InitiatingProcessId, InitiatingProcessCreationTime,
        InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName,
        Signal = "IOC", MeshAgentStaged = toint(0), Detail = strcat(FolderPath, " md5=", MD5);
union S_Sideload, S_Pipe, S_Artefact, S_Cloud, S_IocNet, S_IocFile
| summarize
    arg_max(Timestamp, ReportId, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName),
    FirstSeen = min(Timestamp),
    Signals = make_set(Signal, 20),
    Details = make_set(Detail, 20),
    MeshAgentStaged = max(MeshAgentStaged)
    by DeviceId, InitiatingProcessId, InitiatingProcessCreationTime
| extend HasIoc = set_has_element(Signals, "IOC")
| extend BehaviourScore =
      toint(set_has_element(Signals, "Sideload+config.ini"))
    + toint(set_has_element(Signals, "Pipe p<OwnPID>"))
    + toint(set_has_element(Signals, "Artefact"))
    + toint(array_length(set_intersect(Signals, dynamic(["CloudC2:GitHub", "CloudC2:MSGraph", "CloudC2:Ably"]))) > 0)
    + MeshAgentStaged
| where HasIoc or BehaviourScore >= 2
| extend Variant = case(
    Signals has "CloudC2:GitHub" and Signals has "CloudC2:Ably", "GitDoor",
    Signals has "CloudC2:MSGraph" or Details has "Intel_Log", "GraphDoor",
    "ShadowCloud (unspecified)")
| project Timestamp, ReportId, DeviceId, DeviceName, Variant, BehaviourScore, HasIoc, Signals, Details, MeshAgentStaged,
    InitiatingProcessId, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
    InitiatingProcessAccountName, FirstSeen
```
