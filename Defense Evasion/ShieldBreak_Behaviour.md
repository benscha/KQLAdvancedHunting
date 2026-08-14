# *ShieldBreak Behaviour*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1685	| Disable or Modify Tools | https://attack.mitre.org/techniques/T1685/ |
| T1574.001	| Hijack Execution Flow: DLL Search Order Hijacking	| https://attack.mitre.org/techniques/T1574/001/ | 
| T1055.001	| Process Injection: Dynamic-link Library Injection	| https://attack.mitre.org/techniques/T1055/001/ |


#### Description
This KQL query correlation addresses that gap by tracking processes loading system modules like CldApi.dll or taskschd.dll while simultaneously interacting with specific artifacts tied to the attack, such as unusual WER report queues, restricted named objects, or specific file indicators. By joining module loads directly with suspicious file operations at the process level, it cuts through the noise and highlights potential EDR bypass activity that would otherwise slip through undetected.

#### Risk
Defense Evasion

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- https://github.com/MSNightmare/ShieldBreak

## Defender XDR
```KQL
let lookback = 14d;
let excluded_processes = dynamic([
    "MsMpEng.exe",
    "MpCmdRun.exe",
    "NisSrv.exe",
    "SenseIR.exe"
]);
let cloudapi_loads =
    DeviceImageLoadEvents
    | where Timestamp >= ago(lookback)
    | where FileName =~ "CldApi.dll"
        or FolderPath has @"\CldApi.dll"
        or FileName =~ "taskschd.dll"
        or FolderPath has @"\taskschd.dll"
    | where InitiatingProcessFileName !in~ (excluded_processes)
    | project
        DeviceId,
        DeviceName,
        InitiatingProcessId,
        InitiatingProcessFileName,
        InitiatingProcessCommandLine,
        InitiatingProcessIntegrityLevel,
        ModuleLoadTime = Timestamp,
        ModulePath = FolderPath,
        ModuleName = FileName
    | summarize
        FirstModuleLoad=min(ModuleLoadTime),
        LastModuleLoad=max(ModuleLoadTime),
        ModulePaths=make_set(ModulePath, 20),
        ModuleNames=make_set(ModuleName, 20)
      by DeviceId, DeviceName, InitiatingProcessId, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessIntegrityLevel;
let suspicious_file_activity =
    DeviceFileEvents
    | where Timestamp >= ago(lookback)
    | where ActionType in~ ("FileCreated", "FileModified", "FileRenamed", "FileDeleted")
    | where
          FileName in~ ("BERLIN", "phoneinfo.dll", "Report.wer", "SHIELDBREAK")
       or FolderPath has @"\BaseNamedObjects\Restricted\WD_"
       or FolderPath has @"\ShieldBreak_"
       or FolderPath has @"\ProgramData\Microsoft\Windows\WER\ReportQueue\Kernel_"
       or FolderPath has @".\globalroot\BaseNamedObjects\Restricted\WD_"
    | where InitiatingProcessFileName !in~ (excluded_processes)
    | project
        DeviceId,
        DeviceName,
        InitiatingProcessId,
        InitiatingProcessFileName,
        InitiatingProcessCommandLine,
        FileName,
        FolderPath,
        ActionType,
        FileEventTime = Timestamp
    | summarize
        FirstFileEvent=min(FileEventTime),
        LastFileEvent=max(FileEventTime),
        FileNames=make_set(FileName, 20),
        FolderPaths=make_set(FolderPath, 50),
        ActionTypes=make_set(ActionType, 20)
      by DeviceId, DeviceName, InitiatingProcessId, InitiatingProcessFileName, InitiatingProcessCommandLine;
let combined =
    cloudapi_loads
    | join kind=inner suspicious_file_activity on DeviceId, InitiatingProcessId
    | extend SuspiciousScore = 40 + 30 + 10
    | where SuspiciousScore >= 60
    | project
        Timestamp = LastFileEvent,
        DeviceId,
        DeviceName,
        InitiatingProcessFileName,
        InitiatingProcessCommandLine,
        InitiatingProcessIntegrityLevel,
        ModuleNames,
        ModulePaths,
        FileNames,
        FolderPaths,
        ActionTypes,
        SuspiciousScore;
combined
| order by Timestamp desc
```

