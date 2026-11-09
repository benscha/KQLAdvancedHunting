# *Reverse Shell Spawned from Vulnerable React Server Components*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1190 | Exploit Public-Facing Application | https://attack.mitre.org/techniques/T1190 |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | https://attack.mitre.org/techniques/T1059/004 |
| T1059.001 | Command and Scripting Interpreter: PowerShell | https://attack.mitre.org/techniques/T1059/001 |



#### Description

This rule identifies likely remote code execution against internet facing Node.js servers that run a vulnerable version of React Server Components. It first narrows the scope to devices classified as Server in DeviceInfo, then checks DeviceTvmSoftwareInventory for the react-server-dom-webpack, react-server-dom-parcel or react-server-dom-turbopack packages whose version falls into the affected ranges (19.0.0 to 19.0.8, 19.1.0 to 19.1.9, 19.2.0 to 19.2.8, or exactly 19.3.0). Only process and network events from those devices are considered further.

The query then looks in DeviceProcessEvents, within the last 70 minutes, for a shell or interpreter such as sh, bash, zsh, cmd.exe or powershell.exe that was spawned directly by a node process. The command line of that shell is tested against four patterns that are typical for post exploitation activity: a curl or wget output piped into a shell, a bash style reverse shell using /dev/tcp with file descriptor redirection, a PowerShell command combining Invoke-Expression with a download cmdlet such as Invoke-WebRequest, or a PowerShell reverse shell built on System.Net.Sockets.TcpClient.

To raise confidence, each matching shell process is joined, by device, process id and creation time, to outbound network connections recorded in DeviceNetworkEvents, checking both the shell process itself and its parent process as the initiator. A match is only kept if a successful connection to a public IP address occurred within five minutes after the shell started, captured as the correlation window. The result lists the triggering command lines together with the remote IPs, ports and URLs observed, giving an analyst what is needed to confirm exploitation and begin containment.

Tuning notes: adjust Lookback and CorrelationWindow for longer hunts or environments with slower post exploitation network setup; review the affected version ranges whenever a new React Server Components advisory is published, since they will likely need to be extended; and consider allowlisting known internal proxy or monitoring IPs to reduce noise from legitimate outbound connections that happen to fall inside the correlation window.

#### Author
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let Lookback = 70m;
let CorrelationWindow = 5m;
let ServerDeviceIds =
    DeviceInfo
    | summarize arg_max(Timestamp, DeviceType) by DeviceId
    | where DeviceType =~ "Server"
    | project DeviceId;
let RscServerDeviceIds =
    DeviceTvmSoftwareInventory
    | where DeviceId in (ServerDeviceIds)
    | extend PackageName = replace_string(tolower(SoftwareName), "_", "-")
    | where PackageName in (
        "react-server-dom-webpack",
        "react-server-dom-parcel",
        "react-server-dom-turbopack"
    )
    | where SoftwareVersion matches regex @"^19\.[0-3]\.[0-9]+$"
    | extend Version = parse_version(SoftwareVersion)
    | where
        Version between (parse_version("19.0.0") .. parse_version("19.0.8"))
        or Version between (parse_version("19.1.0") .. parse_version("19.1.9"))
        or Version between (parse_version("19.2.0") .. parse_version("19.2.8"))
        or Version == parse_version("19.3.0")
    | distinct DeviceId;
let Shells =
    DeviceProcessEvents
    | where Timestamp >= ago(Lookback)
    | where DeviceId in (RscServerDeviceIds)
    | where ActionType == "ProcessCreated"
    | where InitiatingProcessFileName in~ ("node", "node.exe")
    | where FileName in~ (
        "sh", "bash", "dash", "ash", "zsh", "ksh",
        "cmd.exe", "powershell.exe", "pwsh.exe", "pwsh"
    )
    | extend Cmd = tolower(ProcessCommandLine)
    | extend
        DownloadPipeToShell =
            Cmd matches regex
            @"\b(curl|wget)\b[^|;\r\n]*\|\s*(/[^\s|;]+/)?(bash|sh|dash|ash|zsh|ksh)\b",
        BashReverseShell =
            Cmd contains "/dev/tcp/"
            and Cmd matches regex @"[012]?[<>]&[012]",
        PowerShellDownloadExecute =
            Cmd matches regex @"\b(iex|invoke-expression)\b"
            and (
                Cmd contains "downloadstring"
                or Cmd contains "downloadfile"
                or Cmd contains "invoke-webrequest"
                or Cmd contains "invoke-restmethod"
            ),
        PowerShellReverseShell =
            Cmd contains "net.sockets.tcpclient"
            and Cmd contains "getstream"
    | where DownloadPipeToShell
        or BashReverseShell
        or PowerShellDownloadExecute
        or PowerShellReverseShell
    | extend DetectionReason = case(
        BashReverseShell, "Node -> shell: /dev/tcp reverse-shell pattern",
        PowerShellReverseShell, "Node -> PowerShell: TCP reverse-shell pattern",
        DownloadPipeToShell, "Node -> shell: download piped into interpreter",
        "Node -> PowerShell: download and Invoke-Expression"
    )
    | project
        Timestamp,
        DeviceId,
        DeviceName,
        ReportId,
        AccountName,
        ShellPid = ProcessId,
        ShellStart = ProcessCreationTime,
        ShellCommandLine = ProcessCommandLine,
        NodeCommandLine = InitiatingProcessCommandLine,
        DetectionReason;
let Egress = materialize(
    DeviceNetworkEvents
    | where Timestamp >= ago(Lookback)
    | where DeviceId in (RscServerDeviceIds)
    | where ActionType == "ConnectionSuccess"
    | where RemoteIPType == "Public"
    | project
        DeviceId,
        NetworkTime = Timestamp,
        RemoteIP,
        RemotePort,
        RemoteUrl,
        InitiatingProcessId,
        InitiatingProcessCreationTime,
        InitiatingProcessParentId,
        InitiatingProcessParentCreationTime
);
let EgressByProcess =
    union
        (
            Egress
            | project
                DeviceId,
                NetworkTime,
                RemoteIP,
                RemotePort,
                RemoteUrl,
                MatchPid = InitiatingProcessId,
                MatchStart = InitiatingProcessCreationTime
        ),
        (
            Egress
            | project
                DeviceId,
                NetworkTime,
                RemoteIP,
                RemotePort,
                RemoteUrl,
                MatchPid = InitiatingProcessParentId,
                MatchStart = InitiatingProcessParentCreationTime
        );
Shells
| join kind=inner EgressByProcess on
    DeviceId,
    $left.ShellPid == $right.MatchPid,
    $left.ShellStart == $right.MatchStart
| where NetworkTime >= ShellStart
    and NetworkTime <= (ShellStart + CorrelationWindow)
| summarize
    FirstNetworkTime = min(NetworkTime),
    RemoteIPs = make_set(RemoteIP, 20),
    RemotePorts = make_set(RemotePort, 20),
    RemoteUrls = make_set(RemoteUrl, 20)
    by
        Timestamp,
        DeviceId,
        DeviceName,
        ReportId,
        AccountName,
        ShellPid,
        ShellStart,
        NodeCommandLine,
        ShellCommandLine,
        DetectionReason
```
