# *WinRM Child Process with Inbound Network Logon*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1021.006 | Remote Services: Windows Remote Management | https://attack.mitre.org/techniques/T1021/006 |



#### Description

This query detects child processes spawned by the WinRM host processes wsmprovhost.exe and winrshost.exe on Defender for Endpoint onboarded devices and enriches them with the inbound network logon and WinRM connection that most likely caused them. It starts from DeviceProcessEvents within the lookback window, ignoring conhost.exe, and then correlates each process via its initiating logon ID with the first successful network logon in DeviceLogonEvents, which provides the authenticating account and the source IP. In a second step, inbound connections accepted on TCP 5985 or 5986 from the same source IP are taken from DeviceNetworkEvents, and the connection closest in time to the logon is selected. The WinRM port is only reported when the connection lies within the MaxConnToLogon window of the logon, so unrelated connections do not produce misleading context. The result is one row per process event showing who executed what, from where and over which WinRM port.

Remote command execution via WinRM is a common technique for lateral movement and hands on keyboard activity, and is also used by tools such as Evil-WinRM or Invoke-Command. Legitimate administration and automation will generate the same pattern, so the KnownAutomation table should be populated with source IP and account pairs of trusted management systems. Lookback, Buffer and MaxConnToLogon can be tuned to the environment and to the scheduling interval of the rule.

#### Author
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let Lookback = 1h;
let Buffer = 15m;
let MaxConnToLogon = 5m;
let KnownAutomation = datatable(RemoteIP:string, AccountName:string)
[
    "x.x.x.x", "YOURSERVICEACCOUNT"
];
let WinRMHosts = dynamic(["wsmprovhost.exe", "winrshost.exe"]);
let WinRMChildProcesses = materialize(
    DeviceProcessEvents
    | where Timestamp > ago(Lookback)
    | where InitiatingProcessFileName in~ (WinRMHosts)
    | where FileName !~ "conhost.exe"
    | project
        Timestamp, DeviceId, DeviceName, ReportId,
        InitiatingProcessLogonId,
        InitiatingProcessAccountDomain, InitiatingProcessAccountName,
        FileName, ProcessCommandLine,
        InitiatingProcessFileName, InitiatingProcessCommandLine
);
let RelevantDevices = WinRMChildProcesses | distinct DeviceId;
let NetworkLogons =
    DeviceLogonEvents
    | where Timestamp > ago(Lookback + Buffer)
    | where DeviceId in (RelevantDevices)
    | where ActionType == "LogonSuccess" and LogonType == "Network"
    | where isnotempty(RemoteIP) and LogonId != 0
    | extend RemoteIP = replace_string(RemoteIP, "::ffff:", "")
    | summarize arg_min(Timestamp, AccountDomain, AccountName, RemoteIP, Protocol)
        by DeviceId, InitiatingProcessLogonId = LogonId
    | project-rename LogonTime = Timestamp, LogonProtocol = Protocol;
let WinRMConnections =
    DeviceNetworkEvents
    | where Timestamp > ago(Lookback + Buffer)
    | where isnotempty(RemoteIP)
    | where DeviceId in (RelevantDevices)
    | where ActionType == "InboundConnectionAccepted" and LocalPort in (5985, 5986)
    | extend RemoteIP = replace_string(RemoteIP, "::ffff:", "")
    | where isnotempty(RemoteIP) and RemoteIP !in ("127.0.0.1", "::1")
    | project DeviceId, RemoteIP, ConnectionTime = Timestamp, WinRMPort = LocalPort;
WinRMChildProcesses
| join kind=leftouter NetworkLogons on DeviceId, InitiatingProcessLogonId
| project-away DeviceId1, InitiatingProcessLogonId1
| join kind=leftouter WinRMConnections on DeviceId, RemoteIP
| join kind=leftanti KnownAutomation on RemoteIP, AccountName
| project-away DeviceId1, RemoteIP1
| extend ConnDelta = iff(isnull(ConnectionTime) or isnull(LogonTime), 365d, abs(LogonTime - ConnectionTime))
| summarize arg_min(ConnDelta, *) by ReportId, DeviceId      // one row per process event
| extend WinRMPort = iff(ConnDelta <= MaxConnToLogon, WinRMPort, int(null))
| project
    Timestamp, DeviceId, DeviceName, ReportId,
    AccountDomain = coalesce(AccountDomain, InitiatingProcessAccountDomain),
    AccountName   = coalesce(AccountName, InitiatingProcessAccountName),
    RemoteIP, WinRMPort, LogonProtocol, LogonTime,
    FileName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```
