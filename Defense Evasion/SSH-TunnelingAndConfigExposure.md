# *Suspicious SSH Tunneling and Config Exposure*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1090 | Proxy | https://attack.mitre.org/techniques/T1090 |
| T1572 | Protocol Tunneling | https://attack.mitre.org/techniques/T572 |


#### Description
Detects active SSH port forwarding and tunneling activity, including local, dynamic, and remote tunnels via tools like ssh, plink, and putty. It establishes a 30-day baseline to filter out routine administrative usage, evaluates listening interface scopes and persistent shell flags to score risk, and flags unauthorized modifications to sshd configuration files or command-line overrides like GatewayPorts.

#### Risk
Defense Evasion

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- https://www.hackingarticles.in/a-detailed-guide-on-ssh-port-forwarding-tunnelling/

## Defender XDR
```KQL
let Lookback    = 7d;
let BaselineWin = 30d;
// Set to true to filter out noisy local development tunnels on loopback and focus on higher-risk activity
let HighFidelityOnly = true;
let FwdRegex = @"(^|\s)-[LDR] ?(\d{1,5}(:|\s|$)|\*:|0\.0\.0\.0:|localhost:|\[)";
let SshTunnelEvents = (StartTime:datetime, EndTime:datetime) {
    DeviceProcessEvents
    | where Timestamp between (StartTime .. EndTime)
    // Ignore sshd here, as -D and -R are standard daemon flags there
    | where FileName in~ ("ssh", "ssh.exe", "plink.exe", "putty.exe")
    | where ProcessCommandLine matches regex FwdRegex
    | extend TunnelFlag   = extract(@"(^|\s)-([LDR]) ?(\d|\*:|0\.0\.0\.0:|localhost:|\[)", 2, ProcessCommandLine)
    | extend ForwardSpecs = extract_all(@"(?:^|\s)-[LDR] ?(\S+)", ProcessCommandLine)
    | extend AllSpecs     = strcat_array(ForwardSpecs, " ")
    | extend SshTarget    = extract(@"\s([\w\.\-]+@[\w\.\-]+)", 1, ProcessCommandLine)
    | extend CmdPattern   = replace_regex(ProcessCommandLine, @"\b\d{4,5}\b", "<port>")
};
let TunnelBaseline =
    SshTunnelEvents(ago(BaselineWin + Lookback), ago(Lookback))
    | distinct DeviceName, AccountName, CmdPattern;
let TunnelFindings =
    SshTunnelEvents(ago(Lookback), now())
    | extend TunnelType = case(
        TunnelFlag == "L", "Local Port Forwarding (-L)",
        TunnelFlag == "D", "Dynamic Port Forwarding / SOCKS (-D)",
        TunnelFlag == "R", "Remote Port Forwarding (-R)",
        "SSH Tunneling / Other")
    // Explicit binding requires all four fields (bind:port:host:hostport)
    | extend ListenerScope = case(
        AllSpecs matches regex @"(^|\s)(\*|0\.0\.0\.0|::):",           "Bind to all interfaces",
        AllSpecs matches regex @"[\w\.\-]+:\d{1,5}:[\w\.\-]+:\d{1,5}", "Bind to explicit address",
        "Loopback (Default)")
    | extend PersistentTunnel = ProcessCommandLine matches regex @"(^|\s)-(fN|Nf|N|f)(\s|$)"
    // Regular local dev tunnels on loopback are excluded in High-Fidelity mode
    | where HighFidelityOnly == false
        or ListenerScope != "Loopback (Default)"
        or TunnelType startswith "Remote"
    | summarize
        EventCount     = count(),
        FirstSeen      = min(Timestamp),
        LastSeen       = max(Timestamp),
        SampleCmd      = any(ProcessCommandLine),
        Parents        = make_set(InitiatingProcessFileName, 8),
        SshTargets     = make_set_if(SshTarget, isnotempty(SshTarget), 8),
        ForwardSpecSet = make_set(AllSpecs, 8),
        ReportId       = any(ReportId),
        DeviceId       = any(DeviceId)
        by DeviceName, AccountName, InitiatingProcessAccountName, FileName,
           TunnelType, ListenerScope, PersistentTunnel, CmdPattern
    | join kind=leftanti TunnelBaseline on DeviceName, AccountName, CmdPattern
    | extend RiskScore =
          iff(ListenerScope == "Bind to all interfaces",   40, 0)
        + iff(ListenerScope == "Bind to explicit address", 20, 0)
        + iff(TunnelType startswith "Remote",                30, 0)
        + iff(PersistentTunnel,                               15, 0)
        + iff(TunnelType startswith "Dynamic",               10, 0)
    | project
        Category  = "SSH Port Forwarding",
        RiskScore,
        Signal    = TunnelType,
        Evidence  = strcat(TunnelType, " | ", ListenerScope,
                        iff(PersistentTunnel, " | persistent tunnel without shell (-N/-f)", "")),
        DeviceName,
        Account   = coalesce(AccountName, InitiatingProcessAccountName),
        EventCount,
        FirstSeen,
        LastSeen,
        CLI       = SampleCmd,
        SampleCmd,
        Details   = strcat("Specs: ", strcat_array(ForwardSpecSet, ", "),
                        iff(array_length(SshTargets) > 0, strcat(" | Targets: ", strcat_array(SshTargets, ", ")), ""),
                        " | Parent: ", strcat_array(Parents, ", ")),
        ReportId,
        DeviceId;
let ConfigWrites =
    DeviceFileEvents
    | where Timestamp > ago(Lookback)
    | where FileName =~ "sshd_config" or FolderPath has "/etc/ssh/sshd_config.d"
    | where ActionType in ("FileCreated", "FileModified", "FileRenamed")
    | project Timestamp, DeviceName, Account = InitiatingProcessAccountName,
              Cmd = InitiatingProcessCommandLine, Path = FolderPath,
              Signal = "sshd_config modified", Score = 35, ReportId, DeviceId;
let GatewayPortsCmd =
    DeviceProcessEvents
    | where Timestamp > ago(Lookback)
    | where ProcessCommandLine has_cs "GatewayPorts" or ProcessCommandLine has_cs "PermitTunnel"
    | where ProcessCommandLine !contains "GatewayPorts=no" and ProcessCommandLine !contains "GatewayPorts no"
    | project Timestamp, DeviceName, Account = InitiatingProcessAccountName,
              Cmd = ProcessCommandLine, Path = FolderPath,
              Signal = "GatewayPorts/PermitTunnel in command line", Score = 45, ReportId, DeviceId;
let ConfigFindings =
    union ConfigWrites, GatewayPortsCmd
    // Adjust admin and deployment accounts based on your environment
    | where Account !in~ ("puppet", "ansible", "salt")
        and Cmd !has "cloud-init" and Cmd !has "unattended-upgrade"
    | summarize
        EventCount = count(),
        FirstSeen  = min(Timestamp),
        LastSeen   = max(Timestamp),
        SampleCmd  = any(Cmd),
        Paths      = make_set(Path, 4),
        RiskScore  = max(Score),
        ReportId   = any(ReportId),
        DeviceId   = any(DeviceId)
        by DeviceName, Account, Signal
    | project
        Category  = "sshd_config Exposure",
        RiskScore,
        Signal,
        Evidence  = strcat(Signal, " by ", Account),
        DeviceName,
        Account,
        EventCount,
        FirstSeen,
        LastSeen,
        CLI       = SampleCmd,
        SampleCmd,
        Details   = strcat("Paths: ", strcat_array(Paths, ", ")),
        ReportId,
        DeviceId;
union TunnelFindings, ConfigFindings
| extend Severity = case(RiskScore >= 40, "High", RiskScore >= 20, "Medium", "Low")
| project-reorder Severity, RiskScore, Category, Evidence, DeviceName, Account,
              EventCount, FirstSeen, LastSeen, CLI, SampleCmd, Details
| sort by RiskScore desc, LastSeen desc
```

