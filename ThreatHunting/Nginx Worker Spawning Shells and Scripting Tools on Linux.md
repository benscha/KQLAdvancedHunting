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
let nginxParents = dynamic(["nginx", "nginx-debug"]);
let shellNames = dynamic(["sh", "bash", "dash", "ash", "zsh", "ksh"]);
let suspiciousTools = dynamic(["python", "python3", "perl", "ruby", "php", "node", "lua", "awk", "gawk",
    "nc", "ncat", "netcat", "socat", "openssl", "telnet", "curl", "wget", "ssh", "sftp", "busybox"]);
let reverseShellPatterns = dynamic(["/dev/tcp", "bash -i", "mkfifo", "base64 -d",
    "-e /bin/sh", "-e /bin/bash", "| sh", "| bash"]);
union isfuzzy=true
(
    // Process level: shell or tool started by nginx, or nested under nginx
    DeviceProcessEvents
    | where Timestamp >= ago(lookback)
    | where InitiatingProcessFileName in~ (nginxParents)
        or (InitiatingProcessFileName in~ (shellNames) and InitiatingProcessParentFileName in~ (nginxParents))
    | where FileName in~ (shellNames) or FileName in~ (suspiciousTools)
    | extend AttackMethod = case(
        ProcessCommandLine has_any (reverseShellPatterns), "Reverse shell pattern in command line",
        InitiatingProcessFileName in~ (nginxParents), "Direct child process of nginx worker (code execution)",
        "Nested child process nginx -> shell -> tool")
    | project Timestamp, DeviceName, AttackMethod,
        Reason = strcat(
            "Initiator=", InitiatingProcessFileName,
            " Parent=", InitiatingProcessParentFileName,
            " Child=", FileName,
            iff(ProcessCommandLine has_any (reverseShellPatterns), " | cmdline matched reverse shell pattern", "")),
        Detail = tostring(ProcessCommandLine),
        Context = tostring(InitiatingProcessCommandLine)
),
(
    // File level: files written by nginx to temp locations
    DeviceFileEvents
    | where Timestamp >= ago(lookback)
    | where InitiatingProcessFileName in~ (nginxParents)
    | where FolderPath starts
