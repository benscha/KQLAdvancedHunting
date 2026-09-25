# *Suspicious Shell and Tooling Activity in Containerized Environment*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059 | Command and Scripting Interpreter | https://attack.mitre.org/techniques/T1059 |
| T1059.004 | Unix Shell | https://attack.mitre.org/techniques/T1059/004 |
| T1105 | Ingress Tool Transfer | https://attack.mitre.org/techniques/T1105 |


#### Description

This rule detects the execution of suspicious command-line utilities, shells, or network tools within container environments. It identifies the use of interpreters like bash, sh, zsh, and python, as well as common network transfer tools like curl, wget, ncat, and socat, which are often leveraged by attackers for post-exploitation tasks such as reverse shell establishment, command-and-control communication, or file downloading. The rule includes filters for common container management processes such as liveness and readiness probes to minimize noise.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let Lookback = 1d;
CloudProcessEvents
| where Timestamp > ago(Lookback)
| where isnotempty(KubernetesPodName)
| extend Command = tolower(ProcessCommandLine), Proc = tolower(ProcessName), Parent = tolower(ParentProcessName)
| where Proc in ("bash", "sh", "dash", "zsh", "nc", "ncat", "netcat", "socat", "python", "python3", "perl", "ruby", "php")
	or Command has_any ("/dev/tcp/", "bash -i", "sh -i", "mkfifo", "curl ", "wget ", "| sh", "| bash", "base64 -d", "base64 --decode", "chmod +x", "nohup ")
| where not(Command has_any ("readiness", "liveness", "healthcheck"))
```
