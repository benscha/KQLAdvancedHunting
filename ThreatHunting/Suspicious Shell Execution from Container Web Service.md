# Suspicious Shell Execution from Container Web Service*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1053.007 | Container Orchestration Job | https://attack.mitre.org/techniques/T1053/007 |
| T1609 | Container Administration Command | https://attack.mitre.org/techniques/T1609 |
| T1611 | Escape to Host | https://attack.mitre.org/techniques/T1611 |

#### Description

Detects anomalous shell process execution originating from common web application processes within a containerized environment. The rule uses behavioral indicators such as parent-child process relationships, network-related command execution, file system reconnaissance, and suspicious utility usage to calculate a risk score for newly observed or suspicious shell activity.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let Lookback = 14d;
let DetectWindow = 1h;
let SessionWindow = 10m;
let WebParents = dynamic(["java", "node", "nginx", "httpd", "apache2", "php-fpm", "php", "gunicorn", "uwsgi",
                          "uvicorn", "dotnet", "ruby", "puma", "python", "python3"]);
let Shells = dynamic(["sh", "bash", "dash", "ash", "zsh", "busybox"]);
let Proc = CloudProcessEvents
| where Timestamp > ago(Lookback)
| where isnotempty(KubernetesPodName) and ContainerName != "host"
| extend ImageRepo = tostring(split(ContainerImageName, ":")[0]),
         P = tolower(ProcessName), PP = tolower(ParentProcessName);
let ShellFromWeb = Proc
| where PP in (WebParents) and P in (Shells);
let Baseline = ShellFromWeb
| where Timestamp < ago(DetectWindow)
| summarize by ImageRepo, PP
| extend Known = true;
let Suspects = ShellFromWeb
| where Timestamp >= ago(DetectWindow)
| join kind=leftouter Baseline on ImageRepo, PP
| extend NewPair = isnull(Known)
| project ShellTime = Timestamp, ContainerId, AzureResourceId, KubernetesNamespace, KubernetesPodName,
          ContainerImageName, WebParent = PP, ShellCmd = tolower(ProcessCommandLine), NewPair;
let Children = Proc
| where Timestamp >= ago(DetectWindow + SessionWindow)
| where PP in (Shells) or PP in (WebParents)
| project ChildTime = Timestamp, ContainerId, ChildProc = P, ChildCmd = tolower(ProcessCommandLine);
Suspects
| join kind=leftouter Children on ContainerId
| extend InWin = ChildTime between (ShellTime .. (ShellTime + SessionWindow))
| extend Recon = InWin and (ChildProc in ("id", "whoami", "uname", "hostname", "env", "printenv", "ifconfig", "ip", "netstat", "ss", "mount")
                            or ChildCmd has_any ("/etc/passwd", "/etc/shadow", "serviceaccount", "169.254.169.254")),
         Download = InWin and (ChildProc in ("curl", "wget", "tftp") or ChildCmd has_any ("curl ", "wget ")),
         NetTool = InWin and (ChildProc in ("nc", "ncat", "netcat", "socat", "telnet") or ChildCmd has "/dev/tcp"),
         Staging = InWin and ChildCmd has_any ("chmod +x", "chmod 777", "/dev/shm/", "/tmp/")
| summarize ReconCount = countif(Recon), DownloadCount = countif(Download), NetCount = countif(NetTool), StagingCount = countif(Staging),
            ChildCommands = make_set_if(ChildCmd, InWin, 30)
    by ShellTime, ContainerId, AzureResourceId, KubernetesNamespace, KubernetesPodName, ContainerImageName, WebParent, ShellCmd, NewPair
| extend ShellDownload = ShellCmd has_any ("curl", "wget"),
         ShellNet = ShellCmd has_any ("/dev/tcp", "socat", "ncat", "nc -e")
| extend Score = toint(NewPair) * 2
               + iff(ReconCount >= 2, 2, 0)
               + iff(DownloadCount > 0 or ShellDownload, 3, 0)
               + iff(NetCount > 0 or ShellNet, 3, 0)
               + iff(StagingCount > 0, 2, 0)
| where Score >= 4
| extend Severity = iff(Score >= 6, "High", "Medium")
| order by Score desc
```
