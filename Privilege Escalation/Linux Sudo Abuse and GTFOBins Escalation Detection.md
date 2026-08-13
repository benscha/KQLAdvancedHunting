# *Linux Sudo Abuse and GTFOBins Escalation Detection*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1548.003 | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | https://attack.mitre.org/techniques/T1548/003 |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | https://attack.mitre.org/techniques/T1059/004/ |
| T1202 | Indirect Command Execution | https://attack.mitre.org/techniques/T1202 |

#### Description
This rule detects unauthorized privilege escalation on Linux systems by identifying malicious sudo usage patterns. It specifically monitors for interactive root shells spawned through sudo, the execution of documented GTFOBins payloads (e.g., Python, Perl, Vim, Nmap escapes), the creation of reverse shells via sudo with network utilities (like socat or netcat), and execution of binaries from user-writable directories (e.g., /tmp, /var/tmp) that suggest a 'write-then-run' attack chain.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- https://www.hackingarticles.in/linux-privilege-escalation-using-exploiting-sudo-rights/
- 
## Sentinel

```KQL
// Linux Sudo Abuse & GTFOBins Escape Detection
let lookback = 7d;
let shell_names = dynamic(["sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "fish", "busybox"]);
let benign_sudo = dynamic(["su", "sudo", "bash", "sh", "dash", "zsh", "login", "sshd", "systemd", "cloud-init", "unattended-upgrade", "apt", "apt-get", "dpkg", "yum", "dnf", "ansible-playbook", "puppet", "chef-client", "salt-minion", "docker", "containerd"]);
let file_ops = dynamic(["mv", "cp", "install", "chmod", "chown", "rm", "ln", "tar", "cat", "tee", "dd", "rsync", "touch", "mkdir", "gzip", "gunzip"]);
// Known-noisy temp prefixes: macOS installer sandboxes, VPN packages, CI/test harnesses
let noisy_prefixes = dynamic(["/tmp/vpn."]); 
let linux_devices =
    DeviceInfo
    | where Timestamp > ago(lookback)
    | where OSPlatform == "Linux"
    | distinct DeviceId;
let common_paths =
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where DeviceId in (linux_devices)
    | where FolderPath matches regex @"^/(tmp|var/tmp|dev/shm)/"
    | extend PathPattern = replace_regex(FolderPath, @"[A-Za-z0-9._-]{6,}", "*")
    | summarize DeviceCount = dcount(DeviceId) by PathPattern
    | where DeviceCount >= 5
    | distinct PathPattern;
// Single pass pre-filter on core process events
let sudo_events = DeviceProcessEvents
| where Timestamp > ago(lookback)
| where DeviceId in (linux_devices)
| where AccountName =~ "root" or InitiatingProcessFileName =~ "sudo" or InitiatingProcessParentFileName =~ "sudo";
let ShellEscape = sudo_events
| where FileName in~ (shell_names)
| where AccountName =~ "root" and InitiatingProcessParentFileName =~ "sudo"
| where InitiatingProcessFileName !in~ (benign_sudo)
| extend ShellArgs = trim(@"\s+", replace_regex(ProcessCommandLine, @"^\S+\s*", ""))
| where isempty(ShellArgs) or ShellArgs matches regex @"^-{1,2}[ilps]{1,4}$"
| extend Technique = strcat("Shell escape via ", InitiatingProcessFileName),
         Verdict = "High: Interactive root shell spawned by non-shell binary via sudo";
let PayloadSignature = sudo_events
| where InitiatingProcessFileName =~ "sudo" and AccountName =~ "root"
| extend Cmd = tolower(ProcessCommandLine)
| extend Technique = case(
    Cmd matches regex @"^\S*python[0-9.]*\s+-c\s.{0,80}(os\.system|pty\.spawn|subprocess\.|os\.exec)", "Python shell escape",
    Cmd matches regex @"^\S*perl\s.{0,40}-e\s.{0,60}(exec|system).{0,15}/bin/", "Perl shell escape",
    Cmd matches regex @"^\S*awk\s.{0,30}begin\s*\{\s*system\s*\(", "Awk shell escape",
    Cmd matches regex @"^\S*(vim|vi|nvim|rvim|view)\s.{0,40}-c\s.{0,10}:\s*!", "Vim escape",
    Cmd matches regex @"^\S*env\s+(/usr)?/bin/(ba|da|z|k)?sh\s*$", "env shell escape",
    Cmd matches regex @"^\S*find\s.{0,120}-exec\s.{0,25}/(ba|da|z)?sh\s", "find -exec escape",
    Cmd matches regex @"^\S*tar\s.{0,80}--checkpoint-action=exec", "tar checkpoint-action escape",
    Cmd matches regex @"^\S*nmap\s.{0,25}--interactive", "nmap interactive escape",
    Cmd matches regex @"^\S*(ruby|node|lua|php)\s.{0,40}-e\s.{0,80}(exec|spawn|system|child_process)", "Interpreter shell escape",
    Cmd matches regex @"^\S*gdb\s.{0,40}-ex\s.{0,30}!", "gdb shell escape",
    "")
| where isnotempty(Technique)
| extend Verdict = "High: Documented GTFOBins sudo payload in command line";
let ReverseShell = sudo_events
| where FileName in~ ("socat", "socat1", "nc", "ncat", "netcat", "nc.traditional")
| where AccountName =~ "root" and (InitiatingProcessFileName =~ "sudo" or InitiatingProcessParentFileName =~ "sudo")
| extend Cmd = tolower(ProcessCommandLine)
| where Cmd matches regex @"(exec\s*:|system\s*:|--sh-exec|\s-e\s+/?(usr/)?bin/)"
| where Cmd matches regex @"(tcp[46]?:|tcp-connect|openssl:|udp[46]?:)"
| extend Technique = "Sudo reverse shell via networking binary",
         Verdict = "Critical: Root network process with exec payload";
let WritableTarget = sudo_events
| where InitiatingProcessFileName =~ "sudo"
| where AccountName =~ "root"
| extend RunBinary = tostring(split(replace_regex(ProcessCommandLine, @"^(sudo\s+)+", ""), " ")[0])
| extend RunBinaryName = extract(@"([^/]+)$", 1, RunBinary)
| where RunBinaryName !in~ (file_ops)
| extend FirstArg = extract(@"^\S+\s+(/\S+)", 1, ProcessCommandLine)
| extend WritablePath = case(
    FolderPath matches regex @"^/(tmp|var/tmp|dev/shm|run/user)/", FolderPath,
    RunBinary matches regex @"^/(tmp|var/tmp|dev/shm|run/user)/", RunBinary,
    FirstArg matches regex @"^/(tmp|var/tmp|dev/shm|run/user)/.*\.(sh|py|pl|rb|bash)$", FirstArg,
    "")
| where isnotempty(WritablePath)
| where not (WritablePath has_any (noisy_prefixes))
| where replace_regex(WritablePath, @"[A-Za-z0-9._-]{6,}", "*") !in (common_paths)
| extend Technique = "Sudo execution from user-writable path",
         Verdict = "High: Write-then-run pattern in temporary directory";
union ShellEscape, PayloadSignature, ReverseShell, WritableTarget
| extend ProcessLineage = strcat(coalesce(InitiatingProcessParentFileName, "?"), " -> ", coalesce(InitiatingProcessFileName, "?"), " -> ", FileName)
// Resolve the sudo process whether it is the parent or the grandparent of the hit
| extend SudoKey = iff(InitiatingProcessFileName =~ "sudo", InitiatingProcessId, InitiatingProcessParentId)
| join kind=leftouter (
    sudo_events
    | where FileName =~ "sudo"
    | project DeviceId, SudoProcessId = ProcessId, InvokingUser = InitiatingProcessAccountName, SudoCommandLine = ProcessCommandLine
) on DeviceId, $left.SudoKey == $right.SudoProcessId
| project
    Timestamp,
    DeviceName,
    DeviceId,
    Technique,
    Verdict,
    EffectiveUser = AccountName,
    InvokingUser,
    ProcessLineage,
    GrandparentProcess = InitiatingProcessParentFileName,
    ParentProcess = InitiatingProcessFileName,
    ExecutedProcess = FileName,
    ProcessCommandLine,
    ParentCommandLine = InitiatingProcessCommandLine,
    ProcessId,
    ParentProcessId = InitiatingProcessId,
    GrandparentProcessId = InitiatingProcessParentId,
    SudoCommandLine,
    ReportId
| sort by Timestamp desc
```
