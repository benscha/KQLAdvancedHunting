# *Suspicious Shell or Direct Process Execution from Browser*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059 | Command and Scripting Interpreter | https://attack.mitre.org/techniques/T1059/ |

#### Description
This rule detects suspicious command-line activity originating from browser processes. It looks for shell processes (sh, bash, zsh, etc.) executing with suspicious keywords (curl, wget, whoami, pwd) or direct execution of suspicious binaries (curl, wget, osascript, pwsh, python*, perl*, php*) where the parent process is a web browser. This could indicate drive-by download attacks, malicious browser extensions, or exploitation of browser vulnerabilities leading to command execution.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References


## Sentinel

```KQL
let BrowserProcesses = dynamic([
    "Google Chrome",
    "firefox",
    "Opera",
    "Safari",
    "com.apple.WebKit.WebContent",
    "Microsoft Edge"
]);
let ShellProcesses = dynamic(["sh", "bash", "dash", "ksh", "tcsh", "zsh"]);
let SuspiciousShellKeywords = dynamic(["curl", "nscurl", "wget", "whoami", "pwd"]);
let SuspiciousDirectProcesses = dynamic(["curl", "wget", "osascript", "pwsh"]);
// ---- Main Query ----
DeviceProcessEvents
| where Timestamp > ago(9m)
| where ActionType in ("ProcessCreated", "ProcessStarted")
// Parent process is a browser
| where InitiatingProcessFileName in~ (BrowserProcesses)
     or InitiatingProcessFileName startswith_cs "Google Chrome Helper"
// Two paths: Shell with suspicious arguments OR directly suspicious processes
| where
    (
        // Path 1: Shell process with suspicious keywords in the command line
        FileName in~ (ShellProcesses)
        and ProcessCommandLine != ""
        and (
            ProcessCommandLine has_any (SuspiciousShellKeywords)
        )
    )
    or
    (
        // Path 2: Directly suspicious processes (curl, wget, python*, perl*, php*, osascript, pwsh)
        FileName in~ (SuspiciousDirectProcesses)
        or FileName startswith "python"
        or FileName startswith "perl"
        or FileName startswith "php"
    )
// Command line must not be empty
| where isnotempty(ProcessCommandLine)
// Result projection
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FileName,
    ProcessCommandLine,
    FolderPath,
    ProcessId,
    InitiatingProcessId
| sort by Timestamp desc
```
