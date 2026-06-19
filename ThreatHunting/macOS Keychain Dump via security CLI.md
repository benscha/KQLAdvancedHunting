# *macOS Keychain Dump via security CLI*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1555.001 | Credentials from Password Stores: Keychain | https://attack.mitre.org/techniques/T1555/001|


#### Description

This query detects attempts to dump macOS Keychain credentials using the native security command-line tool with the dump-keychain -d flag, which exports stored passwords in cleartext. It focuses on high-fidelity scenarios where the dump is initiated by a suspicious parent process such as shell interpreters (bash, zsh, python) or known post-exploitation tools or by unsigned binaries executing from staging directories like /tmp/, Downloads, or hidden home directories. Legitimate MDM and management tools are excluded to reduce noise. Repeated dump attempts by the same account are aggregated and scored by risk level, helping analysts prioritize automated credential harvesting over isolated accidental executions.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### Possible false positives
- Legitimate administrative tools (e.g., MDM solutions like Jamf, Kandji, Mosyleclient) performing keychain operations.
- Developers or system administrators legitimately using scripting languages (python, ruby, perl, etc.) for system management tasks that involve keychain access.
- Accidental or benign execution of 'security dump-keychain' by a user or script, especially if not repeated.

## Defender XDR
```KQL
let SuspiciousParents = dynamic([
    "bash", "sh", "zsh", "python", "python3", "ruby",
    "perl", "osascript", "curl", "wget", "nc", "ncat"
]);
let LegitimateAdminTools = dynamic([
    "Jamf", "kandji", "mosyleclient", "nudge", "munkimanager"
]);
DeviceProcessEvents
| where FileName =~ "security"
| where ProcessCommandLine has_all ("dump-keychain", "-d")
// Scope: macOS devices
| where FolderPath startswith "/usr/bin/security"
    or FolderPath startswith "/bin/security"
// Initiating process: suspicious interpreters or unsigned binaries
| where InitiatingProcessFileName in~ (SuspiciousParents)
    or (
        InitiatingProcessSignerType == "None"
        and not(InitiatingProcessFolderPath startswith "/Applications/")
    )
// Whitelisting legitimate MDM tools
| where not(InitiatingProcessFileName has_any (LegitimateAdminTools))
// Execution from known staging paths
| where InitiatingProcessFolderPath has_any (
        "/tmp/", "/var/folders/", "/private/tmp/",
        "/Users/Shared/", "/Library/Caches/",
        "Downloads", ".Trash"
    )
    or (
        InitiatingProcessFolderPath matches regex @"/Users/[^/]+/\.[^/]+"
        // Hidden directory under home
    )
// Temporal clustering: same account performs multiple dumps in a short time
| summarize
    DumpCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    CommandLines = make_set(ProcessCommandLine, 10),
    InitiatingProcesses = make_set(strcat(InitiatingProcessFileName, " | ", InitiatingProcessFolderPath), 5)
    by DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessSignerType
| where DumpCount >= 1
// Optional: for repeated dumps only, increase to >= 2 for high-fidelity-only mode
| extend
    RiskScore = case(
        InitiatingProcessFileName in~ (SuspiciousParents) and DumpCount >= 2, "Critical",
        InitiatingProcessSignerType == "None" and DumpCount >= 2, "High",
        InitiatingProcessFileName in~ (SuspiciousParents), "High",
        InitiatingProcessSignerType == "None", "Medium",
        "Low"
    ),
    TimeDeltaSeconds = datetime_diff("second", LastSeen, FirstSeen)
| where RiskScore in ("Critical", "High", "Medium")
| project
    FirstSeen, LastSeen, TimeDeltaSeconds,
    DeviceName, AccountName,
    InitiatingProcessFileName, InitiatingProcessSignerType,
    InitiatingProcesses, CommandLines,
    DumpCount, RiskScore
| sort by RiskScore asc, DumpCount desc
```
