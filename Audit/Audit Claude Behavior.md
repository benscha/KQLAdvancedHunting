# *Audit Claude Behavior*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |


#### Description
This query is a comprehensive security monitoring tool designed to detect and categorize potentially malicious activities initiated by Claude. It acts as a behavioral guardrail by auditing process, file, and network events for signs of compromise or insider threats.

#### Key Functional Areas:
- Child Process Execution: Identifies when a monitored process launches unexpected shells or system tools (e.g., powershell.exe, nc, curl).
- Destructive Operations: Monitors for commands that could lead to data loss or system instability, such as bulk file deletions or disk formatting.
- Sensitive File Access: Detects unauthorized attempts to read high-value targets like SSH keys, .env files, or credential stores.
- Privilege Escalation: Flags attempts to gain administrative or root permissions using commands like sudo, runas, or chmod +s.
- Git & Repository Integrity: Audits for destructive version control actions, including force-pushes or hard resets that could jeopardize source code.
- Package & Software Management: Tracks the installation of new software or libraries (via npm, pip, apt) to prevent the introduction of shadow IT or malware.
- Anomaly Detection: Flags high-volume process activity occurring outside of standard business hours (7:00 AM – 7:00 PM).
- 
#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References

## Defender XDR
```KQL
let ClaudeProcesses = dynamic(["claude"]);
// ── Child Process Execution (Severity: Medium / High) ──────────────────────
DeviceProcessEvents
| where InitiatingProcessFileName has_any(ClaudeProcesses)
| where FileName has_any(dynamic([
    "cmd.exe", "powershell.exe", "pwsh.exe", "bash", "sh", "zsh",
    "python.exe", "python3", "pip", "npm", "curl", "wget", "nc", "ncat"
  ]))
| extend
    Category = "Child Process Execution",
    Severity = case(
        FileName in~("nc", "ncat"),                             "Critical",
        FileName in~("powershell.exe", "pwsh.exe", "cmd.exe"),   "High",
        FileName in~("curl", "wget"),                            "High",
        "Medium")
| project Timestamp, DeviceName, AccountName, Category, Severity,
    InitiatingProcessFileName, FileName, ProcessCommandLine
| union (
  // ── Destructive Operations (Severity: Critical / High) ───────────────────
  DeviceProcessEvents
  | where InitiatingProcessFileName has_any(ClaudeProcesses)
  | where ProcessCommandLine has_any(dynamic([
      "rm -rf", "rm -r", "del /f", "del /s", "format",
      "shred", "wipe", "rmdir /s", "Remove-Item -Recurse"
    ]))
  | extend
      Category = "Destructive Operation",
      Severity = case(
          ProcessCommandLine has_any(dynamic(["rm -rf", "format", "shred", "wipe"])),  "Critical",
          ProcessCommandLine has_any(dynamic(["del /f", "del /s", "rmdir /s"])),       "High",
          "Medium")
  | project Timestamp, DeviceName, AccountName, Category, Severity,
      InitiatingProcessFileName, FileName, ProcessCommandLine
)
| union (
  // ── Sensitive File Access (Severity: Critical / High / Medium) ────────────
  DeviceFileEvents
  | where InitiatingProcessFileName has_any(ClaudeProcesses)
  | where FileName has_any(dynamic([
      ".env", "id_rsa", "id_ed25519", ".pem", ".p12", ".pfx",
      "credentials", "secrets", "token", "passwd", "shadow",
      ".kdbx", ".key"
    ]))
  | extend
      Category = "Sensitive File Access",
      Severity = case(
          FileName in~("shadow", "passwd", "id_rsa", "id_ed25519"),                   "Critical",
          FileName in~(".env", "credentials", "secrets", "token", ".pem", ".p12"),  "High",
          "Medium")
  | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, Category, Severity,
      InitiatingProcessFileName, FileName = strcat(FolderPath, "/", FileName),
      ProcessCommandLine = ActionType
)
| union (
  // ── Privilege Escalation (Severity: Critical / High) ──────────────────────
  DeviceProcessEvents
  | where InitiatingProcessFileName has_any(ClaudeProcesses)
  | where ProcessCommandLine has_any(dynamic([
      "sudo ", "runas", "chmod +s", "chown root",
      "setuid", "net localgroup administrators", "Add-LocalGroupMember"
    ]))
  | extend
      Category = "Privilege Escalation",
      Severity = case(
          ProcessCommandLine has_any(dynamic(["chmod +s", "setuid", "chown root"])),                   "Critical",
          ProcessCommandLine has_any(dynamic(["net localgroup administrators", "Add-LocalGroupMember"])),  "Critical",
          "High")
  | project Timestamp, DeviceName, AccountName, Category, Severity,
      InitiatingProcessFileName, FileName, ProcessCommandLine
)
| union (
  // ── Git Manipulations (Severity: High / Medium) ──────────────────────────
  DeviceProcessEvents
  | where InitiatingProcessFileName has_any(ClaudeProcesses)
  | where ProcessCommandLine has_any(dynamic([
      "git push --force", "git push -f", "git branch -D",
      "git tag -d", "git reset --hard", "git clean -fd"
    ]))
  | extend
      Category = "Git Repository Manipulation",
      Severity = case(
          ProcessCommandLine has_any(dynamic(["git push --force", "git push -f"])),  "High",
          ProcessCommandLine has_any(dynamic(["git reset --hard", "git branch -D"])),  "High",
          "Medium")
  | project Timestamp, DeviceName, AccountName, Category, Severity,
      InitiatingProcessFileName, FileName, ProcessCommandLine
)
| union (
  // ── Package Installations (Severity: Medium / Low) ───────────────────────
  DeviceProcessEvents
  | where InitiatingProcessFileName has_any(ClaudeProcesses)
  | where FileName has_any(dynamic(["pip", "pip3", "npm", "yarn", "apt", "apt-get", "brew", "choco"]))
  | where ProcessCommandLine has_any(dynamic(["install", "add", "upgrade"]))
  | extend
      Category = "Package Installation",
      Severity = case(
          FileName in~("apt", "apt-get", "choco"),  "Medium",
          "Low")
  | project Timestamp, DeviceName, AccountName, Category, Severity,
      InitiatingProcessFileName, FileName, ProcessCommandLine
)
| union (
  // ── Anomaly: Off-Hours Activity (Severity: Medium) ───────────────────────
  DeviceProcessEvents
  | where InitiatingProcessFileName has_any(ClaudeProcesses)
  | extend HourOfDay = datetime_part("hour", Timestamp)
  | where HourOfDay !between(7 .. 19)
  | summarize
      Count = count(),
      ProcessCommandLineSet = make_set(ProcessCommandLine, 5)
      by Timestamp = bin(Timestamp, 1h), DeviceName, AccountName,
         InitiatingProcessFileName, FileName, HourOfDay
  | where Count > 10
  | extend
      Category = "Anomaly - Off-Hours Activity",
      Severity = "Medium"
  | project Timestamp, DeviceName, AccountName, Category, Severity,
      InitiatingProcessFileName, FileName,
      ProcessCommandLine = tostring(ProcessCommandLineSet)
)
```
