# *Suspicious VS Code Extensions Hunting*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059 | Command and Scripting Interpreter | https://attack.mitre.org/techniques/T1059/ |


#### Description
This Kusto Query Language (KQL) script is designed to hunt for potentially malicious Visual Studio Code extensions across two risk profiles.

The first section defines SuspiciousExtension, which monitors for new file creations in the VS Code extensions folder that were not initiated by trusted processes (like VS Code itself or system setup tools). It specifically looks for files created by suspicious parent processes such as PowerShell, CMD, curl, or Wget.

The second section defines HighRiskExtension, which also monitors the extensions folder but narrows the search to high-risk file types (like .js, .exe, or .ps1) that appear from sources other than official updater processes.

Finally, the query unions these two datasets and applies a reputation check using the FileProfile function, filtering out common, well-known files to focus only on rare or unique files (Global Prevalence < 10000) that warrant further investigation.

#### Risk
Defense Evasion

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- 

## Defender XDR
```KQL
let SuspiciousExtension = DeviceFileEvents
| where TimeGenerated > ago(1h)
| where ActionType == "FileCreated"
| where FolderPath has_any ("vscode", "visual studio code", "microsoft vs code")
| where FolderPath has "extensions"
// Extension was NOT created by a normal VSCode process
| where InitiatingProcessFileName !in~ (
    "code.exe", "code-insiders.exe", "node.exe", 
    "winget.exe", "setup.exe", "CodeSetup.exe", "jamf app installers"
  )
// Suspicious parent processes
| where InitiatingProcessFileName has_any (
    "powershell", "cmd", "wscript", "cscript", 
    "mshta", "curl", "wget", "certutil"
  );
let HighRiskExtension = DeviceFileEvents
| where TimeGenerated > ago(1h)
| where ActionType == "FileCreated"
| where FolderPath has_any ("vscode", "visual studio code", "microsoft vs code")
| where FolderPath has "extensions"
// Only suspicious file types
| extend FileExtension = tolower(tostring(parse_path(FileName).Extension))
| where FileExtension in ("js", "ts", "vsix", "json", "ps1", "sh", "exe", "dll", "py")
// Not from the normal VSCode updater process
| where InitiatingProcessFileName !in~ (
    "code.exe", "code-insiders.exe", "node.exe", "winget.exe", "setup.exe"
  );
union SuspiciousExtension, HighRiskExtension
| invoke FileProfile(SHA256)
| where GlobalPrevalence < 10000
| where not(IsCertificateValid == 1 and SignatureState == "SignedValid" and Issuer == "Microsoft Code Signing PCA 2024")
```

