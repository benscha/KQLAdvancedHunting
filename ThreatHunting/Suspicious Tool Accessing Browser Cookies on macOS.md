# *Suspicious Tool Accessing Browser Cookies on macOS*

## Query Information

### Category: Threat Hunting 

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1539 | Steal Web Session Cookie | https://attack.mitre.org/techniques/T1539 |
| T1552.001 | Unsecured Credentials: Credentials In Files | https://attack.mitre.org/techniques/T1552/001/ |


#### Description

This rule detects when a suspicious command-line tool (e.g., curl, python, bash) attempts to access browser cookie files on a macOS system. This activity could indicate an adversary attempting to steal web session cookies for unauthorized access.


#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

## Defender XDR
```KQL
let suspiciousTools = dynamic(["cp", "tar", "zip", "python", "python3",
    "curl", "scp", "ruby", "perl", "php", "node",
    "osascript", "bash", "sh", "zsh", "rsync"]);
let legitimateBrowsers = dynamic(["google chrome", "safari", "cfprefsd",
    "firefox", "brave browser", "microsoft edge"]);
let cookiePaths = dynamic([
    "/Cookies",         // Chrome, Edge, Brave 
    "cookies.sqlite",   // Firefox
    "Cookies.binarycookies" // Safari 
]);
DeviceProcessEvents
| where FolderPath has "macOS"
| where ProcessCommandLine has_any (cookiePaths)
| where ProcessCommandLine has_any (
    "/Google/Chrome/",
    "/Microsoft Edge/",
    "/BraveSoftware/Brave-Browser/",
    "/com.apple.Safari/",
    "/Firefox/Profiles/"
)
| where tolower(InitiatingProcessFileName) !in (legitimateBrowsers)
| where FileName in~ (suspiciousTools)
| project TimeGenerated, DeviceName, AccountName,
    FileName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath, 
    ProcessCommandLine
```
