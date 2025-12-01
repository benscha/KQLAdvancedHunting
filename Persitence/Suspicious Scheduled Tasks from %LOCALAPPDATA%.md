# *Suspicious Scheduled Tasks from %LOCALAPPDATA%*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1053.005 | Scheduled Tasks | https://attack.mitre.org/techniques/T1053/005 |


#### Description
This rule detects suspicious scheduled tasks that execute binaries from the AppData\Local folder, which is a common location for user-specific applications and can be abused by adversaries for persistence. Such behavior is often used by Infostealer Malware. The rule specifically looks for processes initiated by 'svchost.exe' or 'taskeng.exe' with command lines indicating scheduled task execution, and then filters out a whitelist of known legitimate applications that operate from this directory. It also incorporates a global prevalence check to further reduce false positives.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- Inspired by https://www.linkedin.com/posts/mauricefielenbach_threatintel-cybersecurity-malwareanalysis-activity-7392988024168656896-Ey4C?utm_source=share&utm_medium=member_desktop&rcm=ACoAAA3PxAIBcfr6M0unx3xMtHTyCNuehMi3uNQ


## Defender XDR
```KQL
//Whitelisted FolderPaths
let WhitelistedPaths = dynamic([
    "\\AppData\\Local\\Chrome\\User Data",
    "\\AppData\\Local\\Microsoft\\Teams\\current",
    "\\AppData\\Local\\ZoomMeetings\\bin",
    "\\AppData\\Local\\Google\\GoogleUpdater\\",
    "\\AppData\\Local\\Opera\\autoupdate\\opera_autoupdate.exe",
    "\\AppData\\Local\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe",
    "\\AppData\\Local\\Dropbox\\DropboxUpdater\\",
    "\\AppData\\Local\\Mozilla Firefox\\firefox.exe",
    "\\AppData\\Local\\GoToMeeting\\",
    "\\AppData\\Local\\Mozilla Firefox\\default-browser-agent.exe",
    "\\AppData\\Local\\BraveSoftware\\Update\\BraveUpdate.exe",
    "\\AppData\\Local\\MEGAsync\\MEGAupdater.exe",
    "AppData\\Local\\VLC Plus Player Updater\\Updater.exe",
    "\\AppData\\Local\\ConvertMate\\UpdateRetreiver.exe",
    "AppData\\Local\\Programs\\Syncthing\\stctl.exe",
    "\\AppData\\Local\\Programs\\Opera Air\\autoupdate\\opera_autoupdate.exe",
    "\\AppData\\Local\\PDFClick\\PDFClickUpdater.exe",
    "\\AppData\\Local\\AVAST Software\\Browser\\Application\\AvastBrowser.exe",
    "\\AppData\\Local\\Vivaldi\\Application\\update_notifier.exe",
    "\\AppData\\Local\\anaconda3\\envs\\EMMA\\python.exe"
]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in ("svchost.exe", "taskeng.exe")
| where InitiatingProcessCommandLine has_all ("netsvcs", "Schedule") or InitiatingProcessFileName == "taskeng.exe"
| where FolderPath matches regex @"(?i)C:\\Users\\.*\\AppData\\Local\\.*"
// Substring-based Whitelisting
| where not(FolderPath has_any (WhitelistedPaths))
| extend TaskSource = iff(InitiatingProcessFileName == "svchost.exe", "Scheduled Task (svchost)", "Scheduled Task (taskeng)")
| invoke FileProfile(SHA1)
| where GlobalPrevalence < 30000
| order by Timestamp desc

```
