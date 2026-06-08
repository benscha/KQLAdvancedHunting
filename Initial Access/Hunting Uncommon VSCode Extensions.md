# *Hunting Uncommon VSCode Extensions*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1195 | Supply Chain Compromise | https://attack.mitre.org/techniques/T1195/ |
| T1195.002 | Compromise Software Supply Chain | https://attack.mitre.org/techniques/T1195/002/ |


#### Description
This query proactively hunts for the installation of potentially malicious or untrusted Visual Studio Code extensions. Instead of relying on post-exploitation behavior, it catches the initial entry by correlating recent extension file creations with unusual network activity and global file prevalence.
How It Works
- File Creation Monitoring: Identifies newly created package.json files within the VS Code extensions directories (.vscode/extensions) over the last 7 days to capture new installations on both Windows and macOS.
- Network Correlation: Collects network events originating from VS Code processes or official domains, then joins them with the file events within a tight 2-minute window.
- Network Scoring: Assigns a risk score (10 points) if the extension was downloaded from an unverified, non-Microsoft source URL.
- Prevalence Checking: Leverages the FileProfile() function to check Microsoft's global threat intelligence database. If the package SHA256 is globally rare (installed on fewer than 1,000 devices), it adds another 10 points.
- Risk Classification: Combines the metrics into a TotalRiskScore to classify the alert severity from Low to Critical. Highly rare extensions downloaded from non-standard URLs trigger a Critical severity alert.

Threat Hunting Value
This query is designed for proactive threat hunting rather than real-time alerting due to the resource-intensive nature of the 7-day network join and the FileProfile() API invocation. It is highly effective at discovering targeted supply-chain attacks, rogue lookalike extensions (typosquatting), or custom malicious extensions introduced to developer workstations.

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
// Define time window for network join (2 minutes)
let TimeWindow = 2m;
// Gather installed extensions including SHA256 of the package.json (Works for Windows & macOS)
let InstalledExtensions = 
    DeviceFileEvents
    | where TimeGenerated > ago(7d)
    | where FolderPath has ".vscode/extensions" or FolderPath has @".vscode\extensions"
    | where ActionType == "FileCreated" and FileName =~ "package.json"
    | where isnotempty(SHA256)
    // Dynamic extraction handles both backward and forward slashes
    | extend ExtensionID = extract(@"(?i)\.vscode[/\\]extensions[/\\]([^/\\]+)", 1, FolderPath)
    | project FileCreationTime = TimeGenerated, DeviceName, DeviceId, ExtensionID, FolderPath, SHA256,
              InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessCreationTime, RequestAccountName;
// Gather network connections including macOS specific VS Code processes
let NetworkConnections = 
    DeviceNetworkEvents
    | where TimeGenerated > ago(7d)
    // Expanded process list to support macOS binaries (Electron, Code Helper, Visual Studio Code)
    | where InitiatingProcessFileName in~ ("code.exe", "code", "vsce-sign.exe", "Electron", "Visual Studio Code", "Code Helper") 
      or RemoteUrl has "vsassets.io" or RemoteUrl has "visualstudio.com"
    | project NetworkTime = TimeGenerated, DeviceId, RemoteIP, RemoteUrl, RemotePort, 
              InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessCreationTime;
// Correlation and initial scoring based on network source
let ScoredNetworkData = 
    InstalledExtensions
    | join kind=inner (NetworkConnections) on DeviceId, InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessCreationTime
    | where FileCreationTime between ((NetworkTime - TimeWindow) .. (NetworkTime + TimeWindow))
    | extend TimeDifferenceSeconds = datetime_diff('second', FileCreationTime, NetworkTime)
    // Scoring based on the source URL
    | extend NetworkScore = iif(RemoteUrl has "vsassets.io" or RemoteUrl has "visualstudio.com", 0, 10);
// Query FileProfile() for global prevalence
ScoredNetworkData
| invoke FileProfile(SHA256, 10000)
// Scoring based on GlobalPrevalence (handling empty values as high risk)
| extend PrevalenceScore = case(
    GlobalPrevalence < 1000 or isempty(GlobalPrevalence), 10,
    GlobalPrevalence >= 1000 and GlobalPrevalence <= 2500, 5,
    0
)
// Calculate total risk score and assign severity levels
| extend TotalRiskScore = NetworkScore + PrevalenceScore
| extend Severity = case(
    TotalRiskScore >= 20, "Critical",
    TotalRiskScore >= 10, "High",
    TotalRiskScore >= 5, "Medium",
    "Low"
)
// Select and arrange columns for the alert overview
| project Severity, TotalRiskScore, NetworkScore, PrevalenceScore, GlobalPrevalence, ExtensionID, DeviceName, RequestAccountName, 
          RemoteUrl, RemoteIP, SHA256, FolderPath, FileCreationTime, TimeDifferenceSeconds
| order by TotalRiskScore desc, FileCreationTime desc```
