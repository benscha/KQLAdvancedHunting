# *Privileged RDP Session Source Mismatch*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1078 | Valid Accounts | https://attack.mitre.org/techniques/T1078/ |
| T1021.001 | Valid Accounts | https://attack.mitre.org/techniques/T1021/001/ |

#### Description
This query detects Remote Desktop Protocol (RDP) logons using privileged accounts where the account owner did not recently log on to the source device using their standard account. In a secure enterprise workflow, an administrator typically initiates an RDP session from their own workstation. For example, if marc.mueller is logged into a workstation, an RDP session from that machine using the privileged account sysa.mmueller is expected.

However, if sysa.mmueller initiates a session from a device where only j.schmidt has been active, it flags a significant anomaly. This pattern often points to:
- Lateral Movement: An attacker using compromised privileged credentials from a previously breached standard workstation.
- Credential Theft: The use of stolen admin credentials from an unauthorized source.
- Account Sharing: Violation of security policies regarding individual accountability.

The query correlates data from DeviceLogonEvents and DeviceNetworkEvents to resolve the source device via IP mapping and then cross-references the naming patterns of the privileged account against the interactive users on that source device.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- Full Blog Post on Linkedin: https://www.linkedin.com/pulse/detecting-unauthorized-privileged-rdp-sessions-benjamin-zulliger-7pxye/

## Sentinel

```KQL
// ============================================================================
// Configuration variables — adjust these to match your environment
// ============================================================================
// Regex pattern to exclude shared terminal servers (would cause excessive false positives)
let ExcludeTerminalServerRegex = @"^tsar[ae][0-9]{3}";
// Regex pattern to identify privileged accounts by naming convention
let PrivUserPattern = @"sys[ae]\.[a-z]+";
// Regex pattern to identify privileged accounts in the recent users list (for short name extraction)
let PrivRecentUserPattern = @"^sys[ae]\.";
// Service account domains to exclude from recent user enrichment
let ExcludedAccountDomains = dynamic(["nt service", "font driver host", "window manager", "nt-autorität", "autorite nt", "nt authority"]);
// Generic account names to exclude from recent user enrichment
let ExcludedAccountNames = dynamic(["-", "admin"]);
// IP ranges to exclude from device IP mapping (link-local, private)
let ExcludeIPRange1 = "169.254.0.0/16";
let ExcludeIPRange2 = "192.168.0.0/16";
// ============================================================================
// Time Settings
// ============================================================================
// Detection window for new privileged RDP logons (aligned with scheduled run interval)
let DetectionWindow = 1h;
// Lookback window for IP resolution and recent user context
let LookbackWindow = 1d;
// Maximum allowed time difference (in seconds) between logon and IP observation for device resolution
let MaxTimeDiffSeconds = 3600;
// ============================================================================
// Query start
// ============================================================================
// Collect all known device-to-IP mappings within lookback window (broad window to handle IP changes)
let DeviceIPs = DeviceNetworkEvents
| where Timestamp > ago(LookbackWindow)
| where isnotempty(DeviceName)
| where not(ipv4_is_in_range(LocalIP, ExcludeIPRange1))
| where not(ipv4_is_in_range(LocalIP, ExcludeIPRange2))
| where LocalIP != "0.0.0.0"
| project DeviceIP_Timestamp = Timestamp, DeviceName, LocalIP;
// Privileged RDP logons within detection window
let PrivLogons = DeviceLogonEvents
| where Timestamp > ago(DetectionWindow)
| where LogonType == "RemoteInteractive"
| where not(DeviceName matches regex ExcludeTerminalServerRegex)
| where AccountName matches regex PrivUserPattern
| where isnotempty(RemoteIP)
| project-rename PrivAccountName = AccountName, LogonTimestamp = Timestamp;
// Resolve RemoteIP to the closest matching source device (within configured tolerance)
PrivLogons
| join kind=inner DeviceIPs on $left.RemoteIP == $right.LocalIP
| extend TimeDiff = abs(datetime_diff('second', LogonTimestamp, DeviceIP_Timestamp))
| where TimeDiff < MaxTimeDiffSeconds
| summarize arg_min(TimeDiff, *) by LogonTimestamp, DeviceName, PrivAccountName, RemoteIP
// Enrich with recent interactive users on the resolved source device
| join kind=leftouter (
    DeviceLogonEvents
    | where Timestamp > ago(LookbackWindow)
    | where LogonType in ("Interactive", "RemoteInteractive")
    | where AccountDomain !in (ExcludedAccountDomains)
    | where AccountName !in (ExcludedAccountNames)
    | summarize LastLogon = max(Timestamp),
                RecentUsers = make_set(AccountName, 3)
              by DeviceName
) on $left.DeviceName1 == $right.DeviceName
| summarize arg_max(LogonTimestamp, *) by DeviceName1, PrivAccountName
| where isnotempty(RecentUsers)
// Expand each recent user and extract comparable short name
| mv-expand RecentUser = RecentUsers to typeof(string)
| extend UNameshort1 = extract(@"\.(.+)$", 1, PrivAccountName)
// For priv accounts take only the surname, for regular accounts take first initial + surname
| extend UNameshort2 = iif(
    RecentUser matches regex PrivRecentUserPattern,
    extract(@"\.(.+)$", 1, RecentUser),
    strcat(substring(RecentUser, 0, 1), extract(@"\.(.+)$", 1, RecentUser))
)
// Check if any recent user on the source device matches the priv account owner
| summarize MatchFound = countif(UNameshort2 has UNameshort1), 
            arg_max(LogonTimestamp, *) 
          by DeviceName1, PrivAccountName
// Alert only when no matching user was found — potential unauthorized priv account usage
| where MatchFound == 0
| extend RecentUsersOnSource = strcat_array(RecentUsers, ", ")
| project LogonTimestamp, DeviceName, DeviceName1, PrivAccountName, RemoteIP, RecentUsersOnSource```
