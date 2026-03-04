# *Detection of High-Risk Sign-ins from New or Uncommon IPs with User Agent or OS Changes*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1078 | Valid Accounts | https://attack.mitre.org/techniques/T1078 |

#### Description

This query identifies users exhibiting unusual authentication behavior by combining Behavior Analytics with recent sign-in activity. It highlights high‑risk sign-ins originating from previously unseen IP addresses where the user agent or operating system has changed compared to historical patterns. The query enriches findings with historical sign-in context and Identity Info to support investigation of potentially compromised accounts.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let ExludedApps = dynamic(["app-ext-jamfconnect-p"]);
let EnterpriseIPRange = "147.86.0.0/16" ;
let LookbackStart = ago(30d);
let LookbackEnd = ago(1d);
let HistoricalSignins = SigninLogs
| where ResultType == 0
| where TimeGenerated >= LookbackStart and TimeGenerated < LookbackEnd
| extend operatingSystem = tostring(DeviceDetail.operatingSystem)
| summarize HistoricalIPSeenCount = count(), HistoricalUserAgents = make_set(UserAgent), HistoricalOperatingSystems = make_set(operatingSystem) by UserPrincipalName, IPAddress;
BehaviorAnalytics
| where isnotempty(UserPrincipalName)
| where ActionType !contains "Failed"
| where ActivityType !contains "Failed"
| where not(ipv4_is_in_range(SourceIPAddress, EnterpriseIPRange))
| where InvestigationPriority >= 3
| project Timestamp=TimeGenerated, UserPrincipalName, SourceIPAddress, InvestigationPriority
| join kind=inner (
    SigninLogs
    | where ResultType == 0
    | where UserType !in ("Guest")
    | where AppDisplayName !in (ExludedApps)
    | extend operatingSystem = tostring(DeviceDetail.operatingSystem), browser = tostring(DeviceDetail.browser), isManaged = tostring(DeviceDetail.isManaged)
    | where isManaged == "false"
    | where RiskLevelDuringSignIn != "none"
    | project TimeGenerated, UserPrincipalName, SigninIPAddress = IPAddress, AppDisplayName, RiskLevelDuringSignIn, operatingSystem, browser, isManaged, UserAgent
) on UserPrincipalName
| join kind=leftouter (
    HistoricalSignins
) on UserPrincipalName, $left.SigninIPAddress == $right.IPAddress
| project-away UserPrincipalName1, UserPrincipalName2
| extend IPSeenBefore = iff(isnotempty(HistoricalIPSeenCount), true, false)
| extend UserAgentChanged = iff(IPSeenBefore and isnotempty(HistoricalUserAgents) and not(set_has_element(HistoricalUserAgents, UserAgent)), true, false)
| extend OperatingSystemChanged = iff(IPSeenBefore and isnotempty(HistoricalOperatingSystems) and not(set_has_element(HistoricalOperatingSystems, operatingSystem)), true, false)
| extend IPUsageRisk = case(
    IPSeenBefore == false, "High - new IP for this user",
    HistoricalIPSeenCount < 3, "Medium - rare IP for this user",
    HistoricalIPSeenCount >= 3, "Low - frequently used IP",
    "Unknown"
)
| summarize arg_max(TimeGenerated, *) by UserPrincipalName, UserAgent
| where IPSeenBefore == false and ( UserAgentChanged == true or OperatingSystemChanged == true) 
| join kind=leftouter( 
    IdentityInfo 
    | project AccountObjectId, AccountUpn, ReportId )
    on $left.UserPrincipalName == $right.AccountUpn
```
