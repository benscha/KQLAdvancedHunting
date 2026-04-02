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
let ExcludedApps = dynamic(["app-ext-jamfconnect-p"]); // Exclude some Apps
let EnterpriseIPRange = "0.0.0.0/16"; // Define your internal network range here
let ExcludedCountries = dynamic(["Craft Beer Land","Wonderland"]);
let LookbackStart = ago(30d);
// Historical Profile: Establish a baseline of "normal" behavior for each user
let UserHistory = SigninLogs
| where TimeGenerated >= LookbackStart and TimeGenerated < ago(1d)
| where ResultType == 0
| summarize 
    KnownIPs = make_set(IPAddress), 
    KnownAgents = make_set(UserAgent),
    KnownOS = make_set(tostring(DeviceDetail.operatingSystem))
    by UserPrincipalName;
// Current Activity: Analyze recent sign-ins with exclusion filters applied
BehaviorAnalytics
| where TimeGenerated > ago(1d)
| where InvestigationPriority >= 3
| where not(ipv4_is_in_range(SourceIPAddress, EnterpriseIPRange))
| project Timestamp=TimeGenerated, UserPrincipalName, SourceIPAddress, InvestigationPriority
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(1d)
    | where ResultType == 0 
    | where UserType != "Guest"
    | where AppDisplayName !in (ExcludedApps) // Filter out known management or system applications
    | where DeviceDetail.isManaged == "false" // Focus on unmanaged/BYOD devices
    | project TimeGenerated, UserPrincipalName, IPAddress, UserAgent, 
              OS = tostring(DeviceDetail.operatingSystem), AppDisplayName
) on UserPrincipalName
| join kind=leftouter UserHistory on UserPrincipalName
// Check if the current activity matches the historical baseline
| extend IsNewIP = iff(set_has_element(KnownIPs, IPAddress), false, true)
| extend IsNewAgent = iff(set_has_element(KnownAgents, UserAgent), false, true)
| extend IsNewOS = iff(set_has_element(KnownOS, OS), false, true)
// Filter: Identify sign-ins from a new IP combined with unknown technical signatures (Agent/OS)
| where IsNewIP == true and (IsNewAgent == true and IsNewOS == true)
| extend IpInfo = geo_info_from_ip_address(SourceIPAddress)
| extend Country = tostring(IpInfo.country)
| where Country !in (ExcludedCountries) // Exclude sign-ins from defined Countries
| summarize arg_max(TimeGenerated, *) by UserPrincipalName
```
