# *Risky Sign In from unkown Device and rarely used IP*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1078.004 | Cloud Accounts | https://attack.mitre.org/techniques/T1078/004/ |

#### Description

This rule detects risky sign-in attempts from devices that are either unmanaged/not onboarded or from IP addresses that are rarely used by the specific user. It focuses on first-time connections from a device for internal members, excluding corporate network traffic and failed login attempts. The risk classification is based on historical IP usage, flagging new IPs as 'High Risk' and infrequent IPs (seen less than 3 distinct days in the last 29 days) as 'Medium Risk'. The rule specifically looks for events where the source device is unknown and the IP address has been seen less than 2 distinct days historically.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
// Define corporate network range to exclude internal traffic
let CorporateIPRange = "0.0.0.0/16";
// Define the timeframe for historical analysis
let LookbackHistory = 29d;
// Set reference point to the beginning of the current day
let TodayStart = startofday(now());
// Identify users with suspicious behavior within the detection window
let AffectedUsers = materialize(
    BehaviorAnalytics
    | where TimeGenerated > ago(4h)
    // Filter out internal corporate traffic
    | where not(ipv4_is_in_range(SourceIPAddress, CorporateIPRange))
    | where isnotempty(UserPrincipalName)
    // Exclude noise from failed login attempts
    | where ActivityType != "FailedLogOn"
    // Focus on first-time connections from a device
    | where ActivityInsights.FirstTimeUserConnectedFromDevice == true
    | join kind=inner (
        IdentityInfo
        | summarize arg_max(TimeGenerated, *) by AccountUpn
        | project AccountUpn, TenantMembershipType
    ) on $left.UserPrincipalName == $right.AccountUpn
    // Limit to internal members only
    | where TenantMembershipType == "Member"
    | distinct UserPrincipalName
);
// Retrieve historical IP usage for the identified users
let HistoricalIPs = 
    EntraIdSignInEvents
    // Filter for the 29-day period prior to today
    | where TimeGenerated between ((TodayStart - LookbackHistory) .. (TodayStart - 1ms))
    // Optimization: filter by affected users before processing
    | where AccountUpn in (AffectedUsers)
    | where ErrorCode == 0
    // Count unique days each user was seen from a specific IP
    | summarize DistinctDaysSeenFromIP = dcount(bin(TimeGenerated, 1d)) 
        by AccountUpn, IPAddress
    | project UserPrincipalName = AccountUpn, SourceIPAddress = IPAddress, DistinctDaysSeenFromIP;
// Main query to correlate current behavior with historical data and device status
BehaviorAnalytics
| where TimeGenerated > ago(4h)
| where not(ipv4_is_in_range(SourceIPAddress, CorporateIPRange))
| where isnotempty(UserPrincipalName)
| where ActivityType != "FailedLogOn"
| where ActivityInsights.FirstTimeUserConnectedFromDevice == true
| join kind=inner hint.strategy=broadcast (
    IdentityInfo
    | summarize arg_max(TimeGenerated, *) by AccountUpn
    | project AccountUpn, TenantMembershipType
) on $left.UserPrincipalName == $right.AccountUpn
| where TenantMembershipType == "Member"
| extend SourceDeviceLower = tolower(SourceDevice)
// Check if the source device is managed or onboarded
| join kind=leftouter (
    DeviceInfo
    | extend DeviceNameLower = tolower(DeviceName)
    | project DeviceNameLower, DeviceName, DeviceId, OnboardingStatus
) on $left.SourceDeviceLower == $right.DeviceNameLower
// Filter for unmanaged or non-onboarded devices
| where OnboardingStatus != "Onboarded" or isempty(OnboardingStatus)
// Enrich current activity with historical IP frequency
| join kind=leftouter hint.strategy=broadcast (
    HistoricalIPs
) on UserPrincipalName, SourceIPAddress
// Classify risk based on how often the IP was seen in the past
| extend IPRiskClassification = case(
    isempty(DistinctDaysSeenFromIP), "High Risk - New IP",
    DistinctDaysSeenFromIP < 3,       "Medium Risk - Infrequent IP",
    "Low Risk"
)
// Filter out low-risk events
| where IPRiskClassification != "Low Risk"
// Get the most recent relevant event per user
| summarize arg_max(TimeGenerated, *) by UserPrincipalName
// Final filters for unknown devices and very low historical IP presence
| where isempty(DeviceName)
| where DistinctDaysSeenFromIP < 2
```
