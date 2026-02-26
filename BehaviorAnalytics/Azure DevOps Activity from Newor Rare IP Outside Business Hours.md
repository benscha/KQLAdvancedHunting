# *Azure DevOps Activity from New/Rare IP Outside Business Hours*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1078.004 | Cloud Accounts | https://attack.mitre.org/techniques/T1078/004/ |

#### Description

This rule detects Azure DevOps activities originating from new or rarely seen IP addresses outside of defined business hours. It establishes a baseline of historical IP addresses and flags activities from IPs that have been seen for fewer than a specified number of days, indicating potentially suspicious access.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
// List non-internal Azure DevOps activities excluding business hours
// Exclude business hours: Mon-Fri 06:30-18:30 and Monday 20:30-23:00
// Configuration
// Define your IP Range
let internalIpRange = "1.2.3.4/16";
// Define your default Business hours 
let businessHoursStart = 6 * 60 + 30;  // 06:30 in minutes
let businessHoursEnd = 18 * 60 + 30;   // 18:30 in minutes
let mondayExtraStart = 20 * 60 + 30;   // 20:30 in minutes
let mondayExtraEnd = 23 * 60;          // 23:00 in minutes
let businessDaysStart = 1;             // Monday
let businessDaysEnd = 5;               // Friday
let monday = 1;
let lookbackPeriod = 1d;
let historicalLookback = 29d;
let minHistoricalDays = 3;             // Minimum number of days for known IPs
// Build historical IP list with day count
let HistoricalIPDays = ADOAuditLogs_CL
| where TimeGenerated >= ago(historicalLookback)
| extend isInternalIp = ipv4_is_in_range(IpAddress, internalIpRange)
| where isInternalIp == false and isnotnull(IpAddress)
| summarize UniqueDays = dcount(format_datetime(TimeGenerated, 'yyyy-MM-dd')) by ActorUPN, IpAddress;
// Current activities outside of business hours
let CurrentActivities = ADOAuditLogs_CL
| where TimeGenerated > ago(lookbackPeriod)
| extend Dow = toint(dayofweek(TimeGenerated) / 1d)
| extend MinutesSinceMidnight = 60 * datetime_part("Hour", TimeGenerated) + datetime_part("Minute", TimeGenerated)
| where not(
    // Mon-Fri 06:30-18:30
    (Dow >= businessDaysStart and Dow <= businessDaysEnd and MinutesSinceMidnight >= businessHoursStart and MinutesSinceMidnight <= businessHoursEnd)
    or
    // Monday 20:30-23:00
    (Dow == monday and MinutesSinceMidnight >= mondayExtraStart and MinutesSinceMidnight <= mondayExtraEnd)
)
| extend isInternalIp = ipv4_is_in_range(IpAddress, internalIpRange)
| where isInternalIp == false and isnotnull(IpAddress)
| summarize CountEvents=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated), Actions=make_set(ActionId, 20) by ActorUPN, ActorDisplayName, IpAddress, UserAgent;
// Join with historical data and filter for new/rare IPs
CurrentActivities
| join kind=leftouter HistoricalIPDays on ActorUPN, IpAddress
| extend 
    IPSeenDays = coalesce(UniqueDays, 0),
    IPRiskLevel = case(
        isempty(UniqueDays) or UniqueDays == 0, "High Risk - New IP",
        UniqueDays < minHistoricalDays, "Medium Risk - Rare IP",
        UniqueDays >= minHistoricalDays, "Lower Risk - Known IP",
        "Unknown"
    )
// Only alert for new or rare IPs (less than 3 days)
| where IPRiskLevel in ("High Risk - New IP", "Medium Risk - Rare IP")

```
