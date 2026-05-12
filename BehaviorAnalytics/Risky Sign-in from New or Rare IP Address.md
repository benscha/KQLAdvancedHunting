# *Risky Sign-in from New or Rare IP Address*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1078.004 | Cloud Accounts | https://attack.mitre.org/techniques/T1078/004/ |

#### Description

This query identifies high-risk authentication events by correlating recent risky sign-ins with a user's 30-day IP history. It is designed to filter out "noise" and focus on anomalies where a risky sign-in occurs from a location never seen before for that specific account.

Key Logic & Filtering:
    Initial Risk Assessment: It targets internal (non-guest) users with non-compliant and unmanaged devices where the RiskLevelDuringSignIn is 50 or higher.
    Exclusion List: Specific applications (e.g., "TestAppTEST1") are excluded to reduce false positives.
    Historical Baselining: The query analyzes the last 29 days of successful sign-ins to build a profile of known IP addresses for each user.

Risk Scoring: It categorizes the current sign-in based on IP frequency:
    High Risk: The IP address has never been used by the user in the last 29 days.
    Medium Risk: The IP has been seen fewer than 3 times.
    Lower Risk: The IP is frequently used (3+ times).

Output: The final result focuses exclusively on High Risk (New IP) events, providing security analysts with critical details such as Account UPN, Application, IP Address, and geographic location (City/Country).

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let ExcludedApps = pack_array("TestAppTEST1", "TestAppTEST2");
let RiskySignIns = AADSignInEventsBeta
| where TimeGenerated > ago(1d)
| where isnotempty(RiskLevelDuringSignIn) 
| where Application !in (ExcludedApps)
| where RiskLevelDuringSignIn >= 50
| where IsGuestUser == 0
| where IsCompliant == 0
| where IsManaged == 0
| where RiskLevelAggregated > 1
| project Timestamp, AccountUpn, Application, IPAddress, RiskLevelAggregated, RiskLevelDuringSignIn, RiskState, City, Country, ReportId;
// Count how often an IP was used per account in the last 29 days
let HistoricalIPCounts = AADSignInEventsBeta
| where ErrorCode == 0
| where Timestamp >= ago(29d)
| summarize IPSeenCount = count() by AccountUpn, IPAddress;
// Build the IP list per account
let HistoricalIPs = AADSignInEventsBeta
| where ErrorCode == 0
| where Timestamp >= ago(29d)
| summarize HistoricalIPs = make_set(IPAddress) by AccountUpn;
// Join with RiskySignIns and Counts
RiskySignIns
| join kind=leftouter HistoricalIPs on AccountUpn
| join kind=leftouter HistoricalIPCounts on AccountUpn, IPAddress
| extend 
    IPSeenBefore = iff(isnotempty(IPSeenCount), true, false),
    IPSeenCount = coalesce(IPSeenCount, 0)
| extend IPRiskLevel = case(
        IPSeenBefore == false, "High Risk - New IP",
        IPSeenBefore == true and IPSeenCount < 3, "Medium Risk - Rare IP",
        IPSeenBefore == true and IPSeenCount >= 3, "Lower Risk - Frequent IP",
        "Unknown"
    )
// Filter for only New IPs. here you can adapt the value
| where IPRiskLevel startswith "High"
| project Timestamp, ReportId, AccountUpn, Application, IPAddress, 
          RiskLevelAggregated, RiskLevelDuringSignIn, RiskState, 
          IPSeenBefore, IPSeenCount, IPRiskLevel, City, Country
```




