# *Post Phishing UrlClick SuspiciousSignIns*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566 | Phishing | https://attack.mitre.org/techniques/T1566 |

#### Description

Most of us know the Task, that you have to analyse post Phishing E-Mail Events. This Query detects users who clicked on a defined phishing link (Defined by SenderIP [phishingSenderIPs] or Subject [phishingSubjects] ) and experienced a successful login from an unknown or rare IP address within 24 hours of the click.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
// Define whitelisted URLs
let whitelistedURLs = dynamic([
    "https://aka.ms/LearnAboutSenderIdentification",
    "https://givmegithubstars.com"
]);
// Define whitelisted login IP ranges
let whitelistedIPRange = dynamic(["XX.XX.0.0/16", "10.0.0.0/8"]);
// Define known phishing indicators
let phishingSenderIPs = dynamic(["XX.XX.XX.XX", "XX.XX.XX.XX"]);
let phishingSubjects = dynamic([
    "Complete Document E-sign Agreement Review",
    'Matheus Bernardes shared "Document!"'
]);
// IP History: Count how many times the user has logged in from this IP (last 29 days)
let HistoricalIPCounts = EntraIdSignInEvents
| where ErrorCode == 0
| where Timestamp >= ago(29d)
| summarize IPSeenCount = count() by AccountUpn, IPAddress;
// Identify users who clicked on phishing links
let PhishClickUsers = EmailEvents
| where SenderIPv4 in (phishingSenderIPs)
    or Subject in (phishingSubjects)
    or Subject has_any (phishingSubjects)
| join EmailUrlInfo on NetworkMessageId
| join UrlClickEvents on Url
| where Url !in (whitelistedURLs)
| project AccountUpn, Url, ClickTimestamp = Timestamp;
// Correlate logins after the click with IP history
PhishClickUsers
| join kind=leftouter (
    EntraIdSignInEvents
    | where ErrorCode == 0
    | project 
        AccountUpn,
        LoginTimestamp = Timestamp,
        IPAddress,
        Country,
        City,
        DeviceName,
        Application,
        LogonType,
        IsManaged,
        ConditionalAccessStatus,
        RiskLevelDuringSignIn,
        UserAgent
) on AccountUpn
| where isnotempty(LoginTimestamp)
| where LoginTimestamp > ClickTimestamp
| where LoginTimestamp < ClickTimestamp + 24h
| extend MinutesSinceClick = datetime_diff('minute', LoginTimestamp, ClickTimestamp)
| where not(ipv4_is_in_any_range(IPAddress, whitelistedIPRange))
// Join with IP history data
| join kind=leftouter HistoricalIPCounts on AccountUpn, IPAddress
| extend IPSeenCount = coalesce(IPSeenCount, 0)
| extend IPRiskLevel = case(
    IPSeenCount == 0,            "High Risk - New IP",
    IPSeenCount < 3,             "Medium Risk - Rare IP",
    IPSeenCount >= 3,            "Lower Risk - Frequent IP",
    "Unknown"
)
| where IPSeenCount < 2
| project
    AccountUpn,
    ClickTimestamp,
    Url,
    LoginTimestamp,
    MinutesSinceClick,
    IPAddress,
    Country,
    City,
    DeviceName,
    Application,
    RiskLevelDuringSignIn,
    ConditionalAccessStatus,
    IPSeenCount,
    IPRiskLevel,
    UserAgent
| sort by MinutesSinceClick asc
```
