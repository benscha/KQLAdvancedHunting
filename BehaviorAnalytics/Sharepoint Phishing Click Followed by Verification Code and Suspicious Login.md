# *Sharepoint Phishing Click Followed by Verification Code and Suspicious Login*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566 | Phishing | https://attack.mitre.org/techniques/T1566 |
| T1566.002 | Spearphishing Link | https://attack.mitre.org/techniques/T1566/002 |

#### Description

This rule detects a multi-stage phishing attack where a user clicks on a suspicious SharePoint link, subsequently receives an email containing a verification code (indicating an MFA/OTP bypass attempt), and then logs in from an unusual IP address or a new device within a short timeframe. It correlates URL click events, email events, and Azure AD sign-in events to identify this specific attack chain, leveraging historical IP and device behavior for risk classification.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
// Parameters 
let LookbackHistory = 29d;
// please be aware that there is an underscore instead of a dot
let OwnSharepointDomain = "fhnw_ch"; 

// Phishing Clicks 
let PhishClicks = materialize(
    UrlClickEvents
    | where Timestamp > ago(1d)
    | where Url has_all ("sharepoint.com", "personal")
    | where Url !has (OwnSharepointDomain)
    | project UrlClickTimestamp = Timestamp, AccountUpn, Url
    | join kind=inner (
        EmailEvents
        | where Timestamp > ago(1d)
        | project EmailTimestamp = Timestamp, RecipientEmailAddress, Subject
    ) on $left.AccountUpn == $right.RecipientEmailAddress
    | where EmailTimestamp > UrlClickTimestamp
    | where Subject has_any ("Überprüfungscode", "verification code")
    | project UrlClickTimestamp, TargetUser = AccountUpn, Url
    | summarize arg_min(UrlClickTimestamp, *) by TargetUser
);
// Affected Users & Historical IPs
let AffectedUsers = materialize(
    PhishClicks 
    | project AccountUpn = TargetUser 
    | distinct AccountUpn
);
let HistoricalIPs = materialize(
    PhishClicks
    | project AccountUpn = TargetUser, UrlClickTimestamp
    | join kind=inner hint.strategy=broadcast (
        EntraIdSignInEvents
        | where Timestamp > ago(1d + LookbackHistory)
        | where ErrorCode == 0
        | where AccountUpn in (AffectedUsers)
        | project AccountUpn, IPAddress, Timestamp
    ) on AccountUpn
    | where Timestamp between ((UrlClickTimestamp - LookbackHistory) .. (UrlClickTimestamp - 1h))
    | summarize IPSeenDays = dcount(bin(Timestamp, 1d)) by AccountUpn, IPAddress
);
// Behavior Analytics 
let BehaviorData = materialize(
    BehaviorAnalytics
    | where isnotempty(UserPrincipalName)
    | where TimeGenerated > ago(7d)  // <── adjust as needed
    | where tolower(UserPrincipalName) in (AffectedUsers)
    | mv-expand ActivityInsights
    //| where ActivityInsights.["FirstTimeUserConnectedFromDevice"] == "True"
    //| where ActivityInsights.["ISPUncommonlyUsedByUser"] == "True"
    | project
        AccountUpn = tolower(UserPrincipalName),
        FirstTimeUserConnectedFromDevice = tostring(ActivityInsights.Value)
);

// Suspicious Logins after Click (within 4h)
EntraIdSignInEvents
| where Timestamp > ago(1d)
| where ErrorCode == 0
| where AccountUpn in (AffectedUsers)
| join kind=inner hint.strategy=broadcast PhishClicks
    on $left.AccountUpn == $right.TargetUser
| where Timestamp >= UrlClickTimestamp
| where Timestamp <= UrlClickTimestamp + 4h
| join kind=leftouter hint.strategy=broadcast HistoricalIPs
    on AccountUpn, IPAddress
| join kind=leftouter hint.strategy=broadcast BehaviorData
    on AccountUpn
| extend IPRiskClassification = case(
    isempty(IPSeenDays), "High Risk - New IP",
    IPSeenDays < 3,      "Medium Risk - Infrequent IP",
    "Low Risk"
)
| where IPRiskClassification != "Low Risk"
// Filter for only new devices 
| where FirstTimeUserConnectedFromDevice == "True"
```
