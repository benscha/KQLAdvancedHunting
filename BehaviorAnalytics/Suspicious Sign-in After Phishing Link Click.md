# *Suspicious Sign-in After Phishing Link Click*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566 | Phishing | https://attack.mitre.org/techniques/T1566 |

#### Description

This query detects suspicious sign-in activity from a user who has recently clicked on a phishing link. It correlates email click events with sign-in logs, identifying sign-ins from new or infrequent IP addresses after a user has interacted with a suspicious email. The rule uses configurable parameters for sender email addresses, sender domains, and subject keywords to identify phishing emails.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
// Parameter
let CampaignStartUtc = datetime(2026-01-13T00:00:00Z);
let LookbackHistory = 29d;
let HistoryStart = CampaignStartUtc - LookbackHistory;
// Filter options - populate these as needed
let SenderEmailAddresses = dynamic([]);  // e.g., ["phishing@evil.com", "fake@badactor.net"]
let SenderDomains = dynamic([]);         // e.g., ["evil.com", "badactor.net"]
let SubjectKeywords = dynamic([          
    "bring me some beers",
    "craft beer please",
    "i prefer a juicy New England IPA ;-)"
]);
// Use and Logic for SenderEmailAddresses, SenderDomains and SubjectKeywords
let UseAndLogic = false;  // true = ALL criteria must match, false = AT LEAST ONE must match
let ExcludedApps = dynamic(["TestAppTEST1", "TestAppTEST2"]);
// Affected Users
let PhishClicks = materialize(
    EmailEvents
    | where TimeGenerated >= CampaignStartUtc
    | extend 
        // We check if a filter is active (not empty)
        EmailFilterActive = array_length(SenderEmailAddresses) > 0,
        DomainFilterActive = array_length(SenderDomains) > 0,
        SubjectFilterActive = array_length(SubjectKeywords) > 0
    | extend 
        // Actual matches
        EmailMatches = SenderFromAddress has_any (SenderEmailAddresses),
        DomainMatches = SenderFromDomain has_any (SenderDomains),
        SubjectMatches = Subject has_any (SubjectKeywords)
    | where 
        (UseAndLogic == true and 
            (not(EmailFilterActive) or EmailMatches) and 
            (not(DomainFilterActive) or DomainMatches) and 
            (not(SubjectFilterActive) or SubjectMatches)
        )
        or 
        (UseAndLogic == false and 
            (
                // Logic: If multiple filters are provided, they must ALL match (Targeted Search)
                // If only one is provided, only that one must match.
                (not(EmailFilterActive) or EmailMatches) and 
                (not(DomainFilterActive) or DomainMatches) and 
                (not(SubjectFilterActive) or SubjectMatches)
            )
        )
    | project NetworkMessageId, Subject, SenderFromAddress, SenderFromDomain, RecipientEmailAddress
    | join kind=inner (
        UrlClickEvents 
        | where TimeGenerated >= CampaignStartUtc
        | project NetworkMessageId, ClickTime=TimeGenerated, Url, AccountUpn
    ) on NetworkMessageId
    | extend TargetUser = coalesce(AccountUpn, RecipientEmailAddress)
    | where isnotempty(TargetUser)
    | summarize 
        MinClickTime = min(ClickTime), 
        ClickedUrl = any(Url),
        Sender = any(SenderFromAddress),
        SenderDomain = any(SenderFromDomain)  
        by TargetUser, Subject
);
// Historical IPs
let HistoricalIPs = 
    SigninLogs
    | where TimeGenerated between (HistoryStart .. CampaignStartUtc)
    | where ResultType == 0
    | join kind=inner hint.strategy=broadcast (
        PhishClicks | project UserPrincipalName = TargetUser | distinct UserPrincipalName
    ) on UserPrincipalName
    | summarize IPSeenCount = count() by UserPrincipalName, IPAddress;
// Suspicious Sign-ins
SigninLogs
| where TimeGenerated >= CampaignStartUtc
| where ResultType == 0 
| where AppDisplayName !in (ExcludedApps)
| join kind=inner hint.strategy=broadcast PhishClicks on $left.UserPrincipalName == $right.TargetUser
| where TimeGenerated >= MinClickTime
| join kind=leftouter hint.strategy=broadcast HistoricalIPs on UserPrincipalName, IPAddress
| extend IPRiskClassification = case(
    isempty(IPSeenCount), "High Risk - New IP",
    IPSeenCount < 3,      "Medium Risk - Infrequent IP",
    "Low Risk"
)
| where IPRiskClassification != "Low Risk"
// Final Aggregation and Reporting
| summarize 
    FirstSignIn       = min(TimeGenerated),
    SignInCountBefore       = count(),
    AccessedApps      = make_set(AppDisplayName, 100),
    City              = any(tostring(LocationDetails.city)),
    Country           = any(tostring(LocationDetails.countryOrRegion)),
    PhishSubject      = any(Subject),
    PhishUrl          = any(ClickedUrl),
    PhishSender       = any(Sender),
    ClickTime         = any(MinClickTime)
    by TargetUser, IPAddress, IPRiskClassification
| project TargetUser, IPAddress, Country, City, IPRiskClassification, FirstSignIn, ClickTime, SignInCountBefore, AccessedApps, PhishSubject, PhishSender
// Filter for rarely used IPs. to reduce only to NEW used IPAdresses Filter to <1
| where SignInCountBefore <2
```
