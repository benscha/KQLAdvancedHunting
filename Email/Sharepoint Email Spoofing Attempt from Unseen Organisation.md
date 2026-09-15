# *Sharepoint Email Spoofing Attempt from Unseen Organisation*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566| Phishing | https://attack.mitre.org/tactics/T1566/ |


#### Description
This query detects high-volume inbound email campaigns where the sender domain has no history in the last 30 days, the email subjects contain the organization's name, and the messages mimic internal communications while appearing to originate from a spoofed 'no-reply@sharepointonline.com' address by extracting the actual sender from the Cc field. It effectively identifies potential spear-phishing campaigns utilizing domain impersonation.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References

## Defender XDR
```KQL
// Edit YOUR OrgName
let OrgName = "myORG";
let badSPSubjects = EmailEvents
| where TimeGenerated >ago(4h)
| where SenderFromAddress == "no-reply@sharepointonline.com"
| where Subject has (OrgName)
| summarize count() by Subject
// adjust this value to the size of your ORG
| where count_ > 30;
let SenderInfos = EmailEvents
| where Subject in (badSPSubjects)
| extend OrigSenderFromAddress = extract(@"<([^>]+)>", 1, tostring(Cc))
| extend OrigSenderFromDomain = tostring(split(OrigSenderFromAddress, "@")[1])
| distinct OrigSenderFromAddress, OrigSenderFromDomain, Subject;
let SenderHistory = EmailEvents
| where Timestamp > ago(30d)
| summarize HistoryCount = count() by SenderFromDomain;
let filteredDomains = SenderInfos
| join kind=leftouter SenderHistory on $left.OrigSenderFromDomain == $right.SenderFromDomain
| where isnull(HistoryCount) or HistoryCount == 0
| project OrigSenderFromDomain;
EmailEvents
| where EmailDirection == "Inbound" and DeliveryAction != "Junked"
| where Subject in (badSPSubjects)
| extend OrigSenderFromAddress = extract(@"<([^>]+)>", 1, tostring(Cc))
| extend OrigSenderFromDomain = tostring(split(OrigSenderFromAddress, "@")[1])
| where OrigSenderFromDomain in (filteredDomains)
```

Second Detection Option
```KQL
let knownOrgs = EmailEvents
| where TimeGenerated between (ago(30d) .. ago(1d))
| where SenderFromAddress == "no-reply@sharepointonline.com"
| where InternetMessageId startswith "<Share"
| extend OrigSenderFromAddress = extract(@"<([^>]+)>", 1, tostring(Cc))
| extend OrigSenderFromDomain = tostring(split(OrigSenderFromAddress, "@")[1])
| summarize count() by OrigSenderFromDomain;
let OwnMailDomains = IdentityInfo
| where isnotempty( CompanyName)
| where TimeGenerated > ago(14d)
| summarize arg_max(TimeGenerated, *) by AccountUpn
| extend UserDomain = tolower(tostring(split(AccountUpn, "@")[1]))
| where isnotempty( UserDomain) and UserDomain !endswith "onmicrosoft.com"
| distinct UserDomain;
EmailEvents
| where TimeGenerated >ago(8h)
| where EmailDirection == "Inbound" and DeliveryAction != "Junked"
| where RecipientDomain in~ (OwnMailDomains)
| where SenderFromAddress == "no-reply@sharepointonline.com"
| where InternetMessageId startswith "<Share"
| extend OrigSenderFromAddress = extract(@"<([^>]+)>", 1, tostring(Cc))
| extend OrigSenderFromDomain = tostring(split(OrigSenderFromAddress, "@")[1])
| where not(OrigSenderFromDomain in~ (knownOrgs))
```
