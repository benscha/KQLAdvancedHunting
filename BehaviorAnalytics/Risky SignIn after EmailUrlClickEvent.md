# *Risky SignIn after EmailUrlClickEvent*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566 | Phishing | https://attack.mitre.org/techniques/T1566/ |
| TA001 | Initial Access | https://attack.mitre.org/tactics/TA0001/ |

#### Description
This rule detects a highly suspicious sequence of events: a user clicking on a URL (potentially a phishing link) followed by a risky sign-in attempt to Azure AD from an IP address outside the organization's defined range. The rule specifically looks for sign-ins with a high-risk level (>= 50) that occur after a URL click event, suggesting a potential compromise initiated by a phishing attack.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- 

## Defender XDR
```KQL
let loopback = 1h;
//Add your IPRange to minimize the Results
let OwnIPRange = "147.86.";
let UserClicks = UrlClickEvents
| where Timestamp > ago(loopback)
| where IPAddress !startswith (OwnIPRange)
| project TimestampUrlClick=Timestamp, AccountUpn;
AADSignInEventsBeta
| where isnotempty(RiskEventTypes) and isnotempty(RiskLevelDuringSignIn) 
| where ErrorCode == 0 
| join kind=inner UserClicks on AccountUpn
| where RiskLevelDuringSignIn >= 50
| where Timestamp > TimestampUrlClick
```
