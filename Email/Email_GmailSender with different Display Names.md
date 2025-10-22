# *Gmail Sender with Multiple Display Names*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566| Phishing | https://attack.mitre.org/tactics/T1566/ |
| T1656 | Impersonation | https://attack.mitre.org/tactics/T1656/ |

#### Description
Detects a single Gmail sender address using multiple distinct display names within a short timeframe (1 hour). This behavior can indicate an attempt at impersonation, phishing, or spam campaigns where an attacker tries to appear as different entities from the same compromised or controlled email account.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References

## Defender XDR
```KQL
let suspiciousSender = EmailEvents
| where Timestamp > ago(1h)
| summarize 
    DistinctDisplayNames = dcount(SenderDisplayName),
    DisplayNames = make_set(SenderDisplayName)
by SenderFromAddress
| where DistinctDisplayNames > 1
| order by DistinctDisplayNames desc
| where SenderFromAddress endswith "gmail.com";
EmailEvents
| join kind=inner (
    suspiciousSender
    | project SenderFromAddress) on SenderFromAddress 
```
