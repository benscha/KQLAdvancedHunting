# *Potential Display Name Spoofing*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566| Phishing | https://attack.mitre.org/tactics/T1566/ |
| T1656 | Impersonation | https://attack.mitre.org/tactics/T1656/ |

#### Description
This rule detects inbound emails that are delivered and are the first contact from a sender, where the sender's display name and email address exhibit characteristics often associated with phishing or impersonation attempts. Specifically, it flags emails where the local part of the sender's email address does not contain parts of their display name (first or last name) and has a high number of digits or a high digit-to-length ratio, suggesting a generated or obfuscated address.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References

## Defender XDR
```KQL
let OwnDomains = dynamic(["mydomain1.ch", "mydomain2.ch"]);
let ExcludedDomains = dynamic(["host.docker.internal", "bounces.google.com"]);
let ExcludedSenderFragments = dynamic(["dmarc-request", "+"]);
IdentityInfo
| project AccountDisplayName
| join EmailEvents on $left.AccountDisplayName == $right.SenderDisplayName
| where EmailDirection == "Inbound"
| where DeliveryAction == "Delivered"
| where IsFirstContact == 1
// Normalize and extract local part early for reuse
| extend LocalPart = tostring(split(tolower(SenderFromAddress), "@")[0])
| extend SenderDomain = tostring(split(tolower(SenderFromAddress), "@")[1])
// Exclude own and whitelisted domains — use SenderFromAddress-derived domain consistently
| where not(SenderDomain has_any (OwnDomains))
| where not(SenderMailFromDomain has_any (ExcludedDomains))
// Exclude addresses containing whitelisted fragments (substring match)
| where not(LocalPart has_any (ExcludedSenderFragments))
| where not(SenderFromAddress has_any (ExcludedSenderFragments))
// Name matching: check if local part contains first or last name
| extend NameParts = split(tolower(SenderDisplayName), " ")
| extend FirstName = tostring(NameParts[0]), LastName = tostring(NameParts[1])
| extend NameMatch = iff(
    (LocalPart contains FirstName and isnotempty(FirstName)) or 
    (LocalPart contains LastName and isnotempty(LastName)), 
    true, false)
// Digit ratio check
| extend DigitCount = strlen(replace_regex(LocalPart, @'[^0-9]', ''))
| extend LocalPartLength = strlen(LocalPart)
// Flag suspicious: no name match + too many digits
| where NameMatch == false 
    and (DigitCount > 4 or (DigitCount * 1.0 / LocalPartLength) > 0.4)
```
