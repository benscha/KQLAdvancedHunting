# *LDAP Cross-Domain Enumeration*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1087.002 | Domain Account | https://attack.mitre.org/techniques/T1087/002/ |
| T1069.002 | Domain Groups | https://attack.mitre.org/techniques/T1069/002/ |

#### Description

This rule detects a single device performing LDAP queries for user objects across multiple domains within a short timeframe. This behavior can indicate reconnaissance activity by an attacker attempting to map the Active Directory environment.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let LookbackWindow = 2h;
IdentityQueryEvents
| where TimeGenerated >= ago(LookbackWindow)
| where ActionType == "LDAP query"
| where Application == "Active Directory"
| extend AF = parse_json(AdditionalFields)
| extend
	BaseObject   = tostring(AF.BaseObject),
	SearchFilter = tostring(AF.SearchFilter),
	FromDevice   = tostring(AF["FROM.DEVICE"]),
	SourceOS     = tostring(AF.SourceComputerOperatingSystem)
| where BaseObject matches regex @"^DC="   // Root-Domain
| where SearchFilter has "(objectClass=user)"
| extend Domain = extract(@"DC=([^,]+),DC=ds", 1, BaseObject)  
| where isnotempty(Domain)
| summarize
	Domains      = make_set(Domain),
	DomainCount  = dcount(Domain),
	QueryCount   = count(),
	BaseObjects  = make_set(BaseObject, 5),
	FirstSeen    = min(TimeGenerated),
	LastSeen     = max(TimeGenerated)
	by FromDevice, IPAddress, SourceOS
| where DomainCount >= 2   // at least two domains
| extend TimespanMin = datetime_diff("minute", LastSeen, FirstSeen)
| project
	FirstSeen,
	LastSeen,
	TimespanMin,
	FromDevice,
	IPAddress,
	SourceOS,
	DomainCount,
	Domains,
	QueryCount,
	BaseObjects
| order by DomainCount desc, QueryCount desc
```
