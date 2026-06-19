# *Correlating LDAP Reconnaissance with Kerberoasting and Sensitive Queries*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1558.003 | Kerberoasting | https://attack.mitre.org/techniques/T1558/003/ |
| T1087.002 | Domain Account | https://attack.mitre.org/techniques/T1087/002/ |
| T1069.002 | Domain Groups | https://attack.mitre.org/techniques/T1069/002/ |
| T1018 | Remote System Discovery | https://attack.mitre.org/techniques/T1018 |

#### Description

This query detects suspicious Active Directory reconnaissance by identifying LDAP queries targeting the root domain and correlates them with additional risky behaviors such as Kerberoasting-related SPN queries and the use of sensitive LDAP filters. By combining multiple signals and applying a scoring mechanism, it highlights devices that exhibit patterns commonly associated with post-exploitation activity, helping analysts focus on high-confidence threats instead of isolated events.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
// Base: LDAP WholeSubtree on Root Domain (no OU filter)
let LookbackWindow = 2h;
let tstart = ago(LookbackWindow);
let RootDomainRecon =
	IdentityQueryEvents
	| where TimeGenerated >= tstart
	| where ActionType == "LDAP query"
	| where Application == "Active Directory"
	| extend AF = parse_json(AdditionalFields)
	| extend
		BaseObject	 = tostring(AF.BaseObject),
		SearchFilter   = tostring(AF.SearchFilter),
		FromDevice	 = tostring(AF["FROM.DEVICE"]),
		SourceOS	   = tostring(AF.SourceComputerOperatingSystem),
		SourceSid	  = tostring(AF.SourceComputerSid)
	| where BaseObject matches regex @"^DC="		  // Root domain, no OU= prefix
	| where SearchFilter has "(objectClass=user)"
	| project TimeGenerated, FromDevice, IPAddress, SourceOS, SourceSid, BaseObject, SearchFilter, ReportId;
// Lateral Movement after Recon
// Authentication to a new host within the time window
let SignalA =
	IdentityLogonEvents
	| where TimeGenerated >= tstart
	| where ActionType in ("LogonSuccess", "LogonAttempt")
	| where Protocol in ("Kerberos", "Ntlm")
	| extend FromDevice = tostring(AccountName) // Approximation; use DeviceName if available
	| summarize LateralTargets = dcount(DestinationDeviceName) by AccountSid, DeviceName
	| where LateralTargets >= 2  // at least 2 different targets
	| project DeviceName, AccountSid, LateralTargets;
// Kerberoasting — TGS requests for multiple SPNs
let SignalB =
	IdentityQueryEvents
	| where TimeGenerated >= tstart
	| where ActionType == "LDAP query"
	| extend AF = parse_json(AdditionalFields)
	| extend SearchFilter = tostring(AF.SearchFilter)
	| where SearchFilter has_any (
		"servicePrincipalName",
		"(objectClass=user)(servicePrincipalName=*)"
	)
	| extend FromDevice = tostring(parse_json(AdditionalFields)["FROM.DEVICE"])
	| summarize SpnQueryCount = count() by FromDevice
	| where SpnQueryCount >= 2
	| project FromDevice, SpnQueryCount;
// Sensitive LDAP filters
let SignalC =
	IdentityQueryEvents
	| where TimeGenerated >= tstart
	| where ActionType == "LDAP query"
	| extend AF = parse_json(AdditionalFields)
	| extend
		SearchFilter = tostring(AF.SearchFilter),
		FromDevice   = tostring(AF["FROM.DEVICE"])
	| where SearchFilter has_any (
		"adminCount=1",
		"ms-MCS-AdmPwd",		// LAPS password attribute
		"msLAPS-Password",	   // Windows LAPS (new)
		"Domain Admins",
		"memberOf",
		"ms-DS-MachineAccountQuota",
		"(objectCategory=groupPolicyContainer)"  // GPO enumeration
	)
	| summarize SensitiveFilterCount = count(), SensitiveFilters = make_set(SearchFilter, 5) by FromDevice
	| project FromDevice, SensitiveFilterCount, SensitiveFilters;
// Join + Scoring
RootDomainRecon
| summarize
	ReconCount	= count(),
	ReconBases	= make_set(BaseObject, 5),
	FirstSeen	 = min(TimeGenerated),
	LastSeen	  = max(TimeGenerated)
	by FromDevice, IPAddress, SourceOS
| join kind=leftouter SignalB on $left.FromDevice == $right.FromDevice
| join kind=leftouter SignalC on $left.FromDevice == $right.FromDevice
| extend
	ScoreRecon   = iff(ReconCount >= 1, 1, 0),
	ScoreKerb	= iff(isnotempty(SpnQueryCount), 1, 0),
	ScoreSensF   = iff(isnotempty(SensitiveFilterCount), 1, 0)
| extend TotalScore = ScoreRecon + ScoreKerb + ScoreSensF
| where TotalScore >= 2
| extend Severity = case(
	TotalScore == 3, "High",
	TotalScore == 2, "Medium",
	"Low"
)
| project
	FirstSeen,
	LastSeen,
	FromDevice,
	IPAddress,
	SourceOS,
	ReconCount,
	ReconBases,
	SpnQueryCount,
	SensitiveFilterCount,
	SensitiveFilters,
	TotalScore,
	Severity
| order by TotalScore desc, FirstSeen asc
```
