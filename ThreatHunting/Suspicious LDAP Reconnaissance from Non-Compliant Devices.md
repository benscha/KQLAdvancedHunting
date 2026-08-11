# *Suspicious LDAP Reconnaissance from Non-Compliant Devices*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1087.002 | Account Discovery: Domain Account | https://attack.mitre.org/techniques/T1087/002/ |
| T1069.002 | Permission Groups Discovery: Domain Groups | https://attack.mitre.org/techniques/T1069/002/ |
| T1018 | Remote System Discovery | https://attack.mitre.org/techniques/T1018/ |


#### Description
This detection surfaces Active Directory reconnaissance originating from endpoints that Intune currently reports as non-compliant or as carrying an active mobile threat defense risk level. It correlates the latest per-device compliance snapshot from IntuneDeviceComplianceOrg with LDAP query activity in IdentityQueryEvents from Microsoft Defender for Identity, normalizing hostnames so that FQDN and NetBIOS variants match reliably.

Rather than flagging every mention of a directory attribute, the query scores each LDAP query by signal strength, weighting access to highly sensitive attributes such as LAPS passwords, security descriptors and delegation settings far above attributes that appear routinely in normal domain operations. It additionally looks for LDAP matching rules and userAccountControl bitmask filters that are characteristic of offensive tooling like BloodHound, PowerView and Rubeus. Results are aggregated per device, account and time bin, so a single high confidence indicator raises an alert on its own while low weight activity only triggers once it reaches the volume and diversity typical of bulk enumeration. Each result carries a verdict describing why it fired, together with sample queries, source addresses and the targeted domain controllers for triage.


#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References

## Defender XDR
```KQL
let Lookback		= 1d;
let BinSize		= 15m;
let RiskyDevices = materialize(
	IntuneDeviceComplianceOrg
	| where TimeGenerated > ago(7d)
	| summarize arg_max(TimeGenerated, DeviceHealthThreatLevel, ComplianceState) by DeviceName
	| where DeviceHealthThreatLevel in~ ("Low", "Medium", "High")
		or ComplianceState =~ "Noncompliant"
	| extend DeviceKey = tolower(tostring(split(DeviceName, ".")[0]))
	| distinct DeviceKey, DeviceHealthThreatLevel, ComplianceState
);
// Attributes split by signal strength instead of a flat has_any
let RxHigh	= @"ms-mcs-admpwd|mslaps-(encrypted)?password|ntsecuritydescriptor|msds-allowedtodelegateto|msds-keycredentiallink|sidhistory|unixuserpassword";
let RxMed	= @"serviceprincipalname|admincount|msds-managedpassword|gplink|scriptpath";
let RxLow	= @"useraccountcontrol|memberof|member|primarygroupid|grouptype";
// LDAP matching rules and bitmask filters, almost exclusively seen from offensive tooling
let RxTool	= @"1\.2\.840\.113556\.1\.4\.1941|1\.2\.840\.113556\.1\.4\.803:=(4194304|524288|16777216|8192)";
IdentityQueryEvents
| where TimeGenerated > ago(Lookback)
| where ActionType == "LDAP query"
| where isnotempty(Query) and isnotempty(DeviceName)
| where AccountName !endswith "$"				// Computer accounts need their own baseline
| extend DeviceKey = tolower(tostring(split(DeviceName, ".")[0]))
| lookup kind=inner RiskyDevices on DeviceKey
| extend q = tolower(Query)
| extend
	ToolHit	= extract(RxTool, 0, q),
	Score	= iff(q matches regex RxHigh, 5, 0)
		+ iff(q matches regex RxMed,  2, 0)
		+ iff(q matches regex RxLow,  1, 0)
		+ iff(q matches regex RxTool, 5, 0)
		+ iff(q contains "objectcategory=person" and q contains "(&", 1, 0)
| where Score > 0
| summarize
	Events		= count(),
	DistinctQueries	= dcount(Query),
	Targets		= dcount(QueryTarget),
	MaxScore	= max(Score),
	TotalScore	= sum(Score),
	ToolIndicators	= make_set_if(ToolHit, isnotempty(ToolHit), 10),
	SampleQueries	= make_set(substring(Query, 0, 200), 8),
	IPs		= make_set(IPAddress, 5),
	TargetDCs	= make_set(DestinationDeviceName, 5),
	FirstSeen	= min(TimeGenerated),
	LastSeen	= max(TimeGenerated)
	by bin(TimeGenerated, BinSize), DeviceKey, AccountUpn, AccountDisplayName, DeviceHealthThreatLevel, ComplianceState
// Two separate triggers: single high confidence hit OR bulk enumeration
| where MaxScore >= 5 or (TotalScore >= 15 and DistinctQueries >= 20)
| extend Verdict = case(
	array_length(ToolIndicators) > 0,	"High: LDAP matching rule or bitmask filter, typical for offensive tooling",
	MaxScore >= 5,				        "High: access to highly sensitive AD attributes (LAPS/ACL/delegation)",
	DistinctQueries >= 50,			    "Medium: broad AD enumeration in a short time window",
						                "Low: elevated LDAP activity, review context")
| order by MaxScore desc, DistinctQueries desc
```
