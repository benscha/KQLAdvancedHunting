# *Suspicious Non-Interactive Sign-Ins with New IP*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1078 | Valid Accounts | https://attack.mitre.org/techniques/T1078 |
| T1078.004 | Cloud Accounts | https://attack.mitre.org/techniques/T1078/004 |

#### Description

This detection query identifies anomalous non-interactive Microsoft Entra ID sign-ins by analyzing automated session data and cross-referencing it with historical user baselines. It targets non-interactive sign-ins that utilize suspicious tools (such as Python, PowerShell, or curl) or exhibit unusual browser behavior within the same correlation ID. The query then evaluates these sessions against a 30-day historical IP profile for each user, prioritizing alerts where a suspicious user-agent signature coincides with an entirely new or rare IP address.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let lookback	 = 1h;
let historyStart = ago(29d);
let historyEnd   = ago(lookback);
let SuspiciousSessions =
	AADNonInteractiveUserSignInLogs
	| where TimeGenerated >= ago(lookback)
	| where ResultType == 0
	| where isnotempty(UserAgent)
	| where isnotempty(CorrelationId)
	| extend UAType = case(
		UserAgent has "MSAL",									   "MSAL-Client",
		UserAgent has "Windows-AzureAD-Authentication-Provider",	"Windows-Auth-Provider",
		UserAgent has "Dalvik",									 "Android-App",
		UserAgent has "CFNetwork",								  "iOS-App",
		UserAgent has "Microsoft Authenticator",					"Authenticator-App",
		UserAgent has_any ("python", "curl", "powershell",
						   "okhttp", "axios", "go-http",
						   "java/", "requests", "wget"),			"Suspicious-Tool",
		UserAgent startswith "Mozilla",							 "Browser",
																	"Unknown"
	  )
	| extend UANormalized = replace_regex(UserAgent, @'\d+\.\d+\.\d+\.\d+', "x.x.x.x")
	| summarize
		UATypes	 = make_set(UAType, 20),
		UAList	  = make_set(UANormalized, 20),
		IPList	  = make_set(IPAddress, 20),
		AppList	 = make_set(AppDisplayName, 10),
		FirstSeen   = min(TimeGenerated),
		LastSeen	= max(TimeGenerated),
		SignInCount = count()
		by UserPrincipalName, CorrelationId
	| extend UACount		  = array_length(UAList)
	| extend IPCount		  = array_length(IPList)
	| extend HasSuspiciousTool = UATypes has "Suspicious-Tool"
	| extend HasBrowser		= UATypes has "Browser"
	| extend IsUASuspicious	= case(
		HasSuspiciousTool == true,	  true,
		HasBrowser and UACount >= 2,	true,
										false
	  )
	| where IsUASuspicious == true
	| take 500;
let SuspiciousUsers = SuspiciousSessions
	| distinct UserPrincipalName;
let HistoricalIPs =
	EntraIdSignInEvents
	| where Timestamp >= historyStart and Timestamp < historyEnd
	| where ErrorCode == 0
	| summarize hint.shufflekey=AccountUpn
		IPSeenCount   = count(),
		HistoricalIPs = make_set(IPAddress, 200)
		by AccountUpn, IPAddress
	| where AccountUpn in (SuspiciousUsers);
SuspiciousSessions
| mv-expand CurrentIP = IPList to typeof(string)
| join hint.strategy=broadcast kind=leftouter (HistoricalIPs)
	on $left.UserPrincipalName == $right.AccountUpn
	and $left.CurrentIP == $right.IPAddress
| extend IPSeenBefore = isnotempty(IPSeenCount)
| extend IPSeenCount  = coalesce(todouble(IPSeenCount), 0.0)
| summarize
	UATypes		   = any(UATypes),
	UACount		   = any(UACount),
	UAList			= any(UAList),
	IPList			= any(IPList),
	IPCount		   = any(IPCount),
	AppList		   = any(AppList),
	FirstSeen		 = any(FirstSeen),
	LastSeen		  = any(LastSeen),
	SignInCount	   = any(SignInCount),
	HasSuspiciousTool = any(HasSuspiciousTool),
	HasBrowser		= any(HasBrowser),
	IsUASuspicious	= any(IsUASuspicious),
	NewIPCount		= countif(IPSeenBefore == false),
	MinIPSeenCount	= min(IPSeenCount),
	MaxIPSeenCount	= max(IPSeenCount)
	by UserPrincipalName, CorrelationId
| extend WorstIPRisk = case(
	NewIPCount > 0,		 "High - new IP for this User",
	MinIPSeenCount < 3,	 "Medium - rare IP",
							"Low - knwon IP"
  )
| extend Severity = case(
	HasSuspiciousTool and NewIPCount > 0,			   "High",
	IsUASuspicious and WorstIPRisk startswith "High",   "High",
	IsUASuspicious and WorstIPRisk startswith "Medium", "Medium",
														"Low"
  )
| where Severity in ("High", "Medium")
| project
	Severity,
	UserPrincipalName,
	CorrelationId,
	UACount,
	UATypes,
	UAList,
	HasSuspiciousTool,
	NewIPCount,
	IPCount,
	IPList,
	MinIPSeenCount,
	MaxIPSeenCount,
	WorstIPRisk,
	AppList,
	FirstSeen,
	LastSeen,
	SignInCount
| sort by Severity asc, NewIPCount desc
```
