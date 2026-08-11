# *Anomalous Windows Hello for Business Sign-In Without Device ID*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1556.007 | Modify Authentication Process: Hybrid Identity | https://attack.mitre.org/techniques/T566/007 |
| T1110 | Unsecured Credentials / Replay Attack | https://attack.mitre.org/techniques/T1110 |
| T1078.004 | Valid Accounts: Cloud Accounts | https://attack.mitre.org/techniques/T078/004 |
| T1539 | Steal Web Session Cookie / MFA Token Replay | https://attack.mitre.org/techniques/T1539 |

#### Description

This KQL query detects suspicious Windows Hello for Business sign-ins where the device ID is missing despite the user having a strong historical baseline of presenting one. It filters for genuine primary authentications over a thirty-day window, builds a profile of normal user behavior, and flags recent sign-ins that lack a device identifier while exhibiting novel attributes such as unfamiliar network locations, new user agents, or elevated risk levels.


#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let Lookback		= 1d;
let BaselineWindow	= 30d;
let MinBaselineEvents	= 10;			// ignore users with too little history
// Genuine primary WHfB authentications only
let WHfBSignins =
	SigninLogs
	| where TimeGenerated > ago(BaselineWindow)
	| where ResultType == 0
	| where AuthenticationDetails has "Hello"
	| where IncomingTokenType in ("none", "")	// exclude SSO follow-ups and token refreshes
	| mv-apply Detail = todynamic(AuthenticationDetails) on (
			where tobool(Detail.succeeded) == true
				and tostring(Detail.authenticationMethod) == "Windows Hello for Business"
				and tostring(Detail.authenticationStepResultDetail) !has "claim"	// drop inherited MFA claims
			| summarize StepDetail = make_set(tostring(Detail.authenticationStepResultDetail))
		)
	| extend	DeviceId	= tostring(DeviceDetail.deviceId),
			ASN		= tostring(AutonomousSystemNumber);
// Per-user baseline: how consistently does this user present a device ID?
let Baseline =
	WHfBSignins
	| where TimeGenerated between (ago(BaselineWindow) .. ago(Lookback))
	| summarize	BaselineEvents	= count(),
			DeviceIdRatio	= countif(isnotempty(DeviceId)) * 1.0 / count(),
			KnownASNs	= make_set(ASN, 200),
			KnownAgents	= make_set(UserAgent, 200)
			by UserPrincipalName;
WHfBSignins
| where TimeGenerated > ago(Lookback)
| where isempty(DeviceId)
| lookup kind=inner Baseline on UserPrincipalName
| where BaselineEvents >= MinBaselineEvents
| where DeviceIdRatio >= 0.95				// user virtually always submits a device ID
| extend	NewASN		= isnotempty(ASN) and not(set_has_element(KnownASNs, ASN)),
		NewUserAgent	= isnotempty(UserAgent) and not(set_has_element(KnownAgents, UserAgent)),
		RiskySignin	= RiskLevelDuringSignIn in ("medium", "high")
| extend Score =	toint(iff(NewASN, 40, 0))
			+ toint(iff(NewUserAgent, 30, 0))
			+ toint(iff(RiskySignin, 30, 0))
			+ toint(iff(ConditionalAccessStatus == "notApplied", 10, 0))
| where Score >= 40					// require at least one strong novelty signal
| extend Verdict = case(
		Score >= 70,	"High: WHfB primary auth without device ID from a previously unseen network or client",
		"Medium: WHfB primary auth without device ID, single novelty signal")
| project	Verdict,
		Score,
		TimeGenerated,
		UserPrincipalName,
		IPAddress,
		ASN,
		Location,
		UserAgent,
		AppDisplayName,
		ResourceDisplayName,
		ConditionalAccessStatus,
		RiskLevelDuringSignIn,
		DeviceIdRatio,
		NewASN,
		NewUserAgent,
		CorrelationId
| order by Score desc, TimeGenerated desc
```
