# *Privileged Account Authentication Security Posture Audit*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1078.004  | Cloud Accounts | https://attack.mitre.org/techniques/T1078/004/ |


#### Description
This rule audits the authentication posture of highly privileged Entra ID (Azure AD) accounts by analyzing their sign-in activity over the past 30 days. It identifies privileged users and assesses their authentication security by tracking multi-factor authentication (MFA) usage, detecting password-only sign-ins, flagging accounts with limited authentication methods, and identifying inactive privileged accounts. This is intended for risk assessment and identifying potential gaps in MFA enforcement or account hygiene.
 
#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References

## Defender XDR
```KQL
let Lookback = 30d;
let PrivilegedRoles = dynamic([
// ===== ENTRA TIER 0 (Critical – Tenant-Control) =====
	"Global Administrator",
	"Privileged Role Administrator",
	"Privileged Authentication Administrator",
	"Security Administrator",
	"Conditional Access Administrator",
	"Application Administrator",
	"Cloud Application Administrator",
	"Hybrid Identity Administrator",
	"Partner Tier2 Support",
// ===== ENTRA TIER 1 (High – Service-Control/ Writepermission) =====
	"Authentication Administrator",
	"Authentication Policy Administrator",
	"Authentication Extensibility Administrator",
	"User Administrator",
	"Helpdesk Administrator",
	"Password Administrator",
	"Directory Writers",
	"Directory Synchronization Accounts",
	"Domain Name Administrator",
	"External Identity Provider Administrator",
	"Lifecycle Workflows Administrator",
	"Groups Administrator",
	"Identity Governance Administrator",
	"Exchange Administrator",
	"SharePoint Administrator",
	"Teams Administrator",
	"Teams Telephony Administrator",
	"Skype for Business Administrator",
	"Intune Administrator",
	"Compliance Administrator",
	"Security Operator",
	"Power Platform Administrator",
	"Dynamics 365 Administrator",
	"AI Administrator",
	"Global Secure Access Administrator",
	"Attribute Assignment Administrator",
	"Attribute Provisioning Administrator",
	"B2C IEF Keyset Administrator",
	"Cloud App Security Administrator",
	"External ID User Flow Administrator",
	"Partner Tier1 Support",
	"Windows 365 Administrator",
	"Microsoft 365 Backup Administrator",
	"Microsoft 365 Migration Administrator",
	"Yammer Administrator",
	"Knowledge Administrator",
	"Billing Administrator",
// ===== ENTRA TIER 2 (Medium – Read-only / restricted) =====
	"Global Reader",
	"Security Reader",
	"Attribute Provisioning Reader",
	"Application Developer",
	"Cloud Device Administrator",
	"Azure AD Joined Device Local Administrator"
]);
let PrivilegedUsers =
	IdentityInfo
	| where TimeGenerated >= ago(Lookback)
	| where AssignedRoles has_any (PrivilegedRoles)
	| summarize
		AssignedRoles  = make_set(AssignedRoles),
		Department	 = take_any(Department),
		JobTitle	   = take_any(JobTitle),
		AccountEnabled = take_any(IsAccountEnabled)
		by AccountUpn;
// Count per user + method
let AuthMethodCounts =
	SigninLogs
	| where TimeGenerated >= ago(Lookback)
	| where ResultType == 0
	| extend AuthDetails = parse_json(AuthenticationDetails)
	| extend AuthMethod = tostring(AuthDetails[0].authenticationMethod)
	| extend AuthMethodNorm = case(
		AuthMethod == "Password",							"🔑 Password",
		AuthMethod == "Mobile app notification",			"📱 Authenticator (Push)",
		AuthMethod == "Mobile app OTP",						"📱 Authenticator (OTP)",
		AuthMethod == "SMS",								"💬 SMS OTP",
		AuthMethod == "FIDO2 security key",					"🔐 FIDO2 / Passkey",
		AuthMethod == "Windows Hello for Business",			"🖥️ Windows Hello",
		AuthMethod == "Certificate-based authentication",	"📜 Certificate (CBA)",
		AuthMethod == "Voice call",							"📞 Phone Call",
		AuthMethod == "Temporary Access Pass",				"⏳ Temporary Access Pass",
		AuthMethod == "Previously satisfied",				"✅ SSO (Previous Session)",
		isempty(AuthMethod),								"❓ Unknown",
		AuthMethod
	)
	| summarize MethodCount = count() by UserPrincipalName, AuthMethodNorm;
// Build bag per user
let AuthMethodBags =
	AuthMethodCounts
	| summarize AuthMethodBreakdown = make_bag(bag_pack(AuthMethodNorm, MethodCount))
		by UserPrincipalName;
// Aggregate remaining metrics
let AuthEvents =
	SigninLogs
	| where TimeGenerated >= ago(Lookback)
	| where ResultType == 0
	| extend AuthDetails = parse_json(AuthenticationDetails)
	| extend AuthMethod = tostring(AuthDetails[0].authenticationMethod)
	| summarize
		TotalSignins		= count(),
		UniqueAuthMethods	= dcount(AuthMethod),
		LastSignin			= max(TimeGenerated),
		UniqueIPs			= dcount(IPAddress),
		UniqueApps			= dcount(AppDisplayName),
		MFASuccess			= countif(AuthenticationRequirement == "multiFactorAuthentication"),
		PasswordOnlySignins	= countif(AuthMethod == "Password" and AuthenticationRequirement == "singleFactorAuthentication")
		by UserPrincipalName;
// Combine data
PrivilegedUsers
| join kind=leftouter AuthEvents
	on $left.AccountUpn == $right.UserPrincipalName
| join kind=leftouter AuthMethodBags
	on $left.AccountUpn == $right.UserPrincipalName
| project
	User				= AccountUpn,
	Roles				= AssignedRoles,
	AccountActive		= AccountEnabled,
	SigninCount			= coalesce(TotalSignins, 0),
	UsedMethodsCount	= coalesce(UniqueAuthMethods, 0),
	AuthMethodsDetail	= AuthMethodBreakdown,
	LastSignin			= LastSignin,
	UniqueIPs			= coalesce(UniqueIPs, 0),
	UniqueApps			= coalesce(UniqueApps, 0),
	MFASignins			= coalesce(MFASuccess, 0),
	PasswordOnlySignins	= coalesce(PasswordOnlySignins, 0),
	RiskIndicator		= case(
		coalesce(PasswordOnlySignins, 0) > 0, "⚠️ Password-only sign-ins present",
		coalesce(TotalSignins, 0) == 0,	   "🔴 No sign-ins in 30 days",
		coalesce(UniqueAuthMethods, 0) == 1,  "🟡 Only one auth method active",
											  "🟢 OK"
	)
| where SigninCount > 0
| sort by SigninCount desc
```
