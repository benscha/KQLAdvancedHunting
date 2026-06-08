# *RBCD Abuse with Kerberos Logon and Optional Hash Change*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1558 | Steal or Forge Kerberos Tickets | https://attack.mitre.org/techniques/T1558/ |

#### Description
This rule detects potential abuse of Resource-Based Constrained Delegation (RBCD) by correlating three events: an Active Directory attribute modification (msDS-AllowedToActOnBehalfOfOtherIdentity), an optional password/hash change on the modifying account, and a subsequent Kerberos network logon to the target object. The rule prioritizes detections where a hash change occurred shortly before the RBCD modification, indicating a higher likelihood of a sophisticated attack like S4U2Self/U2U abuse.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- https://www.netexec.wiki/smb-protocol/authentication/delegation#rbcd-without-an-spn-u2u
- https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd#rbcd-on-spn-less-users 


## KQL

```KQL
let LookbackPeriod = 7d;
let DetectionWindow = 2h;
// RBCD Attribute Modification (msDS-AllowedToActOnBehalfOfOtherIdentity)
let RbcdModifications =
	IdentityDirectoryEvents
	| where TimeGenerated > ago(LookbackPeriod)
	| where ActionType == "AttributeUpdated"
	| extend AttributeName   = tostring(AdditionalFields.AttributeLDAPDisplayName)
	| where AttributeName == "msDS-AllowedToActOnBehalfOfOtherIdentity"
	| extend ModifierAccount = tostring(AdditionalFields.ActorAccountName)
	| extend ModifierDomain  = tostring(AdditionalFields.ActorAccountDomain)
	| extend ModifierSid	 = tostring(AdditionalFields.ActorAccountSid)
	| extend TargetObject	= tostring(AdditionalFields.TargetObjectName)
	| extend GrantedToSid	= tostring(AdditionalFields.AttributeNewValue) 
	// Filter out legitimate system/service accounts (MFA, AAD Sync, etc.)
	| where ModifierAccount !in~ ("MSOL_IdentityServiceAccount", "AzureADConnect", "ADConnect")
	| project
		TimeModification = TimeGenerated,
		TargetObject,
		ModifierAccount,
		ModifierDomain,
		ModifierSid,
		GrantedToSid;
// Password/Hash Change (U2U Fingerprint: NEWNTHASH trick)
// Attacker sets NT Hash equal to the RC4 session key of the TGT
let PasswordChanges =
	IdentityDirectoryEvents
	| where TimeGenerated > ago(LookbackPeriod)
	| where ActionType in ("UserPasswordChanged", "UserPasswordReset")
	| extend ChangedAccount = tostring(AdditionalFields.TargetObjectName)
	| extend ChangedByCaller = tostring(AdditionalFields.ActorAccountName)
	| project
		TimePasswdChange = TimeGenerated,
		ChangedAccount,
		ChangedByCaller;
// Kerberos Logons on the Target Object after the RBCD Modification
let KerberosLogons =
	IdentityLogonEvents
	| where TimeGenerated > ago(LookbackPeriod)
	| where Protocol == "Kerberos"
	| where LogonType == "Network"
	// S4U2Self/U2U typically does not generate failed logons,
	// but delegation chains might appear with an empty FailureReason or ticket errors
	| project
		TimeLogon = TimeGenerated,
		TargetDevice = DeviceName,
		LogonAccount = AccountName,
		LogonAccountSid = AccountSid,
		LogonDomain = AccountDomain,
		SrcIP = IPAddress,
		FailureReason,
		AdditionalFields;
// RBCD Mod → Hash Change → Kerberos Logon (within DetectionWindow)
RbcdModifications
| join kind=leftouter (
	PasswordChanges
) on $left.ModifierAccount == $right.ChangedAccount
| extend HashChangedBeforeRbcd = (
	isnotempty(TimePasswdChange)
	and TimePasswdChange between ((TimeModification - 30m) .. TimeModification)
)
// Correlate with Kerberos Logon on the target object after the modification
| join kind=inner (
	KerberosLogons
) on $left.TargetObject == $right.TargetDevice
| where TimeLogon between (TimeModification .. (TimeModification + DetectionWindow))
// FP Reduction: Logon from the same account as the modifier OR
// Logon from an account without an SPN (no "$" at the end = normal user → typical for U2U)
| where LogonAccount =~ ModifierAccount
	or (not(LogonAccount endswith "$") and LogonAccount !in~ ("", "-"))
// Scoring: High U2U indicator if a hash change occurred shortly before
| extend RiskScore = case(
	HashChangedBeforeRbcd == true, "High – RBCD+U2U (Hash Change Signal)",
	LogonAccount =~ ModifierAccount, "Medium – RBCD + Modifier Logon",
	"Low – RBCD + Unexpected Logon"
)
| project
	TimeModification,
	TimePasswdChange,
	TimeLogon,
	TargetObject,
	ModifierAccount,
	ModifierDomain,
	LogonAccount,
	SrcIP,
	HashChangedBeforeRbcd,
	RiskScore
| sort by TimeModification desc
```
