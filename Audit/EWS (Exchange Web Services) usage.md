# *EWS (Exchange Web Services) usage*

## Query Information

#### Description
With Microsoft completely disabling Exchange Web Services (EWS) in Exchange Online on October 1, 2026, organizations must identify and migrate all remaining applications, scripts, and legacy integrations using EWS endpoints.

This KQL query provides a detailed inventory of active EWS traffic by aggregating telemetry from CloudAppEvents, resolving OAuth Application IDs to human-readable names, and flagging traffic hidden behind generic resource identifiers or legacy authentication.

```powershell
# Add specific AppIDs to the AllowList
Set-OrganizationConfig -EWSAllowedAppIDs @{Add="<App-ID-GUID-1>", "<App-ID-GUID-2>"}
```

#### Key Features:
The query offers cross-platform portability across both Microsoft Defender XDR Advanced Hunting and Microsoft Sentinel. It uses a multi-tiered app identity resolution process, automatically matching AppIDs to application names using a fallback chain across App Governance (OAuthAppInfo), Service Principal sign-in logs (AADSpnSignInEventsBeta or AADServicePrincipalSignInLogs), and a built-in list of Microsoft first-party apps.

To prevent distinct clients from merging into a single bucket, the logic dynamically groups traffic by User-Agent strings whenever generic Exchange resource IDs or missing AppIDs are encountered. It also generates automated risk assessments for each entry, categorizing them as migration allowlist candidates, limited-usage apps requiring owner outreach, or internal service traffic requiring manual IP review. Key metrics such as total API call volume, unique user count, sample UPNs, client versions, process names, source IP addresses, and first or last seen timestamps are automatically summarized.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References

## Defender XDR
```KQL
// EWS usage inventory for Exchange Online
let Timeframe = 30d;
let GenericExoAppId = "00000002-0000-0ff1-ce00-000000000000";
// Microsoft first-party apps - not covered by OAuthAppInfo
let FirstPartyApps = datatable(AppId:string, FirstPartyName:string)
[
	"00000002-0000-0ff1-ce00-000000000000",	"Office 365 Exchange Online (generic resource)",
	"d3590ed6-52b3-4102-aeff-aad2292ab01c",	"Microsoft Office",
	"27922004-5251-4030-b22d-91ecd9a37ea4",	"Outlook Mobile",
	"f8d98a96-0999-43f5-8af3-69971c7bb423",	"Apple Internet Accounts (Apple Mail for Mac)"
];
// Primary lookup: app governance inventory - requires app governance enabled
let AppInventory =
	union isfuzzy=true
		(datatable(AppId:string, InventoryName:string, ServicePrincipalId:string)[]),
		(OAuthAppInfo
			| summarize arg_max(Timestamp, AppName, ServicePrincipalId) by AppId = tolower(OAuthAppId)
			| project AppId, InventoryName = AppName, ServicePrincipalId)
	| summarize
		InventoryName		= take_any(InventoryName),
		ServicePrincipalId	= take_any(ServicePrincipalId)
		by AppId
	;
// Secondary lookup: service principal sign-ins - table name differs per environment
let SpnNames =
	union isfuzzy=true
		(datatable(AppId:string, SpnName:string)[]),
		(AADSpnSignInEventsBeta			// Defender XDR
			| where Timestamp > ago(Timeframe)
			| where isnotempty(ApplicationId) and isnotempty(Application)
			| project AppId = tolower(ApplicationId), SpnName = Application),
		(AADServicePrincipalSignInLogs		// Sentinel
			| where TimeGenerated > ago(Timeframe)
			| where isnotempty(AppId) and isnotempty(ServicePrincipalName)
			| project AppId = tolower(AppId), SpnName = ServicePrincipalName)
	| summarize SpnName = take_any(SpnName) by AppId
	;
CloudAppEvents
| where Timestamp > ago(Timeframe)
| where Application == "Microsoft Exchange Online"
| extend ClientInfo = tostring(RawEventData.ClientInfoString)
| where ClientInfo startswith "Client=WebServices"
| extend
	AppId		= tolower(coalesce(OAuthAppId, tostring(RawEventData.AppId))),
	ClientUserAgent	= extract(@"UserAgent=([^;]+)", 1, ClientInfo),
	ClientProcess	= extract(@"Client=WebServices;([^;]+)", 1, ClientInfo),
	ClientVersion	= extract(@"Version=([^;]+)", 1, ClientInfo),
	LogonType	= tostring(RawEventData.LogonType),
	ExternalAccess	= tostring(RawEventData.ExternalAccess)
// Identity fallback chain - normalized Account* columns are often empty here
| extend UserKey = tolower(coalesce(
	tostring(RawEventData.UserId),
	tostring(RawEventData.MailboxOwnerUPN),
	AccountObjectId,
	AccountDisplayName))
| extend UserKey = iff(UserKey in ("", "n/a", "not available"), "", UserKey)
// Split unresolved rows by user agent so distinct clients don't merge into one row
| extend ClientKey = iff(isempty(AppId) or AppId == GenericExoAppId, ClientUserAgent, "")
| summarize
	Calls			= count(),
	Users			= dcountif(UserKey, isnotempty(UserKey), 4),
	UnattributedCalls	= countif(isempty(UserKey)),
	SampleUsers		= make_set_if(UserKey, isnotempty(UserKey), 15),
	UserAgents		= make_set(ClientUserAgent, 10),
	Processes		= make_set(ClientProcess, 10),
	Versions		= make_set(ClientVersion, 5),
	Actions			= make_set(ActionType, 15),
	SourceIPs		= make_set(IPAddress, 20),
	LogonTypes		= make_set(LogonType, 5),
	ExternalFlags		= make_set(ExternalAccess, 3),
	FirstSeen		= min(Timestamp),
	LastSeen		= max(Timestamp)
	by AppId, ClientKey
| lookup kind=leftouter AppInventory on AppId
| lookup kind=leftouter SpnNames on AppId
| lookup kind=leftouter FirstPartyApps on AppId
| extend
	ResolvedName	= coalesce(InventoryName, SpnName, FirstPartyName),
	Category	= case(
		isempty(AppId),			"A: no AppId - legacy auth or internal service",
		AppId == GenericExoAppId,	"B: generic EXO resource id - client hidden",
						"C: real AppId")
| extend
	AppName		= case(
		isnotempty(ResolvedName) and isempty(ClientKey),	ResolvedName,
		isnotempty(ClientKey),					strcat("Unresolved - UA: ", ClientKey),
									"Unresolved - no AppId, no user agent"),
	NameSource	= case(
		isnotempty(InventoryName),	"App governance",
		isnotempty(SpnName),		"SPN sign-in",
		isnotempty(FirstPartyName),	"Static list",
						"None - check user agent"),
	Assessment	= case(
		Category startswith "A",	"Not attributable - check source IPs for internal service traffic",
		Category startswith "B",	"Client hidden behind resource id - correlate with sign-in logs",
		UnattributedCalls > Calls / 2,	"User count unreliable - mostly unattributed",
		Users >= 50,			"Broad usage - allow list candidate",
		Users > 0,			"Limited usage - verify owner",
						"Review manually")
| project
	AppName,
	AppId,
	Category,
	Users,
	Calls,
	Assessment,
	NameSource,
	UnattributedCalls,
	UserAgents,
	Processes,
	Versions,
	Actions,
	SourceIPs,
	LogonTypes,
	ExternalFlags,
	SampleUsers,
	ServicePrincipalId,
	FirstSeen,
	LastSeen
| order by Users desc, Calls desc
```
