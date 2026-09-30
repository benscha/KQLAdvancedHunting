# *Mail Bombing Followed by External Teams Contact and Remote Access Execution*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566 | Phishing | https://attack.mitre.org/techniques/T1566 |
| T1204 | User Execution | https://attack.mitre.org/techniques/T1204 |
| T1219 | Remote Access Tools | https://attack.mitre.org/techniques/T1219 |
| T1059 | Command and Scripting Interpreter | https://attack.mitre.org/techniques/T1059 |
| T1105 | Ingress Tool Transfer | https://attack.mitre.org/techniques/T1105 |



#### Description

This query detects a multi stage social engineering chain in which a user is first flooded with inbound email, then contacted by an external party on Microsoft Teams, and finally executes remote access tooling or a suspicious script on the endpoint. This pattern is commonly used by intrusion sets that pose as IT support to convince the victim to start a remote session or run a command.

The first stage looks at EmailEvents for inbound messages and groups them per recipient in 15 minute bins. A bin is flagged as a mail bomb when it contains at least 100 messages from at least 20 distinct senders. The second stage uses MessageEvents to find Teams messages sent by an external domain to a recipient inside the organization, where the message arrives between the start of the flood and two hours after its end. Organization domains are derived from the recipient domains of inbound email. The third stage searches DeviceProcessEvents for the same user within four hours after the Teams contact. It matches either the launch of a known remote support tool such as Quick Assist, AnyDesk, TeamViewer or ScreenConnect, or a script interpreter started from explorer.exe that uses encoded or hidden execution, or that fetches remote content through tools like curl, certutil, bitsadmin or Invoke-WebRequest.

Results are assigned a ChainConfidence value and include the mail burst statistics, the external Teams sender, and the endpoint process details. The thresholds and follow up windows are defined as let parameters at the top and should be tuned to the mail volume of the environment. Legitimate helpdesk use of remote tools by approved external partners is a possible source of false positives and can be excluded by allowlisting.


#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let HuntLookback = 30d;
let MailBurstWindow = 15m;
let TeamsFollowupWindow = 2h;
let EndpointFollowupWindow = 4h;
let MinimumBurstMessages = 100;
let MinimumDistinctSenders = 20;
let OrgDomains = EmailEvents
    | where EmailDirection == "Inbound"
    | distinct RecipientDomain;
let MailBombs =
	EmailEvents
	| where Timestamp >= ago(HuntLookback)
	| where EmailDirection =~ "Inbound"
	| extend UserEmail = tolower(RecipientEmailAddress)
	| summarize
		FloodStart = min(Timestamp),
		FloodEnd = max(Timestamp),
		BurstMessageCount = count(),
		DistinctSenders = dcount(SenderFromAddress),
		DistinctSubjects = dcount(Subject)
		by UserEmail, FloodBin = bin(Timestamp, MailBurstWindow)
	| where BurstMessageCount >= MinimumBurstMessages
		and DistinctSenders >= MinimumDistinctSenders;
let ExternalTeamsMessages =
	MessageEvents
	| where Timestamp >= ago(HuntLookback)
    | mv-expand RecipientDetails
	| extend
		SenderEmail = tolower(SenderEmailAddress),
		RecipientEmail = tolower(parse_json(RecipientDetails.RecipientSmtpAddress))
	| extend
		SenderDomain = tolower(extract(@"@([^@]+)$", 1, SenderEmail)),
		RecipientDomain = tolower(extract(@"@([^@]+)$", 1, RecipientEmail))
	| where isnotempty(SenderDomain) and isnotempty(RecipientDomain)
	| where SenderDomain !in (OrgDomains) and RecipientDomain in (OrgDomains)
	| project
		UserEmail = RecipientEmail,
		TeamsTime = Timestamp,
		ExternalSender = SenderEmail,
		ExternalSenderDomain = SenderDomain,
		TeamsMessageId;
let MailThenTeams =
	MailBombs
	| join kind=inner ExternalTeamsMessages on UserEmail
	| where TeamsTime >= FloodStart and TeamsTime <= FloodEnd + TeamsFollowupWindow
	| summarize
		TeamsTime = min(TeamsTime),
		ExternalSender = take_any(ExternalSender),
		ExternalSenderDomain = take_any(ExternalSenderDomain),
		TeamsMessageId = take_any(TeamsMessageId)
		by UserEmail, FloodBin, FloodStart, FloodEnd, BurstMessageCount, DistinctSenders, DistinctSubjects;
let SuspiciousEndpointActivity =
	DeviceProcessEvents
	| where Timestamp >= ago(HuntLookback)
	| where isnotempty(AccountUpn)
	| extend
		UserEmail = tolower(AccountUpn),
		CommandLine = tolower(ProcessCommandLine),
		ProcessName = tolower(FileName),
		ParentName = tolower(InitiatingProcessFileName),
		GrandparentName = tolower(InitiatingProcessParentFileName)
	| extend
		LaunchedFromExplorer = ParentName == "explorer.exe" or GrandparentName == "explorer.exe",
		HasEncodedOrHiddenExecution = CommandLine matches regex @"(?i)(\s-enc(odedcommand)?\b|\s-w(indowstyle)?\s+hidden\b|frombase64string)",
		HasRemoteFetch = CommandLine matches regex @"(?i)(https?://|downloadstring|invoke-webrequest|\biwr\b|\b(curl|wget|bitsadmin|certutil)\b)",
		IsScriptOrShell = ProcessName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "wscript.exe", "cscript.exe", "curl.exe"),
		IsRemoteSupportTool = ProcessName in~ (
			"quickassist.exe", "anydesk.exe", "teamviewer.exe", "screenconnect.client.exe",
			"rustdesk.exe", "ateraagent.exe", "splashtop.exe", "bomgar-scc.exe", "logmein.exe"
		)
	| where IsRemoteSupportTool
		or (LaunchedFromExplorer and IsScriptOrShell and (HasEncodedOrHiddenExecution or HasRemoteFetch))
	| project
		UserEmail,
		EndpointTime = Timestamp,
		DeviceName,
		DeviceId,
		ProcessFileName = FileName,
		ProcessCommandLine,
		InitiatingProcessFileName,
		InitiatingProcessParentFileName,
		IsRemoteSupportTool,
		HasEncodedOrHiddenExecution,
		HasRemoteFetch;
MailThenTeams
| join kind=inner SuspiciousEndpointActivity on UserEmail
| where EndpointTime >= TeamsTime and EndpointTime <= TeamsTime + EndpointFollowupWindow
| extend ChainConfidence = case(
	IsRemoteSupportTool and (HasEncodedOrHiddenExecution or HasRemoteFetch), "High",
	IsRemoteSupportTool or (HasEncodedOrHiddenExecution and HasRemoteFetch), "High",
	"Elevated")
| project
	ChainConfidence,
	UserEmail,
	FloodStart,
	FloodEnd,
	BurstMessageCount,
	DistinctSenders,
	DistinctSubjects,
	TeamsTime,
	ExternalSender,
	ExternalSenderDomain,
	TeamsMessageId,
	EndpointTime,
	DeviceName,
	DeviceId,
	ProcessFileName,
	ProcessCommandLine,
	InitiatingProcessFileName,
	InitiatingProcessParentFileName,
	IsRemoteSupportTool,
	HasEncodedOrHiddenExecution,
	HasRemoteFetch
| order by ChainConfidence asc, FloodStart desc, EndpointTime desc
```
