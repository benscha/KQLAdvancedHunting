# *Multi-Stage Social Engineering Attack: Mail Bombing, External Teams Phishing, and RMM Execution*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566.003 | Phishing: Spearphishing via Service | https://attack.mitre.org/techniques/T1566/003/ |
| T1219 | Remote Access Tools | https://attack.mitre.org/techniques/T1219 |


#### Description

This rule detects a multi-stage attack chain characterized by an email flooding attack (mail bombing) against a user, followed by unsolicited external Microsoft Teams messages targeting that same user, and culminating in the execution of Remote Monitoring and Management (RMM) software on the user's device. This pattern is indicative of a social engineering campaign where attackers distract the user with a high volume of emails to hide malicious communications and subsequently pressure the user into executing unauthorized remote access tools.


#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
// Config
let Lookback           = 4h;
let MailThreshold      = 100;
let MailTimeWindow     = 30m;
let FloodToTeamsWindow = 2h;
let TeamsToRMMWindow   = 2h;
let MinSenderDomains   = 20;
let InternalDomains = dynamic([
    "domain.ch", "students.domain.ch", "other-domain.ch"
]);
// Windows RMM binaries
let RMMProcessesWin = dynamic([
    "quickassist.exe", "teamviewer.exe", "anydesk.exe",
    "screenconnect.client.exe", "screenconnect.clientservice.exe",
    "rustdesk.exe", "splashtop.exe", "logmein.exe",
    "ateraagent.exe", "syncro.exe", "supremo.exe"
]);
// macOS RMM binaries 
let RMMProcessesMac = dynamic([
    "TeamViewer", "TeamViewer_Desktop", "TeamViewer_Service",
    "AnyDesk", "RustDesk", "rustdesk",
    "ScreenConnect Client", "ConnectWiseControl", "connectwisecontrol",
    "SRStreamer", "Splashtop Streamer", "SplashtopStreamer",
    "LogMeIn", "LMIGUIAgent", "GoToAssist",
    "Supremo", "AteraAgent", "Syncro",
    "ZohoAssist", "Zoho Assist", "ZA_Connect",
    "NetSupport", "client32",
    "remoting_me2me_host", "dwagent", "dwagsvc"
]);
// Vendor tokens for path matches in /Applications
let RMMVendorsMac = dynamic([
    "TeamViewer", "AnyDesk", "RustDesk", "ScreenConnect", "ConnectWise",
    "Splashtop", "Supremo", "Zoho", "NetSupport", "LogMeIn", "GoToAssist",
    "Atera", "Syncro", "DWAgent"
]);
// Native macOS remote access tools used by attackers
let MacNativeBins = dynamic(["kickstart", "systemsetup", "screensharingd", "ARDAgent"]);
let MacNativeArgs = dynamic(["-activate", "-setremotelogin on", "-configure", "-allowAccessFor"]);
// MDM engines that legitimately run kickstart/systemsetup
let MacMgmtParents = dynamic(["jamf", "jamfAgent", "jamfManagementService", "munki", "managedsoftwareupdate", "intunemdmagent"]);
// Detect mail flooding
let MailFloodedUsers =
    EmailEvents
    | where TimeGenerated > ago(Lookback)
    | where EmailDirection == "Inbound"
    | summarize IncomingMails = count(), SenderDomains = dcount(SenderFromDomain)
        by RecipientEmailAddress, Bucket = bin(TimeGenerated, MailTimeWindow)
    | where IncomingMails >= MailThreshold
    | where SenderDomains >= MinSenderDomains
    | summarize FirstFloodTime = min(Bucket), TotalFloodMails = sum(IncomingMails),
                DistinctSenderDomains = max(SenderDomains)
        by TargetUpn = tolower(RecipientEmailAddress)
    | extend UserKeys = pack_array(TargetUpn, tostring(split(TargetUpn, "@")[0]));
// Find Teams messages sent from external addresses
let ExternalTeamsChats =
    MessageEvents
    | where TimeGenerated > ago(Lookback)
    | where isempty(GroupId)
    | where SenderType =~ "User"
    | extend SenderAddress = tolower(tostring(SenderEmailAddress))
    | extend SenderDomain  = tostring(split(SenderAddress, "@")[1])
    | where isnotempty(SenderDomain)
    | where SenderDomain !in~ (InternalDomains)
    | mv-expand Recipient = RecipientDetails
    | extend TargetUpn    = tolower(tostring(Recipient.RecipientSmtpAddress))
    | extend TargetDomain = tostring(split(TargetUpn, "@")[1])
    | where TargetDomain in~ (InternalDomains)
    | project TeamsTime = TimeGenerated, TargetUpn,
              ExternalSender = SenderAddress, ExternalSenderDomain = SenderDomain,
              IsExternalThread, IsOwnedThread, ThreadId, ThreadType,
              ChatSubject = Subject, DeliveryAction;
// OS platform enrichment
let DevicePlatform =
    DeviceInfo
    | where TimeGenerated > ago(Lookback)
    | summarize arg_max(TimeGenerated, OSPlatform) by DeviceId
    | project DeviceId, OSPlatform;
// Track RMM execution (Windows + macOS)
let RMMExecutions =
    DeviceProcessEvents
    | where TimeGenerated > ago(Lookback)
    | extend MacPathHit = FolderPath contains "/Applications/" and FolderPath has_any (RMMVendorsMac)
    | extend MacNativeHit = FileName in~ (MacNativeBins)
                            and ProcessCommandLine has_any (MacNativeArgs)
                            and InitiatingProcessFileName !in~ (MacMgmtParents)
    | where FileName in~ (RMMProcessesWin) or InitiatingProcessFileName in~ (RMMProcessesWin)
         or FileName in~ (RMMProcessesMac) or InitiatingProcessFileName in~ (RMMProcessesMac)
         or MacPathHit
         or MacNativeHit
    | extend RMMProcess = case(
          FileName in~ (RMMProcessesWin) or FileName in~ (RMMProcessesMac) or MacNativeHit, FileName,
          MacPathHit, FileName,
          InitiatingProcessFileName)
    | extend AccessMethod = case(
          MacNativeHit, "macOS native remote access enabled",
          "Third-party RMM")
    | lookup kind=leftouter DevicePlatform on DeviceId
    | extend UserKey = tolower(iff(isnotempty(AccountUpn), AccountUpn, AccountName))
    | where isnotempty(UserKey)
    | project RMMTime = TimeGenerated, DeviceName, DeviceId, OSPlatform, UserKey,
              RMMProcess, AccessMethod, FileName, FolderPath,
              ProcessCommandLine, InitiatingProcessFileName;
// Correlation
MailFloodedUsers
| join kind=inner ExternalTeamsChats on TargetUpn
| where TeamsTime >= FirstFloodTime and TeamsTime <= FirstFloodTime + FloodToTeamsWindow
| mv-expand UserKey = UserKeys to typeof(string)
| join kind=inner RMMExecutions on UserKey
| where RMMTime >= TeamsTime and RMMTime <= TeamsTime + TeamsToRMMWindow
| summarize FloodStartTime        = min(FirstFloodTime),
            MailVolume            = max(TotalFloodMails),
            SenderDomains         = max(DistinctSenderDomains),
            FirstTeamsChat        = min(TeamsTime),
            ExternalTeamsSender   = make_set(ExternalSender, 10),
            ExternalSenderDomains = make_set(ExternalSenderDomain, 10),
            ChatSubjects          = make_set(ChatSubject, 5),
            ThreadTypes           = make_set(ThreadType, 5),
            RMMExecutionTime      = min(RMMTime),
            FolderPaths           = make_set(FolderPath, 5),
            CommandLines          = make_set(ProcessCommandLine, 5)
    by TargetUpn, DeviceName, Platform = coalesce(OSPlatform, "unknown"), RMMProcess, AccessMethod
| extend Verdict = "Social engineering chain: Mail flood, external Teams chat, RMM launch"
| sort by RMMExecutionTime desc
```
