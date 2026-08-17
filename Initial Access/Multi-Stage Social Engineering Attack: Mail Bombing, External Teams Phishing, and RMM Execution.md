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
let Lookback           = 4h;    // Total search window
let MailThreshold      = 100;   // Trigger threshold for mail count
let MailTimeWindow     = 30m;   // Timeframe to hit the mail threshold
let FloodToTeamsWindow = 2h;    // Max allowed gap between mail flood and Teams message
let TeamsToRMMWindow   = 2h;    // Max allowed gap between Teams message and RMM execution
let MinSenderDomains   = 20;    // Mail bombings typically spoof/use many sender domains
// Internal domains 
let InternalDomains = dynamic([
    "domain.ch", "students.domain.ch", "other-domain.ch"
]);
let RMMProcesses = dynamic([
    "quickassist.exe", "teamviewer.exe", "anydesk.exe",
    "screenconnect.client.exe", "screenconnect.clientservice.exe",
    "rustdesk.exe", "splashtop.exe", "logmein.exe",
    "ateraagent.exe", "syncro.exe", "supremo.exe"
]);
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
        by TargetUpn = tolower(RecipientEmailAddress);
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
// Track RMM execution 
let RMMExecutions =
    DeviceProcessEvents
    | where TimeGenerated > ago(Lookback)
    | where FileName in~ (RMMProcesses) or InitiatingProcessFileName in~ (RMMProcesses)
    | project RMMTime = TimeGenerated, DeviceName, TargetUpn = tolower(AccountUpn),
              FileName, ProcessCommandLine, InitiatingProcessFileName;
// Correlation
MailFloodedUsers
| join kind=inner ExternalTeamsChats on TargetUpn
| where TeamsTime >= FirstFloodTime and TeamsTime <= FirstFloodTime + FloodToTeamsWindow
| join kind=inner RMMExecutions on TargetUpn
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
            CommandLines          = make_set(ProcessCommandLine, 5)
    by TargetUpn, DeviceName, RMMProcess = FileName
| extend Verdict = "Social engineering chain: Mail flood, external Teams chat, RMM launch"
| sort by RMMExecutionTime desc
```
