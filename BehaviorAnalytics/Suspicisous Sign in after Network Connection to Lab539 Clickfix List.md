# *Suspicisous Sign in after Network Connection to Lab539 Clickfix List*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566 | Phishing | https://attack.mitre.org/techniques/T1566/ |
| TA001 | Initial Access | https://attack.mitre.org/tactics/TA0001/ |
| T1204.004 | User Execution: Malicious Copy and Paste | https://attack.mitre.org/techniques/T1204/004/ |

#### Description
Thx Steven Lim for this great Teamwork. ♥
This rule detects suspicious sign-in activities that occur shortly after a network connection to an IP address associated with 'Lab539 Clickfix'. It correlates risky sign-in events from Azure Active Directory (AAD) with network connection logs from devices. Specifically, it looks for AAD sign-ins with a risk level of 30 or higher, from non-guest, non-compliant, and non-managed devices, where the IP address has not been seen for that user in the last 30 days. This is then joined with network connection events to IP addresses found in the 'Lab539 Clickfix' external data, ensuring the sign-in occurs after the network connection within a short timeframe. The 'Lab539 Clickfix' reference suggests a connection to a known threat or campaign, possibly related to phishing or credential compromise.

#### Risk
Clickfix Attacks

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- https://detections.ai/rules/0199e342-187f-7054-a33a-37bc61caf313

## Defender XDR
```KQL
// Based on Steven Lim's Query https://detections.ai/rules/0199e342-187f-7054-a33a-37bc61caf313
// thx Steven for this Teamwork
let ExcludedApps = pack_array("CIT_JamfConnect@Prod", "TestAppTEST2");
let Lab539ClickFix=externaldata(Timestamp:datetime, Hostname:string, IP:string, Country:string, Org:string, Nameservers:string, Time:datetime, DomainCreation:datetime, DomainExpire:datetime, Name:string, Registrar:string, DomainUpdate:datetime, EventID:string)
[h'https://raw.githubusercontent.com/SlimKQL/Hunting-Queries-Detection-Rules/refs/heads/main/IOC/lab539-clickfix-data.csv'];
// Netzwerkverbindungen zu Lab539ClickFix IPs mit Device-Informationen
let Lab539ClickFixNetworkConnections = Lab539ClickFix
| where Timestamp >ago(2d)
| join kind=inner ( DeviceNetworkEvents 
                    | where RemoteIPType == "Public" ) on $left.Hostname == $right.RemoteUrl
| extend NetworkConnectionTime = TimeGenerated
| project NetworkConnectionTime, DeviceName, DeviceId, RemoteIP, InitiatingProcessAccountUpn
| summarize MinConnectionTime = min(NetworkConnectionTime) by DeviceName, InitiatingProcessAccountUpn;
// Risky Sign-ins vom heutigen Tag
let RiskySignIns = AADSignInEventsBeta
| where TimeGenerated > ago(1d)
| where isnotempty(RiskLevelDuringSignIn) 
| where Application !in (ExcludedApps)
| where RiskLevelDuringSignIn >= 30
| where IsGuestUser == 0
| where IsCompliant == 0
| where IsManaged == 0
| where RiskLevelAggregated > 1
| project SignInTimestamp = Timestamp, AccountUpn, AccountObjectId, Application, IPAddress, RiskLevelDuringSignIn, RiskLevelAggregated, RiskState, City, Country, ReportId;
// Historische IPs pro Account - nur Count statt ganze Liste
let HistoricalIPCounts = AADSignInEventsBeta
| where ErrorCode == 0
| where Timestamp >= ago(30d) and Timestamp < ago(1d)
| summarize by AccountUpn, IPAddress
| summarize HistoricalIPCount = count() by AccountUpn, IPAddress;
// Join: Risky Sign-ins mit historischen IP-Counts
let RiskySignInsWithHistory = RiskySignIns
| join kind=leftouter HistoricalIPCounts on AccountUpn, IPAddress
| extend IPSeenBefore = iff(isnotempty(HistoricalIPCount), true, false)
| where IPSeenBefore == false;  // Filter schon hier anwenden
// Join: Risky Sign-ins mit Lab539 Network Connections
Lab539ClickFixNetworkConnections
| join kind=inner RiskySignInsWithHistory on 
    $left.InitiatingProcessAccountUpn == $right.AccountUpn
| where SignInTimestamp > MinConnectionTime
| extend TimeDifference_Minutes = datetime_diff('minute', SignInTimestamp, MinConnectionTime)
| project MinConnectionTime, Timestamp=SignInTimestamp, TimeDifference_Minutes, DeviceName, AccountUpn, AccountObjectId, SignInIP = IPAddress, Application, RiskLevelDuringSignIn, RiskLevelAggregated, RiskState, City, Country, ReportId
| order by Timestamp desc
```
