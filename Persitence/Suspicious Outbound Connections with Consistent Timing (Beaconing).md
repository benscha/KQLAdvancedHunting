# *Suspicious Outbound Connections with Consistent Timing (Beaconing)*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1049 | Exfiltration Over C2 Channel | https://attack.mitre.org/techniques/T1049/ |

#### Description

This rule detects suspicious outbound network connections from devices that exhibit a consistent timing pattern (low standard deviation relative to the average time delta between connections) to public IP addresses. It specifically looks for connections that are not initiated by common browsers unless they are running in headless mode, or connections initiated by processes with low global prevalence or identified as Living Off The Land Binaries (LOLBAS). This pattern can indicate automated activity, command and control communication, or data exfiltration.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- 


## Defender XDR
```KQL
let TimeThreshold = 3600; 
let MinEvents = 6; 
let WhitelistedDomains = dynamic([".wns.windows.com","techsmith.com","firefox.com", "acrobat.com","nic.ch","windowsupdate.com", ".arc.azure.com", ".svc.cloud.microsoft", ".guestconfiguration.azure.com", "adobe.com","assets.adobedtm.com",".pki.goog",".adobe.io",".adobelogin.com", "microsoft.com", "office.com", "sharepoint.com", "icloud.com", "citrix.com", "office365.com","digicert.com"]);
let WhitelistedIPs = dynamic(["127.0.0.1"]);
let Browsers = dynamic(["msedge.exe", "chrome.exe", "firefox.exe", "brave.exe", "opera.exe"]);
// Fetching the official LOLBAS list
let LOLBAS = (externaldata (Name:string, Category:string, Description:string, Author:string, Created:datetime, Commands:string, Paths:string, Detection:string, Resources:string, Acknowledgements:string, Url:string) 
    ['https://lolbas-project.github.io/api/lolbas.csv'] 
    with (format='csv', ignoreFirstRecord=true));
let CIDRASN = (externaldata (CIDR:string, CIDRASN:int, CIDRASNName:string) 
    ['https://firewalliplists.gypthecat.com/lists/kusto/kusto-cidr-asn.csv.zip']);
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where isnotempty(RemoteIP) and RemoteIPType == "Public"
| where RemoteIP !in (WhitelistedIPs)
| where not(RemoteUrl has_any (WhitelistedDomains))
// ReportId zum Project hinzugefügt
| project TimeGenerated, DeviceId, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256, ReportId
| sort by DeviceId, RemoteIP, TimeGenerated asc
| serialize
| extend PrevTime = prev(TimeGenerated), PrevDeviceId = prev(DeviceId), PrevRemoteIP = prev(RemoteIP)
| extend TimeDelta = iif(DeviceId == PrevDeviceId and RemoteIP == PrevRemoteIP, 
                         datetime_diff('second', TimeGenerated, PrevTime), 
                         int(null))
| where TimeDelta > 30 and TimeDelta <= TimeThreshold
| summarize 
    EventCount = count(),
    AvgDelta = avg(TimeDelta),
    StdDevDelta = stdev(TimeDelta),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    ProcessName = any(InitiatingProcessFileName),
    SHA256 = any(InitiatingProcessSHA256),
    CommandLine = any(InitiatingProcessCommandLine),
    // Wir nehmen die ReportId des letzten Events für Verknüpfungen/Alerts
    ReportId = arg_max(TimeGenerated, ReportId)[1]
    by DeviceId, RemoteIP, RemoteUrl, RemotePort
| where EventCount >= MinEvents
| where StdDevDelta < (AvgDelta * 0.2)
| extend isBrowser = ProcessName in~ (Browsers)
| extend isHeadless = CommandLine has_any ("--headless", "-headless", "--remote-debugging-port")
| evaluate ipv4_lookup(CIDRASN, RemoteIP, CIDR, return_unmatched=true)
| invoke FileProfile(SHA256)
| project-away SHA2561
| where (isBrowser == true and isHeadless == true) 
     or (isBrowser == false and (GlobalPrevalence < 10000 or ProcessName in~ ((LOLBAS | project Name))))
| project-reorder LastSeen, ReportId, DeviceId, ProcessName, isHeadless, GlobalPrevalence, RemoteIP, RemoteUrl
| sort by isHeadless desc, GlobalPrevalence asc

```
