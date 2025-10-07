# *Network Connection to High-Confidence ThreatView Domain*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| TA0011 | Command and Control | https://attack.mitre.org/tactics/TA0011/ |

#### Description
This rule detects successful network connections from devices to domains identified as high-confidence threats by ThreatView.io. It specifically looks for outbound connections to public IP addresses where the remote URL's domain matches an entry in the ThreatView high-confidence feed.

#### Risk
Network Connection to High-Confidence URLs

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- https://threatview.io/)

## Defender XDR
```KQL
let DOMAINHighConfThreatView = externaldata (Domain:string) [@" https://threatview.io/Downloads/DOMAIN-High-Confidence-Feed.txt" ] with (format="txt", ignoreFirstRecord = false);
DeviceNetworkEvents
| where isnotempty( RemoteUrl)
| where RemoteIPType == "Public"
| where ActionType == "ConnectionSuccess"
| extend Domain = extract(@"^(?:https?://)?([^/]+)", 1, RemoteUrl)
| join kind=inner DOMAINHighConfThreatView on Domain
```
