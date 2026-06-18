# *Windows Workstations with RDP Enabled and Allowed Connections*

## Query Information

### Category: Threat Hunting 

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1021.001 | Remote Desktop Protocol | https://attack.mitre.org/techniques/T1021/001 |

#### Description

This Threat Hunting Query identifies Windows workstations where the Remote Desktop Protocol (RDP) service is running and configured to allow connections. This configuration, while legitimate, can increase the attack surface if not properly secured, making these systems potential targets for remote access by adversaries.


#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

## Defender XDR
```KQL
// Threat Hunting Query
ExposureGraphNodes
| where NodeLabel == "device"
| extend RawDataDynamic = NodeProperties.rawData
| project-away NodeProperties
| evaluate bag_unpack(RawDataDynamic)
| where deviceSubtype == "Workstation"
| where onboardingStatus == "Onboarded"
| where osDistribution == "Windows"
| extend RdpServiceStatus = parse_json(rdpStatus.serviceRunning)
| where RdpServiceStatus == true
| extend RdpallowConnections = parse_json(rdpStatus.allowConnections)
| where RdpallowConnections == true
| extend RdpServiceStartMode = parse_json(remoteServicesInfo.rdp.startMode)
| extend RdpnlaMode = parse_json(remoteServicesInfo.rdp.nlaRequired)
| project deviceName, exposureScore, osPlatformFriendlyName, osVersionFriendlyName, RdpServiceStatus, RdpallowConnections, RdpServiceStartMode, RdpnlaMode

```
