# *AI Agent Third-Party Plugin with Internal Data Access*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1567 | Exfiltration Over Web Service | https://attack.mitre.org/techniques/T1567/ |

#### Description

Detects AI agents configured with third-party plugins or allowances that also have access to sensitive internal data sources like SharePoint, OneDrive, or Teams. This configuration could pose a data exfiltration risk if the third-party plugin is compromised or malicious.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
// Detection of data exfiltration risks via third-party plugins in sensitive agents
AIAgentsInfo 
| where TimeGenerated >= ago(1d)
| extend RawInfo = parse_json(RawAgentInfo)
| extend ImpactedSettings = RawInfo.impactedSettings
| extend AppType = tostring(RawInfo.appType)
| extend PublishedStatus = tostring(RawInfo.publishedStatus)
// Detection of third-party allowances
| where AppType =~ "thirdParty" 
    or ImpactedSettings has "allowThirdParty"
    or AgentToolsDetails has "thirdParty"
// Focus on agents with access to internal data sources such as SharePoint or Teams
| where AIAgentName has_any ("Sharepoint", "OneDrive", "Teams", "Internal", "Intranet")
    or ConnectedAgentsSchemaNames has_any ("Sharepoint", "OneDrive")
| extend HostCustomEntity = LastModifiedByUpn
```
