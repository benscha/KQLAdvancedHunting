# *Microsoft Copilot Access to External Resources (XPIA)*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1530 | Data from Cloud Storage | https://attack.mitre.org/techniques/T1530/ |

#### Description

This rule detects instances where Microsoft Copilot accesses external resources, specifically identifying events where 'XPIADetected' is true. This indicates Copilot interacting with resources outside its immediate environment, which could be a security concern if the accessed resources are sensitive or untrusted.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
CopilotActivity
| extend LLM = parse_json(LLMEventData)
| mv-expand AccessedResources = LLM.AccessedResources
| extend XPIADetected = toboolean(AccessedResources.XPIADetected)
| extend SiteUrl = tostring(AccessedResources.SiteUrl)
| where XPIADetected == true

```
