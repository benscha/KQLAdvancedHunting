# *AI Agent with Weak Authentication or Access Control*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
|  |  |  |

#### Description

This rule detects AI Agents configured with weak authentication types (None, Anonymous) or overly permissive access control policies ('allowedForAll' or 'unrestricted' capabilities). Such configurations can expose the AI Agent to unauthorized access or manipulation.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
AIAgentsInfo
| where TimeGenerated >= ago(7d)
| extend RawInfo = parse_json(RawAgentInfo)
| extend AuthTrigger = toint(RawInfo.Bot.Attributes.authenticationtrigger.Value)
| extend IsStateActive = toint(RawInfo.Bot.Attributes.statecode.Value) == 0
| where UserAuthenticationType in~ ("None", "Anonymous") 
    or AccessControlPolicy =~ "allowedForAll"
    or AccessCapabilities has "unrestricted"
| project TimeGenerated, 
          AIAgentId, 
          AIAgentName, 
          LastModifiedByUpn, 
          UserAuthenticationType, 
          AccessControlPolicy, 
          AccessCapabilities, 
          AgentStatus
| extend HostCustomEntity = LastModifiedByUpn```
