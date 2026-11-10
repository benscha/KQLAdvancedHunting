# *Agent MCP Server Endpoints Matching Threat Intel*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1071.001 | Application Layer Protocol: Web Protocols | https://attack.mitre.org/techniques/T1071/001 |
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | https://attack.mitre.org/techniques/T1195/002 |



#### Description

This rule correlates the MCP (Model Context Protocol) servers configured for AI agents in the environment against active threat intelligence indicators of type url and domain name. It first builds a lookup table from ThreatIntelIndicators, keeping only indicators seen in the last 30 days that are active, not deleted, not revoked, and currently within their validity window, and summarizes them by lookup type and value together with an indicator count and the highest confidence score observed. The main part reads AgentsInfo for the same 30 day window, takes the latest snapshot per agent, and expands the McpServers array so each configured MCP server is evaluated individually. Only servers with an HTTP or HTTPS endpoint are kept, and the query counts how many distinct agents reference each unique server name, type and endpoint combination. For every server, the host name is extracted from the endpoint, and both the full endpoint and the lowercased host are checked against the threat intelligence lookup for url and domain name indicators respectively. A left outer join keeps every observed MCP server even when there is no match, while adding the total indicator hit count, the matched indicator types, and the maximum confidence where a match exists. The result is ordered with servers that produced the most threat intelligence hits first, then by the number of agents using that server, which makes it easier to prioritize investigation of widely used or clearly flagged servers. Note that the url match compares the endpoint string as stored, without lowercasing, so indicators that differ only in letter case may not be matched; this is worth checking when tuning the rule. Analysts should treat any row marked TI-hit as requiring manual review rather than automatic confirmation of compromise.

#### Author
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Sentinel
```KQL
let TI =
    ThreatIntelIndicators
    | where TimeGenerated > ago(30d)
    | summarize arg_max(TimeGenerated, *)
        by WorkspaceId, Id, ObservableKey, ObservableValue
    | where IsActive == true and IsDeleted == false
    | where coalesce(Revoked, false) == false
    | where isnull(ValidFrom) or ValidFrom <= now()
    | where isnull(ValidUntil) or ValidUntil > now()
    | where ObservableKey in ('url:value', 'domain-name:value')
    | extend LookupType = ObservableKey,
             LookupValue = iff(
                 ObservableKey == 'domain-name:value',
                 tolower(ObservableValue),
                 ObservableValue)
    | summarize IndicatorCount = count(),
                MaxConfidence = max(Confidence)
        by LookupType, LookupValue;
AgentsInfo
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by AgentId
| mv-expand McpServer = McpServers
| extend McpServer = parse_json(tostring(McpServer))
| extend McpServerName = tostring(McpServer.name),
         McpServerType = tostring(McpServer.type),
         McpServerEndpoint = tostring(McpServer.endpoint)
| where McpServerEndpoint matches regex @'^https?://'
| distinct McpServerName, McpServerType, McpServerEndpoint, AgentId
| summarize AgentCount = count()
    by McpServerName, McpServerType, McpServerEndpoint
| extend McpHost = tolower(tostring(parse_url(McpServerEndpoint).Host))
| mv-expand LookupType = dynamic(['url:value', 'domain-name:value'])
    to typeof(string)
| extend LookupValue = iff(
    LookupType == 'url:value', McpServerEndpoint, McpHost)
| join kind=leftouter TI on LookupType, LookupValue
| summarize TIHits = sum(coalesce(IndicatorCount, 0)),
            MatchTypes = make_set_if(LookupType, isnotnull(IndicatorCount)),
            MaxConfidence = max(MaxConfidence)
    by McpServerName, McpServerType, McpServerEndpoint, AgentCount
| extend TIStatus = iff(
    TIHits > 0, 'TI-hit – check', 'No TI-hit')
| order by TIHits desc, AgentCount desc
```
