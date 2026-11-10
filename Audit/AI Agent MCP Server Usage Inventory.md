# *AI Agent MCP Server Usage Inventory*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |



#### Description

This query builds an inventory of which Model Context Protocol (MCP) servers have been used by AI agents over the last 30 days. It reads the AgentsInfo table, keeps only the most recent record per AgentId using arg_max on TimeGenerated, and then expands the McpServers array so that each configured MCP server appears as its own row. The embedded JSON object for each server is parsed to extract its name, type, and endpoint. Rows where neither a server name nor an endpoint could be resolved are dropped, since they carry no useful information. The remaining rows are reduced to distinct combinations of server name, type, endpoint, and AgentId, which removes duplicate associations that could otherwise inflate the counts. Finally, the query summarizes how many distinct agents are associated with each MCP server, grouped by name, type, and endpoint, and orders the results by that agent count in descending order.

The output is intended as an inventory and adoption overview rather than a threat detection: it answers which MCP servers are actually in use across the agent fleet and how widely each one is adopted. It is useful for spotting unexpected or unapproved MCP server endpoints, identifying shadow integrations, and prioritizing which servers deserve closer security review. The 30 day lookback window in the `ago(30d)` filter can be tuned to a shorter or longer period depending on how fresh the inventory needs to be, and the McpServers schema should be checked periodically in case Microsoft changes the field names used here.

#### Author
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Sentinel
```KQL
AgentsInfo
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by AgentId
| mv-expand McpServer = McpServers
| extend McpServer = parse_json(tostring(McpServer))
| extend McpServerName = tostring(McpServer.name),
         McpServerType = tostring(McpServer.type),
         McpServerEndpoint = tostring(McpServer.endpoint)
| where isnotempty(McpServerName) or isnotempty(McpServerEndpoint)
| distinct McpServerName, McpServerType, McpServerEndpoint, AgentId
| summarize AgentCount = count()
    by McpServerName, McpServerType, McpServerEndpoint
| order by AgentCount desc
```
