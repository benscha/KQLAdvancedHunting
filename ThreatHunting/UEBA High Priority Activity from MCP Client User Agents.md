# *UEBA High Priority Activity from MCP Client User Agents*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1078.004 | Valid Accounts: Cloud Accounts | https://attack.mitre.org/techniques/T1078/004 |



#### Description

This query hunts for anomalous user activity in Microsoft Sentinel UEBA that was performed through a Model Context Protocol (MCP) client. It reads the BehaviorAnalytics table, keeps only events with an InvestigationPriority of 5 or higher, expands the DevicesInsights field and extracts the UserAgent of the device involved. Events are returned when the user agent contains the string "mcp".

MCP is increasingly used by AI agents and coding assistants to interact with cloud services, APIs and Microsoft 365 resources on behalf of a user. When such a client acts with a user's identity, the activity often looks unusual to UEBA: new applications, unusual volumes, uncommon resources or atypical access patterns. An attacker who has obtained valid credentials or tokens can also use MCP tooling to automate reconnaissance and data access while blending in with legitimate AI agent traffic. Surfacing high priority UEBA anomalies that originate from MCP clients helps analysts separate sanctioned AI agent usage from suspicious automation and identify users or agents that need review.

The InvestigationPriority threshold can be lowered for broader hunting or raised to reduce noise. Known and approved MCP integrations can be excluded by user or application. Note that the substring "mcp" may also match unrelated user agents, and MCP clients that do not identify themselves in the user agent are not detected.

#### Author
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Sentinel
```KQL
BehaviorAnalytics
| where InvestigationPriority >= 5
| mv-expand DevicesInsights
| extend UserAgent = (DevicesInsights.UserAgent)
| where isnotempty( UserAgent)
| where tolower( UserAgent) contains "mcp"
```
