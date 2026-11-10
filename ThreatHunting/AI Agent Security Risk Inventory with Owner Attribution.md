# *AI Agent Security Risk Inventory with Owner Attribution*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
|  |  |  |



#### Description

This query builds an inventory of active risk indicators reported against registered AI agents, using the AgentsInfo table as the source. It looks back over the last 30 days and keeps only the most recent record per AgentId through arg_max on TimeGenerated, so each agent is represented by its current state rather than its full history. The risk payload is read from either a RiskText or a RiskIndicators column, whichever is present, which makes the query resilient to schema naming differences across table versions. That payload is parsed as JSON and expanded so each risk indicator attached to an agent becomes its own row, with the indicator's title, severity, active flag, description and last updated timestamp pulled out as separate fields.

Rows with no title or severity are dropped, and two external parameters, excludedRiskSeverity and excludedRiskTitle, are used to filter out severities or specific risk titles that the analyst does not want surfaced, which lets known or accepted risks be tuned out without changing the query body. For each remaining risk, the query also digs into the indicator's display evidence to pull out the agent owner's UPN, identified by an evidence entry titled Owner UPNs, and collapses any duplicates into a single comma separated value. The final projection lists the agent name, ID, platform, owner, and the risk's title, severity, active state, description and last update time, ordered with the most recently seen agents first.

Because this is an inventory and tuning query rather than a detection of a specific adversary technique, it has no natural ATT&CK mapping. Analysts should populate excludedRiskSeverity and excludedRiskTitle to match their environment's noise level, and should confirm that the Owner UPNs evidence label matches what their agent platform actually emits, since a mismatch there would leave OwnerUPN empty for otherwise valid risk rows.

#### Author
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Sentinel
```KQL
AgentsInfo
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by AgentId
| extend RiskText = tostring(coalesce(
    column_ifexists("RiskText", ""),
    column_ifexists("RiskIndicators", "")
))
| extend RiskBag = parse_json(RiskText)
| mv-expand RiskId = bag_keys(RiskBag)
| extend Risk = RiskBag[tostring(RiskId)]
| extend
    RiskTitle = tostring(Risk["title"]),
    RiskSeverity = tostring(Risk["severity"]),
    RiskActive = tobool(Risk["isActive"]),
    RiskDescription = tostring(Risk["description"]),
    RiskUpdated = todatetime(Risk["lastUpdatedDateTime"])
| where isnotempty(RiskTitle)
| where isnotempty(RiskSeverity)
| where RiskSeverity !in~ (excludedRiskSeverity)
| where RiskTitle !in~ (excludedRiskTitle)
| mv-apply Evidence = Risk["displayEvidence"] on (
    where tostring(Evidence["title"]) =~ "Owner UPNs"
    | summarize OwnerUPN = strcat_array(make_set(tostring(Evidence["text"])), ", ")
)
| project
    TimeGenerated,
    Name,
    AgentId,
    Platform,
    OwnerUPN,
    RiskTitle,
    RiskSeverity,
    RiskActive,
    RiskDescription,
    RiskUpdated
| order by TimeGenerated desc
```
