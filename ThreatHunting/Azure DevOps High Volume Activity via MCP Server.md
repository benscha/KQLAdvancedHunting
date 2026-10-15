# *Azure DevOps High Volume Activity via MCP Server*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1078 | Valid Accounts | https://attack.mitre.org/techniques/T1078 |
| T1213.003 | Data from Information Repositories: Code Repositories | https://attack.mitre.org/techniques/T1213/003 |
| T1526 | Cloud Service Discovery | https://attack.mitre.org/techniques/T1526 |


#### Description

This query monitors the Azure DevOps audit log (ADOAuditLogs) for operations performed through the Azure DevOps MCP Server, identified by a user agent starting with "AzureDevOps.MCP". The MCP Server allows AI agents and assistants to interact with Azure DevOps on behalf of a user, which makes it an attractive path for automated enumeration and bulk data access once an identity or token is compromised, or when an agent is misused or manipulated through prompt injection.

Within the lookback window (default one hour), all MCP operations are aggregated per actor, source IP address and client ID. For each combination the query calculates the time range, the total number of operations, the number of distinct audit areas and operations, and collects the affected projects and operation names. A result is returned when the number of operations exceeds the defined threshold (default 50) or when activity spans more than three different audit areas, which indicates broad exploration of the organization rather than a focused task.

Tune LookbackTime and ThresholdAPIcalls to the normal usage of MCP based agents in your environment. Developers who use AI assistants heavily for legitimate work can trigger the rule, so consider allowlisting known users or client IDs after establishing a baseline.

#### Author
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Sentinel
```KQL
let LookbackTime = 1h;
let ThresholdAPIcalls = 50; // Define your threshold
ADOAuditLogs
| where TimeGenerated > ago(LookbackTime)
| where UserAgent startswith "AzureDevOps.MCP"
| summarize 
    Starttime = min(TimeGenerated),
    Endtime = max(TimeGenerated),
    TotalOperations = count(),
    UniqueAreas = dcount(Area),
    UniqueOperations = dcount(OperationName),
    TargetProjects = make_set(ProjectName, 10),
    OperationsList = make_set(OperationName, 20),
    UserAgents = make_set(UserAgent, 5)
    by ActorUPN, IPAddress, ClientId
| extend IsHighVolume = iff(TotalOperations > ThresholdAPIcalls, true, false)
| where IsHighVolume or UniqueAreas > 3
| project 
    Starttime, 
    Endtime, 
    ActorUPN, 
    IPAddress, 
    TotalOperations, 
    UniqueAreas, 
    TargetProjects, 
    OperationsList, 
    UserAgents,
    IsHighVolume
```
