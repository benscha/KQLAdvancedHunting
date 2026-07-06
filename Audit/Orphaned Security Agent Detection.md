# *Orphaned Security Agent Detection*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |


#### Description
Detects security agents that are in a 'Published' status but lack an associated valid identity or owner in the IdentityInfo dataset. This identifies unmanaged or orphaned agents that may have been decommissioned, misconfigured, or potentially represent unauthorized infrastructure.


#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References

## Defender XDR
```KQL
AgentsInfo
| summarize arg_max(Timestamp, *) by AgentId
| where PublishedStatus == "Published"
| where Platform != "LocalAgents"
| mv-expand Owner = Owners
| extend OwnerObjectId = tolower(tostring(Owner.id))
| where isnotempty(OwnerObjectId)
| join kind=leftanti (
    IdentityInfo
    | summarize arg_max(Timestamp, *) by AccountObjectId
    | extend AccountObjectId = tolower(tostring(AccountObjectId))
) on $left.OwnerObjectId == $right.AccountObjectId
| distinct AgentId, AgentName = Name, OwnerObjectId, Platform, LifecycleStatus
```
