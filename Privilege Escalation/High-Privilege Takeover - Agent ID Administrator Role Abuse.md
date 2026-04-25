# *High-Privilege Takeover - Agent ID Administrator Role Abuse*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1649 | Steal or Forge Authentication Certificates | https://attack.mitre.org/techniques/T1649/ |

#### Description
This detection identifies potential privilege escalation involving the Agent ID Administrator role. Historically, this role could be exploited to bypass intended restrictions by assigning the actor as an owner of sensitive Service Principals and subsequently adding unauthorized credentials.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- https://cybersecuritynews.com/entra-agent-id-administrator-abused/

## Sentinel

```KQL
// ===========================================================================
// Detection: Agent ID Administrator → Service Principal Takeover
// Source: Silverfort Research / Scope Overreach (Privilege Escalation) https://cybersecuritynews.com/entra-agent-id-administrator-abused/
// ===========================================================================
let LookbackDays = 30d;
let AgentRoleAssignments =
    AuditLogs
    | where TimeGenerated > ago(LookbackDays)
    | where OperationName == "Add member to role"
    | where TargetResources has "Agent ID Administrator"
    | extend NewRoleMemberId = tostring(TargetResources[0].id)
    , NewRoleMemberName = tostring(TargetResources[0].userPrincipalName)
    , RoleAssignedAt = TimeGenerated
    | project NewRoleMemberId, NewRoleMemberName, RoleAssignedAt;
// Owner additions to Service Principals
let OwnerAdditions =
    AuditLogs
    | where TimeGenerated > ago(LookbackDays)
    | where OperationName == "Add owner to service principal"
    | where Result == "success"
    | extend ActorId   = tostring(InitiatedBy.user.id)
    , ActorUPN  = tostring(InitiatedBy.user.userPrincipalName)
    , ActorIP   = tostring(InitiatedBy.user.ipAddress)
    // Target: The Service Principal that received a new owner
    | mv-expand TargetResource = TargetResources
    | where tostring(TargetResource["@odata.type"]) == "#microsoft.graph.servicePrincipal"
        or tostring(TargetResource.type) == "ServicePrincipal"
    | extend TargetSPName = tostring(TargetResource.displayName)
    , TargetSPId   = tostring(TargetResource.id)
    | project TimeGenerated, ActorId, ActorUPN, ActorIP, TargetSPName, TargetSPId;
// Credential additions (The proof of actual takeover)
let CredentialAdditions =
    AuditLogs
    | where TimeGenerated > ago(LookbackDays)
    | where OperationName in ("Add service principal credentials", 
                               "Update application – Certificates and secrets management")
    | where Result == "success"
    | extend ActorId   = tostring(InitiatedBy.user.id)
    , ActorUPN = tostring(InitiatedBy.user.userPrincipalName)
    | mv-expand TargetResource = TargetResources
    | extend TargetSPId   = tostring(TargetResource.id)
    , TargetSPName = tostring(TargetResource.displayName)
    | project CredentialAddedAt = TimeGenerated, ActorId, ActorUPN, TargetSPId, TargetSPName;
OwnerAdditions
| join kind=inner AgentRoleAssignments
    on $left.ActorId == $right.NewRoleMemberId
// Temporal Consistency: Owner change must occur AFTER role assignment
| where TimeGenerated >= RoleAssignedAt
// Correlate Credential step (Optional but provides high-fidelity)
| join kind=leftouter CredentialAdditions
    on $left.ActorId == $right.ActorId
    and $left.TargetSPId == $right.TargetSPId
// Prioritize non-agent SPs (Noise reduction filter)
| extend IsLikelyAgentSP = TargetSPName has_any ("Connector", "Agent", "Proxy", "Bot")
| project
    TimeGenerated,
    DetectionPhase    = "1 - Owner Added",
    ActorUPN,
    ActorIP,
    TargetSPName,
    TargetSPId,
    RoleAssignedAt,
    CredentialAddedAt,
    IsLikelyAgentSP,
    HighRiskAlert     = iff(isnotempty(CredentialAddedAt) and not(IsLikelyAgentSP), true, false)
| order by HighRiskAlert desc, TimeGenerated desc
```
