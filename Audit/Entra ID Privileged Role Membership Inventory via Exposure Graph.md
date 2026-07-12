# *Entra ID Privileged Role Membership Inventory via Exposure Graph*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1098.003 | Account Manipulation: Additional Cloud Roles | https://attack.mitre.org/techniques/T1098/003/ |
| T1078.004 | Valid Accounts: Cloud Accounts | https://attack.mitre.org/techniques/T1078/004/ |



#### Description
This query monitors direct, active user-to-role assignments within Microsoft Entra ID using the ExposureGraph table. It categorizes roles into specific tiers (Control Plane, Identity & Security, Application & Credential Control, and Workload Admin) to highlight potentially high-risk or over-privileged account configurations. Note: This query reflects the current snapshot state of the Exposure Graph and covers only permanent (direct) role assignments. PIM-eligible assignments that have not been activated are not visible in this data source and require AuditLogs or the PIM-specific APIs for detection.


#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References

## Defender XDR
```KQL
ExposureGraphEdges
| where EdgeLabel == "member of"
| where SourceNodeLabel == "user"
| where TargetNodeLabel == "role"
| extend RoleName = TargetNodeName
// Tier 0 – Control Plane (highest criticality) 
| extend RoleTier = case(
    RoleName in (
        "Global Administrator",
        "Privileged Role Administrator",
        "Privileged Authentication Administrator"
    ), "Tier0_ControlPlane",
// Tier 1 – Identity & Security 
    RoleName in (
        "Security Administrator",
        "Conditional Access Administrator",
        "Authentication Administrator",
        "Hybrid Identity Administrator",          // AD Connect / PHS / PTA
        "Identity Governance Administrator",
        "Directory Writers",
        "Domain Name Administrator",
        "Lifecycle Workflows Administrator",
        "External Identity Provider Administrator"
    ), "Tier1_IdentitySecurity",
// Tier 1 – Application & Credential Control 
    RoleName in (
        "Application Administrator",
        "Cloud Application Administrator",
        "Application Developer"                   // can create app registrations
    ), "Tier1_AppCredential",
// Tier 2 – Workload Admins 
    RoleName in (
        "Exchange Administrator",
        "SharePoint Administrator",
        "Teams Administrator",
        "Intune Administrator",
        "User Administrator",
        "Helpdesk Administrator",
        "Cloud Device Administrator",
        "Global Reader"                           // reads everything, incl. sensitive data
    ), "Tier2_WorkloadAdmin",
    "Other"
)
| where RoleTier != "Other"   // only monitored roles
```
