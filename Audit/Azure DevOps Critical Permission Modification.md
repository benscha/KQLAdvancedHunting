# *Azure DevOps Critical Permission Modification*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1098.003 | Additional Cloud Roles | https://attack.mitre.org/techniques/T1098/003/ |
| T1078.004 | Cloud Acconts | https://attack.mitre.org/techniques/T1078/004/ |


#### Description
Detects critical permission changes in Azure DevOps, specifically focusing on 'allow' changes to sensitive permissions like 'Edit build pipeline', 'Manage permissions', 'Queue builds', 'Administer build', and 'Bypass policies when completing' within key namespaces such as 'Git Repositories', 'ReleaseManagement', 'PipelinesPrivileges', and 'Project-level Permissions'. This rule aims to identify potential privilege escalation or unauthorized access attempts within Azure DevOps environments.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References

## Defender XDR
```KQL
ADOAuditLogs_CL
| where TimeGenerated > ago(1d)
| where ActionId == "Security.ModifyPermission"
| extend d=parse_json(Data)
| extend NamespaceName=tostring(d.NamespaceName), EventSummary=d.EventSummary
| mv-expand EventSummary
| extend permissionNames=tostring(EventSummary.permissionNames), change=tostring(EventSummary.change), subjectDisplayName=tostring(EventSummary.subjectDisplayName)
| where change =~ "allow"
| where permissionNames in~ ("Edit build pipeline","Manage permissions","Queue builds","Administer build","Bypass policies when completing") or NamespaceName in~ ("Git Repositories","ReleaseManagement","PipelinesPrivileges","Project-level Permissions")

```
