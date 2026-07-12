# *Microsoft Entra Conditional Access Policy Exclusion Modification*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1556.009 | Modify Authentication Process: Conditional Access Policies | https://attack.mitre.org/techniques/T1556/009/ |
| T1484 | Domain or Tenant Policy Modification | https://attack.mitre.org/techniques/T1484 |



#### Description
This rule detects modifications to Microsoft Entra ID Conditional Access policies where users or groups are added to the exclusion list. Such modifications can be used by adversaries to bypass security controls and facilitate persistence or lateral movement by ensuring specific accounts or groups are not subject to MFA or other authentication requirements.


#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References

## Defender XDR
```KQL
// CAP Exludes
AuditLogs
| where OperationName in ("Update conditional access policy", "Create conditional access policy")
| where Result == "success"
| mv-expand TargetResource = TargetResources
| mv-expand ModifiedProperty = TargetResource.modifiedProperties
| where ModifiedProperty.displayName == "PolicyDetail"
| extend OldPolicy = todynamic(tostring(ModifiedProperty.oldValue))
| extend NewPolicy = todynamic(tostring(ModifiedProperty.newValue))
// Extract Excludes
| extend OldExclusions = OldPolicy.conditions.users.excludeGroups
| extend NewExclusions = NewPolicy.conditions.users.excludeGroups
| extend OldExcludedUsers = OldPolicy.conditions.users.excludeUsers
| extend NewExcludedUsers = NewPolicy.conditions.users.excludeUsers
// check for added Excludes
| where array_length(NewExclusions) > array_length(OldExclusions) 
     or array_length(NewExcludedUsers) > array_length(OldExcludedUsers)
| project TimeGenerated, InitiatedBy = Identity, PolicyName = TargetResource.displayName, OldExclusions, NewExclusions, OldExcludedUsers, NewExcludedUsers

```
