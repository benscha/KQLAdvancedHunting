# *Microsoft Dynamics 365 Privilege Escalation via Role or Team Modification*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1098 | Account Manipulation | https://attack.mitre.org/techniques/T1098 |
| T1078 | Valid Accounts | https://attack.mitre.org/techniques/T1078 |

#### Description

This rule detects suspicious activity in Microsoft Dynamics 365 where an account, from outside the corporate IP range, first performs inquiries about user privileges and then subsequently modifies or creates roles or teams within a short time frame. This could indicate an attempt to escalate privileges or gain unauthorized access.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### Possible false positives
- Legitimate administrative actions performed by users 

## Defender XDR
```KQL
let CorporateIPRange = "147.86.0.0/16";
let ThreatWindow = 10m;
let SuspiciousInquiries = 
    CloudAppEvents
    | where TimeGenerated > ago(1d)
    | where Application == "Microsoft Dynamics 365"
    | where not(ipv4_is_in_range(IPAddress, CorporateIPRange ))
    | where IsAdminOperation == 0
    | where ActionType in ("RetrieveUserPrivileges", "RetrieveUserPrivilegeByPrivilegeName", "RetrievePrivilegeMaxDepthFromTeamRoles")
    | project TargetTime = TimeGenerated, AccountId, IPAddress, CorrelationId = tostring(parse_json(RawEventData).CorrelationId);
CloudAppEvents
| where TimeGenerated > ago(1d)
| where Application == "Microsoft Dynamics 365"
| where not(ipv4_is_in_range(IPAddress, CorporateIPRange ))
| where ActionType has_any ("Update", "Create") and (ObjectName has "role" or ObjectName has "team" or parse_json(RawEventData).EntityName has_any ("role", "systemuserroles", "teamroles"))
| project ModificationTime = TimeGenerated, AccountId, ActionType, ObjectName, RawEventData
| join kind=inner SuspiciousInquiries on AccountId
| where ModificationTime between (TargetTime .. (TargetTime + ThreatWindow))
| project ModificationTime, AccountId, ActionType, ObjectName, IPAddress, TargetTime
```
