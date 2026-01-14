# *Certificate Issued to Privileged User*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1649 | Steal or Forge Authentication Certificates | https://attack.mitre.org/techniques/T1649/ |

#### Description
This rule detects when a certificate is issued to a privileged user. It identifies privileged users by checking their group membership against a predefined list of administrative groups such as 'Domain Admins', 'Enterprise Admins', and 'Administrators'. The rule then looks for Windows Security Event ID 4886, which indicates a certificate services operation, and extracts the principal name from the Subject Alternative Name field. Finally, it joins this information with the identified privileged users to flag any certificate issuance to them.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- https://angelica.gitbook.io/hacktricks/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation

## Sentinel

```KQL
// Create a list of privileged users based on AD group membership
let AdminGroups = dynamic([
    "Domain Admins",
    "Enterprise Admins",
    "Administrators",
    "Schema Admins",
    "Account Operators",
    "Backup Operators",
    "Server Operators"
]);
let PrivUsers =
    IdentityInfo
    | where Type == "User"
    | mv-apply GroupMembership on (where GroupMembership in~ (AdminGroups))
    | summarize by PrincipalName = tostring(AccountUpn);
// Process certificate request events (Event ID 4886)
SecurityEvent
| where EventID == 4886
| extend XmlData = parse_xml(EventData)
| mv-expand DataNode = XmlData.EventData.Data
| extend FieldName = tostring(DataNode['@Name']), FieldValue = tostring(DataNode['#text'])
// Group by ResourceId and TimeGenerated to extract specific fields from XML nodes
| summarize
    SubjectAlternativeName = anyif(FieldValue, FieldName == "SubjectAlternativeName"),
    RequestClientInfo = anyif(FieldValue, FieldName == "RequestClientInfo"),
    Computer = any(Computer)
  by _ResourceId, TimeGenerated
| extend SubjectAlternativeName = tostring(SubjectAlternativeName)
| extend RequesterMachine = extract(@"Machine:\s*([A-Za-z0-9\-\_]+)", 1, RequestClientInfo)
| extend PrincipalName = extract(@"Principal Name=([^ ]+)", 1, SubjectAlternativeName)
| extend HasSTU = iff(SubjectAlternativeName has "URL=ID:STU", true, false)
// Set mandatory fields for the Custom Detection Rule
| extend Timestamp = TimeGenerated
| extend ReportId = tostring(new_guid())
// Cross-reference with the privileged user list
| join kind=inner PrivUsers on PrincipalName
// Join with DeviceInfo to enrich with machine context using a normalized join key
| extend JoinKey = tolower(RequesterMachine)
| join kind=leftouter (
    DeviceInfo 
    | extend DeviceNameLower = tolower(DeviceName)
    | summarize arg_max(Timestamp, *) by DeviceNameLower 
) on $left.JoinKey == $right.DeviceNameLower```
