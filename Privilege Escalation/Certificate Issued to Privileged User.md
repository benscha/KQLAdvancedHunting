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
let AdminGroups = dynamic([
    "Domain Admins",
    "Enterprise Admins",
    "Administrators",
    "Schema Admins",
    "Account Operators",
    "Backup Operators",
    "Server Operators"
]);
let PrivUsers = IdentityInfo
//| where TimeGenerated > ago(7d)
| where Type == "User"
| mv-apply GroupMembership on (
    where GroupMembership in~ (AdminGroups)
)
| project PrincipalName = tostring(AccountUpn);
SecurityEvent
| where EventID == "4886"
| extend XmlData = parse_xml(EventData)
| mv-expand DataNode = XmlData.EventData.Data
| extend FieldName = tostring(DataNode['@Name']), FieldValue = tostring(DataNode['#text'])
| summarize DataBag = make_bag(pack(FieldName, FieldValue)) by TimeGenerated, Computer, EventID, _ResourceId
| evaluate bag_unpack(DataBag)
| extend SubjectAlternativeName = tostring(SubjectAlternativeName)
| extend RequesterMachine = extract(@"Machine:\s*([A-Za-z0-9\-\_]+)", 1, RequestClientInfo)
| extend PrincipalName = extract(@"Principal Name=([^ ]+)", 1, SubjectAlternativeName)
| extend HasSTU = iff(SubjectAlternativeName has "URL=ID:STU", true, false)
| project-away SubjectAlternativeName, _ResourceId, DCOMorRPC, RequestCSPProvider
| join kind=inner PrivUsers on PrincipalName
```

if you like to create a Detection Rule you need to use this Query:

```KQL
// Define high privileged AD groups
let AdminGroups = dynamic([
"Domain Admins",
"Enterprise Admins",
"Administrators",
"Schema Admins",
"Account Operators",
"Backup Operators",
"Server Operators"
]);
// Collect privileged users based on group membership
let PrivUsers =
IdentityInfo
| where Type == "User"
| mv-apply GroupMembership on (where GroupMembership in~ (AdminGroups))
| project PrincipalName = tostring(AccountUpn);
// Parse certificate request events (Event ID 4886)
SecurityEvent
| where EventID == 4886
| extend XmlData = parse_xml(EventData)
| mv-expand DataNode = XmlData.EventData.Data
| extend FieldName = tostring(DataNode['@Name']), FieldValue = tostring(DataNode['#text'])
| summarize
    SubjectAlternativeName = anyif(FieldValue, FieldName == "SubjectAlternativeName"),
    RequestClientInfo = anyif(FieldValue, FieldName == "RequestClientInfo"),
    TimeGenerated = any(TimeGenerated),
    Computer = any(Computer),
    EventID = any(EventID)
  by _ResourceId
| extend SubjectAlternativeName = tostring(SubjectAlternativeName)
| extend RequesterMachine = extract(@"Machine:\s*([A-Za-z0-9\-\_]+)", 1, RequestClientInfo)
| extend PrincipalName = extract(@"Principal Name=([^ ]+)", 1, SubjectAlternativeName)
| extend HasSTU = iff(SubjectAlternativeName has "URL=ID:STU", true, false)
| project-away SubjectAlternativeName, _ResourceId
| join kind=inner PrivUsers on PrincipalName
```
