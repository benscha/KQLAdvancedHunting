# *Azure DevOps Critical Search Queries*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1552.004 | Private keys | https://attack.mitre.org/techniques/T1552/004/ |

#### Description
This Query detects suspicious code search queries within Azure DevOps audit logs that may indicate an adversary is attempting to find sensitive information such as passwords, API keys, tokens, or private keys. It specifically looks for keywords like 'password', 'secret', 'token', 'apikey', 'api_key', 'connectionstring', 'connstring', 'credential', 'private key', and 'BEGIN RSA PRIVATE KEY' in code search queries.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References

## Defender XDR
```KQL
// Detect suspicious code search queries (possible secret hunting)
ADOAuditLogs_CL
| where TimeGenerated > ago(7d)
| where ActionId == "Search.Code"
| extend d=parse_json(Data)
| extend SearchQuery=tostring(d.SearchQuery)
| where SearchQuery matches regex @"(?i)(password|passwd|secret|token|apikey|api_key|connectionstring|connstring|credential|private key|BEGIN RSA PRIVATE KEY)"

```
