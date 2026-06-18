# *Azure DevOps Token Administration Activity from Non-Corporate IP*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1528 | Steal Application Access Token | https://attack.mitre.org/techniques/T1528 |
| T1550.001 | Use Alternate Authentication Material: Application Access Token | https://attack.mitre.org/techniques/T1550/001 |

#### Description

This rule detects administrative activities related to tokens (Personal Access Tokens, Access Tokens, identity/security context) within Azure DevOps audit logs that originate from IP addresses outside of the defined corporate network range. This could indicate unauthorized access or suspicious activity related to credential management.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### Possible false positives
- Legitimate administrative actions performed by users working remotely or from non-corporate networks (e.g., home, public Wi-Fi) if the corporate IP range is not comprehensive.
- Third-party integrations or automated processes that manage tokens from external IP addresses.

## Defender XDR
```KQL
let CorporateIPRange = "xx.xx.0.0/16";
// Query audit logs for activities related to tokens (PATs, access tokens, identity/security context)
ADOAuditLogs_CL
| where Area in~ ("TokenAdmin", "TokenAdministration", "Security", "Identities") 
    or Details has "Access Token" 
    or Details has "Personal Access Token"
// Parse JSON payload for structured access to additional fields
| extend DataJson = parse_json(Data)
// Try to extract scopes if available; otherwise fall back to free text field (Filter)
| extend Scopes = coalesce(tostring(DataJson.Scopes), tostring(DataJson.Filter))
// Exclude events originating from trusted corporate network range
| where not(ipv4_is_in_range(IpAddress, (CorporateIPRange)))
```
