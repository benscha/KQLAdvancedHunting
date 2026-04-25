# *SessionIds from multiple OS and UserAgents (Token Theft / Session Hijack Detection)*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1111 | Multi-Factor Authentication Interception | https://attack.mitre.org/techniques/T1111 |
| T1133 | External Remote Services | https://attack.mitre.org/techniques/T1133/ |

#### Description

This rule detects impossible travel scenarios where a single user session (identified by SessionId) exhibits sign-ins from multiple distinct IP addresses, coupled with changes in the operating system or browser family within a short timeframe (1 hour). This behavior is highly indicative of an attacker compromising a user's credentials and attempting to access resources from different locations or devices, potentially bypassing multi-factor authentication or session-based controls.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
// thx to my ♥ Buddy Sergio Albea for the wonderful ASN Part from this Query
let CIDRASN = (externaldata (CIDR:string, CIDRASN:int, CIDRASNName:string)
['https://firewalliplists.gypthecat.com/lists/kusto/kusto-cidr-asn.csv.zip']
with (ignoreFirstRecord=true));
EntraIdSignInEvents
| where TimeGenerated > ago(12h)
| where isnotempty(SessionId)
| where UserAgent !contains "node-fetch"
// Wir rufen die Funktion zweimal auf, um die zwei benötigten Dimensionen zu erhalten
| extend OS = tostring(parse_user_agent(UserAgent, "os").OperatingSystemFamily)
| extend Browser = tostring(parse_user_agent(UserAgent, "browser").BrowserFamily)
| evaluate ipv4_lookup(CIDRASN, IPAddress, CIDR, return_unmatched=true)
| summarize 
    OSFamilyCount = dcount(OS),
    BrowserFamilyCount = dcount(Browser),
    IPAddressCount = dcount(IPAddress),
    ASNCount = dcount(CIDRASNName),
    IPAddressList = make_set(IPAddress),
    ASNNameList = make_set(CIDRASNName),
    UserAgentList = make_set(UserAgent),
    UserPrincipalNames = make_set(AccountUpn) 
    by SessionId
| where IPAddressCount > 1 
| where OSFamilyCount > 1 or BrowserFamilyCount > 1
```
