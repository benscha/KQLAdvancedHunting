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

after sleeping one night over my Query i had the Idea to extend the Timeframe. Be careful with adjusting the Timeframe due to ressources limit

<img width="948" height="139" alt="image" src="https://github.com/user-attachments/assets/df69d8e7-406a-48c4-bf12-9957c0dbf0aa" />


```KQL
let CIDRASN = materialize(externaldata (CIDR:string, CIDRASN:int, CIDRASNName:string)
    ['https://firewalliplists.gypthecat.com/lists/kusto/kusto-cidr-asn.csv.zip']
    with (ignoreFirstRecord=true));
let SuspiciousSessions = materialize(
    EntraIdSignInEvents
    | where TimeGenerated > ago(3d)
    | where isnotempty(SessionId)
    | where UserAgent !contains "node-fetch"
    | project SessionId, IPAddress, UserAgent, AccountUpn
    | extend UA = parse_user_agent(UserAgent, dynamic(["os", "browser"]))
    | extend OS = tostring(UA.OperatingSystemFamily), Browser = tostring(UA.BrowserFamily)
    | project-away UA
    | summarize hint.shufflekey=SessionId
        OSFamilyCount      = dcount(OS),
        BrowserFamilyCount = dcount(Browser),
        IPAddressCount     = dcount(IPAddress),
        IPAddressList      = make_set(IPAddress, 50),
        UserAgentList      = make_set(UserAgent, 10),
        UserPrincipalNames = make_set(AccountUpn, 20)
        by SessionId
    | where IPAddressCount > 1
    | where OSFamilyCount > 1 or BrowserFamilyCount > 1
);
let IPtoASN = materialize(
    SuspiciousSessions
    | mv-expand IPAddress = IPAddressList to typeof(string)
    | distinct IPAddress
    | evaluate ipv4_lookup(CIDRASN, IPAddress, CIDR, return_unmatched=true)
    | summarize ASNNames = make_set(CIDRASNName, 20) by IPAddress
);
SuspiciousSessions
| mv-expand IPAddress = IPAddressList to typeof(string)
| join kind=leftouter IPtoASN on IPAddress
| summarize hint.shufflekey=SessionId
    ASNCount       = dcount(tostring(ASNNames)),
    ASNNameList    = make_set(ASNNames, 50),
    IPAddressList  = make_set(IPAddress, 50),
    UserAgentList  = take_any(UserAgentList),
    UserPrincipalNames = take_any(UserPrincipalNames)
    by SessionId, IPAddressCount, OSFamilyCount, BrowserFamilyCount
```
