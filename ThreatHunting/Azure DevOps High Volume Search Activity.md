# *Azure DevOps High Volume Search Activity*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1526 | Cloud Service Discovery | https://attack.mitre.org/techniques/T1526 |
| T1550.001 | Use Alternate Authentication Material: Application Access Token | https://attack.mitre.org/techniques/T1550/001 |

#### Description

Detects unusually high volumes of search activity within Azure DevOps by a single user from a specific IP address and user agent within a defined time window. This could indicate an adversary attempting to enumerate project details, source code, or other sensitive information.


#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### Possible false positives
- Legitimate administrative tasks involving extensive searching.
- Automated scripts or integrations performing numerous queries.
- Users conducting legitimate, in-depth research or investigations within Azure DevOps.

## Defender XDR
```KQL
let CorporateIPRange = "xx.xx.0.0/16";
// Threshold for the minimum number of search queries within the time window
let Threshold = 20;
// Time window size for aggregating search activities (e.g., 20 minutes)
let Window = 20m;
// Target table for Azure DevOps Audit Logs (Custom Log)
ADOAuditLogs_CL
// Filter for search-related activities in either the ActionId or Area fields
| where ActionId has "Search" or Area =~ "Search"
// Extract the actual search query string from the JSON payload in the 'Data' column
| extend SearchQuery = tostring(parse_json(Data).SearchQuery)
// Aggregate data by user (ActorUPN), source IP, UserAgent, and the defined time window buckets
| summarize 
    StartTime = min(TimeGenerated),        // Timestamp of the first search in this window
    EndTime = max(TimeGenerated),          // Timestamp of the last search in this window
    TotalCount = count(),                  // Total number of search requests executed
    UniqueQueries = dcount(SearchQuery),   // Count of distinct search terms used
    QueryList = make_set(SearchQuery)      // Array containing the unique search terms
    by bin(TimeGenerated, Window), ActorUPN, IpAddress, UserAgent
// Alert trigger: Only keep records that meet or exceed the defined threshold
| where TotalCount >= Threshold
// use this Filter for noise reduction
//| where not(ipv4_is_in_range( IpAddress, (CorporateIPRange))) 
```
