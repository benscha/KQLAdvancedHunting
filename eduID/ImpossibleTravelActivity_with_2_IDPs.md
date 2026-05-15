# *Impossible Travel Activity with 2 IDPs*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1078 | Valid Accounts | https://attack.mitre.org/techniques/T1078 |

#### Description

Target Audience Note: Please note that this query is not a generic, plug-and-play solution for every environment, as it is specifically designed for the Swiss higher education and research sector (NREN community) leveraging SWITCH eduID.
This KQL query detects "Impossible Travel Activity" by correlating and cross-referencing sign-in logs across two independent Identity Providers (IdPs), specifically Microsoft Entra ID and SWITCH eduID. By mapping a unified UPN and memory-caching historical IP data, it effectively eliminates cross-platform false positives. While tailored for the Swiss higher education and research sector, the logic serves as a template easily adaptable to other international NREN IDPs. The highly optimized query includes early IP filtering, late geolocation lookups, and precise velocity calculations to identify true anomalies.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**
- 

## Defender XDR
```KQL
let MaxSpeed = 800;
let TimeFrame = 24h;
let HistoryDays = 29d;
let KnownCIDRs = dynamic(["147.86.0.0/16"]);
let KnownHostingASNs = dynamic(["AS8075"]);
// Load raw data with time filter and early IP filter
let AllLogins = materialize(
    union 
        (SigninLogs
            | where TimeGenerated > ago(TimeFrame)
            | where isnotempty(IPAddress)
            | where not(ipv4_is_in_any_range(IPAddress, KnownCIDRs))
            | project TimeGenerated, UPN = UserPrincipalName, IP = IPAddress, Source = "EntraID",
                      UserAgent),
        (EduIdSuccesSignIns_CL
            | where TimeGenerated > ago(TimeFrame)
            | where isnotempty(client_address)
            | where not(ipv4_is_in_any_range(client_address, KnownCIDRs))
            | project TimeGenerated, username, IP = client_address, Source = "eduID",
                      UserAgent = user_agent
            | join kind=leftouter (
                EntraIDUsersMappings_CL
                | project username = EduIDIdentifier, UPN = userPrincipalName
              ) on username
            | project TimeGenerated, UPN, IP, Source, UserAgent)
    | where isnotempty(UPN)
    // Enrich with geo data only after filtering to reduce cost
    | extend GeoInfo = geo_info_from_ip_address(IP)
    | extend Lat = toreal(GeoInfo.latitude), Lon = toreal(GeoInfo.longitude),
             Country = tostring(GeoInfo.country), City = tostring(GeoInfo.city),
             ASN = tostring(GeoInfo.asn)
    | where isnotnull(Lat) and isnotnull(Lon)
    | where ASN !in (KnownHostingASNs)
);
// Detect impossible travel anomalies
let AnomalousLogins = materialize(
    AllLogins
    | sort by UPN asc, TimeGenerated asc
    | serialize 
    | extend prevTime = prev(TimeGenerated), 
             prevLat = prev(Lat), 
             prevLon = prev(Lon), 
             prevCity = prev(City),
             prevCountry = prev(Country),
             prevSource = prev(Source),
             prevIP = prev(IP),
             prevUserAgent = prev(UserAgent)
    | where UPN == prev(UPN)
    | where IP != prevIP
    | where not(Lat == prevLat and Lon == prevLon)
    | extend dist_meters = geo_distance_2points(Lon, Lat, prevLon, prevLat)
    | extend dist_km = dist_meters / 1000
    | extend time_diff_sec = datetime_diff('second', TimeGenerated, prevTime)
    | extend speed_kmh = (dist_km / time_diff_sec) * 3600
    | extend time_diff = strcat(
        tostring(time_diff_sec / 3600), "h ",
        tostring((time_diff_sec % 3600) / 60), "m ",
        tostring(time_diff_sec % 60), "s")
    | where speed_kmh > MaxSpeed and dist_km > 100
);
// Load historical IPs for affected users only (not the entire directory)
let AnomalousUPNs = AnomalousLogins | summarize by UPN;
let HistoricalEntraIPs = SigninLogs
    | where TimeGenerated > ago(HistoryDays)
    | where UserPrincipalName in (AnomalousUPNs)
    | where isnotempty(IPAddress)
    | summarize by UPN = UserPrincipalName, IP = IPAddress, Source = "EntraID";
let HistoricalEduIPs = EduIdSuccesSignIns_CL
    | where TimeGenerated > ago(HistoryDays)
    | where isnotempty(client_address)
    | join kind=inner AnomalousUPNs on $left.username == $right.UPN
    | summarize by UPN, IP = client_address, Source = "eduID";
// Build cross-IDP IP lookup table
// If an IP was seen on both IDPs within 29 days it is considered a known IP
let KnownCrossIDPIPs = union HistoricalEntraIPs, HistoricalEduIPs
    | summarize Sources = make_set(Source) by UPN, IP
    | project UPN, IP,
              SeenOnEntra = Sources has "EntraID",
              SeenOnEduID = Sources has "eduID";
// Enrich anomalies with cross-IDP history and apply risk scoring
AnomalousLogins
| join kind=leftouter KnownCrossIDPIPs on UPN, IP
| extend IsKnownCrossIP = case(
    // Current login via EntraID: was this IP seen on eduID in the last 29 days?
    Source == "EntraID" and SeenOnEduID == true, true,
    // Current login via eduID: was this IP seen on EntraID in the last 29 days?
    Source == "eduID" and SeenOnEntra == true, true,
    false)
| where IsKnownCrossIP == false
| where Source == "eduID" or prevSource == "eduID"
| extend UA     = parse_user_agent(UserAgent,     dynamic(["browser", "os", "device"]))
| extend prevUA = parse_user_agent(prevUserAgent, dynamic(["browser", "os", "device"]))
// Extract OS and browser details
| extend UA_OS           = tostring(UA.OperatingSystem.Family)
| extend UA_OSType       = case(UA.Device.IsMobile == "True", "Mobile", "Desktop")
| extend UA_Browser      = tostring(UA.Browser.Family)
| extend UA_BrowserVer   = toreal(UA.Browser.MajorVersion)
| extend prev_OS         = tostring(prevUA.OperatingSystem.Family)
| extend prev_OSType     = case(prevUA.Device.IsMobile == "True", "Mobile", "Desktop")
| extend prev_Browser    = tostring(prevUA.Browser.Family)
| extend prev_BrowserVer = toreal(prevUA.Browser.MajorVersion)
// Risk scoring based on user agent changes
| extend Score_MobileBrowserChange = case(
    // Different browser on same mobile OS (version upgrades excluded)
    UA_OSType == "Mobile" and prev_OSType == "Mobile"
    and UA_OS == prev_OS
    and UA_Browser != prev_Browser,
    5, 0)
| extend Score_MobileOSChange = case(
    // Switch between different mobile OS families (e.g. Android to iOS)
    UA_OSType == "Mobile" and prev_OSType == "Mobile"
    and UA_OS != prev_OS,
    8, 0)
| extend Score_DesktopBrowserChange = case(
    // Different browser on same desktop OS
    UA_OSType == "Desktop" and prev_OSType == "Desktop"
    and UA_OS == prev_OS
    and UA_Browser != prev_Browser,
    8, 0)
| extend Score_DesktopOSChange = case(
    // Different desktop OS
    UA_OSType == "Desktop" and prev_OSType == "Desktop"
    and UA_OS != prev_OS,
    12, 0)
| extend Score_MobileBrowserDowngrade = case(
    // Lower browser version on same mobile OS (potential spoofing indicator)
    UA_OSType == "Mobile" and prev_OSType == "Mobile"
    and UA_OS == prev_OS
    and UA_Browser == prev_Browser
    and UA_BrowserVer < prev_BrowserVer,
    15, 0)
| extend Score_DesktopBrowserDowngrade = case(
    // Lower browser version on same desktop OS (potential spoofing indicator)
    UA_OSType == "Desktop" and prev_OSType == "Desktop"
    and UA_OS == prev_OS
    and UA_Browser == prev_Browser
    and UA_BrowserVer < prev_BrowserVer,
    15, 0)
| extend RiskScore = Score_MobileBrowserChange
                   + Score_MobileOSChange
                   + Score_DesktopBrowserChange
                   + Score_DesktopOSChange
                   + Score_MobileBrowserDowngrade
                   + Score_DesktopBrowserDowngrade
| extend Severity = case(
    RiskScore >= 20, "Critical",
    RiskScore >= 15, "High",
    RiskScore >= 8,  "Medium",
    RiskScore >= 5,  "Low",
    "Informational")
| where RiskScore >= 10
| project-away UserAgent, prevUserAgent
| project TimeGenerated, prevTime, UPN, IP, prevIP, Source, prevSource,
          UA_OSType, UA_OS, UA_Browser, UA_BrowserVer,
          prev_OSType, prev_OS, prev_Browser, prev_BrowserVer,
          RiskScore,
          Score_MobileBrowserChange, Score_MobileOSChange,
          Score_DesktopBrowserChange, Score_DesktopOSChange,
          Score_MobileBrowserDowngrade, Score_DesktopBrowserDowngrade,
          Country, prevCountry, City, prevCity,
          dist_km, time_diff, speed_kmh, SeenOnEntra, SeenOnEduID, IsKnownCrossIP

```
