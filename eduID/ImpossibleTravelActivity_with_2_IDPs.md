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
// Schritt 1: Rohdaten mit Zeitfilter und frühem IP-Filter laden
let AllLogins = materialize(
    union 
        (SigninLogs
            | where TimeGenerated > ago(TimeFrame)          // ← Zeitfilter zuerst!
            | where isnotempty(IPAddress)
            | where not(ipv4_is_in_any_range(IPAddress, KnownCIDRs))  // ← früh filtern
            | project TimeGenerated, UPN = UserPrincipalName, IP = IPAddress, Source = "EntraID"),
        (EduIdSuccesSignIns_CL
            | where TimeGenerated > ago(TimeFrame)          // ← Zeitfilter zuerst!
            | where isnotempty(client_address)
            | where not(ipv4_is_in_any_range(client_address, KnownCIDRs))  // ← früh filtern
            | project TimeGenerated, username, IP = client_address, Source = "eduID"
            | join kind=leftouter (
                EntraIDUsersMappings_CL             // Mapping-Tabelle separat
                | project username = EduIDIdentifier, UPN = userPrincipalName
              ) on username
            | project TimeGenerated, UPN, IP, Source)
    | where isnotempty(UPN)
    // Geo erst NACH den Filtern aufrufen
    | extend GeoInfo = geo_info_from_ip_address(IP)
    | extend Lat = toreal(GeoInfo.latitude), Lon = toreal(GeoInfo.longitude),
             Country = tostring(GeoInfo.country), City = tostring(GeoInfo.city),
             ASN = tostring(GeoInfo.asn)
    | where isnotnull(Lat) and isnotnull(Lon)
    | where ASN !in (KnownHostingASNs)
);
// Schritt 2: Anomalien detektieren
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
             prevIP = prev(IP)
    | where UPN == prev(UPN)
    | where IP != prevIP
    | where not(Lat == prevLat and Lon == prevLon)
    | extend dist_meters = geo_distance_2points(Lon, Lat, prevLon, prevLat)
    | extend dist_km = dist_meters / 1000
    | extend time_diff_sec = datetime_diff('second', TimeGenerated, prevTime)
        | extend speed_kmh = (dist_km / time_diff_sec) * 3600   // ← mit _sec rechnen
        | extend time_diff = strcat(                             // ← danach formatieren
            tostring(time_diff_sec / 3600), "h ",
            tostring((time_diff_sec % 3600) / 60), "m ",
            tostring(time_diff_sec % 60), "s")
    | where speed_kmh > MaxSpeed and dist_km > 100
    | extend speed_kmh = (dist_km / time_diff_sec) * 3600
    | where speed_kmh > MaxSpeed and dist_km > 100
);
// Schritt 3: Historische IPs NUR für betroffene User
let AnomalousUPNs = AnomalousLogins | summarize by UPN;
let HistoricalEntraIPs = SigninLogs
    | where TimeGenerated > ago(HistoryDays)
    | where UserPrincipalName in (AnomalousUPNs)        // ← früher Filter auf UPN
    | where isnotempty(IPAddress)
    | summarize by UPN = UserPrincipalName, IP = IPAddress, Source = "EntraID";  // ← summarize statt project (Deduplizierung)
let HistoricalEduIPs = EduIdSuccesSignIns_CL
    | where TimeGenerated > ago(HistoryDays)
    | where isnotempty(client_address)
    | join kind=inner AnomalousUPNs on $left.username == $right.UPN
    | summarize by UPN, IP = client_address, Source = "eduID";  // ← summarize statt project
// Schritt 4: Cross-IDP Lookup aufbauen
let KnownCrossIDPIPs = union HistoricalEntraIPs, HistoricalEduIPs
    | summarize Sources = make_set(Source) by UPN, IP
    | project UPN, IP,
              SeenOnEntra = Sources has "EntraID",
              SeenOnEduID = Sources has "eduID";
// Schritt 5: Anomalien filtern
AnomalousLogins
| join kind=leftouter KnownCrossIDPIPs on UPN, IP
| extend IsKnownCrossIP = case(
    Source == "EntraID" and SeenOnEduID == true, true,
    Source == "eduID" and SeenOnEntra == true, true,
    false)
| where IsKnownCrossIP == false
| where Source == "eduID" or prevSource == "eduID"
| project TimeGenerated, prevTime, UPN, IP, prevIP, Source, prevSource, Country, prevCountry, City, prevCity, dist_km, time_diff, speed_kmh, SeenOnEntra, SeenOnEduID, IsKnownCrossIP

```
