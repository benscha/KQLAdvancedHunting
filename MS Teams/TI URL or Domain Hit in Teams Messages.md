# *MS Teams Threat Intelligence Indicator Hit for Domain or URL*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566 | Phishing | https://attack.mitre.org/techniques/T1556 |


#### Description
This rule detects when a domain or URL observed in Teams Messages matches a known threat intelligence indicator from Microsoft Defender Threat Intelligence. It specifically looks for hits against 'Domain' and 'URL' type indicators.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- KQL Cafe 2025.11.24 Session of Daniel Mozes https://kqlcafe.com/#2025


## Defender XDR
```KQL
// Extract IOC details from ThreatIntelIndicators export
let IOC = ThreatIntelIndicators
| where SourceSystem == "Microsoft Defender Threat Intelligence"
| extend IOCType = case(
    ObservableKey has "ipv4" or ObservableKey has "network-traffic", "IP Address",
    ObservableKey has "domain", "Domain",
    ObservableKey has "url", "URL",
    ObservableKey has "file", "File Hash",
    ObservableKey has "email", "Email Address",
    "Other")
| extend IOCValue = ObservableValue
| extend Pattern = tostring(split(Pattern, "=")[1]) // Extract value from STIX pattern if needed
| extend Description = tostring(parse_json(Data).description)
| extend IndicatorTypes = tostring(parse_json(Data).indicator_types)
| extend ValidFrom = todatetime(parse_json(Data).valid_from)
| extend ValidUntil = todatetime(parse_json(Data).valid_until)
| project TimeGenerated, IOCType, IOCValue, Pattern, Description, IndicatorTypes, ValidFrom, ValidUntil, Confidence
| order by TimeGenerated desc;
let IOCDomain = IOC
| where IOCType == "Domain";
let IOCUrl = IOC
| where IOCType == "URL";
let URLHits = MessageUrlInfo
| join IOCUrl on $left.Url == $right.IOCValue;
let DomainHits = MessageUrlInfo
| join IOCDomain on $left.UrlDomain == $right.IOCValue;
URLHits
| union DomainHits
| join kind=inner MessageEvents on TeamsMessageId
```
