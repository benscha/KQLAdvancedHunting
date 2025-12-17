# *Parse Apache Access*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |



#### Description
This KQL query parses raw Apache access.log entries stored in the accesslog table. It uses regular expressions to extract key fields from each log line, such as ClientIP, Ident, User, Timestamp, HTTP Method, URL, Protocol, Status Code, Bytes Sent, Referer, and User-Agent. After extracting these values, the query removes the original raw data column and presents the parsed fields in a structured table format for easier analysis.
#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References

## Azure Data Explorer

### Query Combination Devices with no AV Scans and Vulnerabilities
```KQL
accesslog
| extend
    ClientIP  = extract(@"^(\S+)", 1, data),
    Ident     = extract(@"^\S+\s+(\S+)", 1, data),
    User      = extract(@"^\S+\s+\S+\s+(\S+)", 1, data), 
    TimeRaw   = extract(@"\[(.*?)\]", 1, data),
    Method    = extract(@"""(\S+)", 1, data),
    Url       = extract(@"""\S+\s+(\S+)", 1, data),
    Protocol  = extract(@"""\S+\s+\S+\s+(\S+)""", 1, data),
    Status    = toint(extract(@"""\s+(\d{3})\s", 1, data)),
    Bytes     = toint(extract(@"\s(\d+|-)\s+""", 1, data)),
    Referer   = extract(@"""\s+""([^""]*)""\s+""", 1, data),
    UserAgent = extract(@"""\s+""([^""]*)""$", 1, data)
| project-away data
```

