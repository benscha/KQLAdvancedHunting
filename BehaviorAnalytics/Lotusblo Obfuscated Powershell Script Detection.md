# *Lotusblo Obfuscated Powershell Script Detection*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.001 | Powershell | https://attack.mitre.org/techniques/T1059/001/ |
| T1027 | Obfuscated Files or Information | https://attack.mitre.org/techniques/T1027/ |

#### Description

This rule detects suspicious, obfuscated PowerShell commands by analyzing the command line for long string literals with low character diversity and high frequency of a single character. It extracts strings enclosed in single quotes, double quotes, or backticks, and then calculates the ratio of distinct characters to total length and the ratio of the most frequent character's count to total length. If these ratios fall below and above certain thresholds, respectively, the command is flagged as suspicious.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- https://www.cyberproof.com/blog/fileless-remcos-attacks-on-the-rise/


## Defender XDR
```KQL
// EXPERIMENTAL
// Searches for suspicious, obfuscated PowerShell commands
// Based on the PowerShell command in this report: https://www.cyberproof.com/blog/fileless-remcos-attacks-on-the-rise/
DeviceProcessEvents
| where InitiatingProcessFileName =~ "powershell.exe"
| extend CommandLine = tolower(ProcessCommandLine) 
| where strlen(CommandLine) > 100
// Find string literals with different types of quotation marks
| extend SingleQuoteStrings = extract_all(@"'([^']{20,})'", CommandLine)
| extend DoubleQuoteStrings = extract_all("\"([^\"]{20,})\"", CommandLine)
| extend BacktickStrings = extract_all(@"`([^`]{20,})`", CommandLine)
// Combine all extracted strings
| extend AllStrings = array_concat(SingleQuoteStrings, DoubleQuoteStrings, BacktickStrings)
| where array_length(AllStrings) > 0
// Expand each extracted string literal
| mv-expand SuspiciousString = AllStrings to typeof(string)
| where isnotempty(SuspiciousString)
| extend TotalLength = strlen(SuspiciousString)
| where TotalLength > 20
// Create an index for every character in the string
| mv-apply Index = range(0, TotalLength - 1, 1) on (
    project Character = substring(SuspiciousString, toint(Index), 1)
)
// Count how often each character occurs
| summarize CharFrequency = count() 
    by DeviceId, Timestamp, Character, TotalLength, TimeGenerated, DeviceName, CommandLine, SuspiciousString, ReportId
// Find the maximum frequency and number of unique characters
| summarize 
    DistinctChars = dcount(Character),
    MostFrequentCharCount = max(CharFrequency),
    TotalLength = any(TotalLength),
    TimeGenerated = any(TimeGenerated),
    DeviceName = any(DeviceName),
    CommandLine = any(CommandLine),
    ReportId = any(ReportId)
    by DeviceId, Timestamp, SuspiciousString
// Calculate ratios
| extend Ratio_Diversity_Total = todouble(DistinctChars) / TotalLength 
| extend Ratio_Junk_Total = todouble(MostFrequentCharCount) / TotalLength 
// Apply threshold values for detection
| where Ratio_Diversity_Total < 0.38 // lower value = more aggressive detection
| where Ratio_Junk_Total > 0.25 // lower value = more aggressive detection
| project TimeGenerated, DeviceId, DeviceName, ReportId, CommandLine, SuspiciousString, TotalLength, DistinctChars, MostFrequentCharCount, Ratio_Diversity_Total, Ratio_Junk_Total
| sort by Ratio_Junk_Total desc
```
