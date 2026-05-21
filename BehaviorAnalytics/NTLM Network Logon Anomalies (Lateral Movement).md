# *NTLM Network Logon Anomalies (Lateral Movement)*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1021 | Remote Services | https://attack.mitre.org/techniques/T1021/ |
| T1078 | Valid Accounts | https://attack.mitre.org/techniques/T1078/ |

#### Description

This rule detects anomalous NTLM network logon activity that could indicate lateral movement within an environment. It identifies accounts performing successful NTLM network logons to multiple devices within a short timeframe, especially when the activity significantly exceeds a historical baseline for that account. The rule filters out service accounts and specific excluded servers to reduce noise.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let ExcludedServer = dynamic(["YOUREXLUDEDSERVER"]); //SCCM Server
let lookback = 1d;
let knownServiceAccounts = dynamic(["svc-backup", "healthservice", "svc-scan"]);
let baseline = DeviceLogonEvents
    | where TimeGenerated between (ago(14d) .. ago(7d))
    | where LogonType == "Network" and Protocol == "NTLM"
    | where AccountName !endswith "$"
    | summarize BaselineDevices = dcount(DeviceName) by AccountName;
DeviceLogonEvents
| where TimeGenerated > ago(lookback)
| where LogonType == "Network"
| where Protocol == "NTLM"
| where ActionType == "LogonSuccess"
| where AccountName !endswith "$"
| where AccountName !in (knownServiceAccounts)
| where AccountName !startswith "svc-"
| where AccountName != "ANONYMOUS LOGON"
| where DeviceName !in (ExcludedServer)
| where isnotempty(AccountName)
| summarize
    DeviceCount    = dcount(DeviceName),
    Devices        = make_set(DeviceName, 10),
    FirstLogon     = min(TimeGenerated),
    LastLogon      = max(TimeGenerated),
    LogonCount     = count()
    by AccountName, AccountDomain
| where DeviceCount >= 2
| extend TimeSpanMin = datetime_diff('minute', LastLogon, FirstLogon)
| extend DevicesPerHour = round(toreal(DeviceCount) / (toreal(TimeSpanMin) / 60.0 + 1), 1)
| join kind=leftouter baseline on AccountName
| extend BaselineDevices = coalesce(BaselineDevices, 0)
| where DeviceCount > BaselineDevices * 1.5 or BaselineDevices == 0
| extend RiskLevel = case(
    DeviceCount >= 3 and TimeSpanMin < 30, "CRITICAL - Rapid Wide Movement",
    DeviceCount >= 5,                      "HIGH - Wide Movement",
    TimeSpanMin < 30,                      "CRITICAL - Rapid Movement",
    DeviceCount >= 2,                      "MEDIUM - Possible Lateral Movement",
    "LOW")
| where DevicesPerHour > 2
| project AccountName, AccountDomain, DeviceCount, BaselineDevices,
          DevicesPerHour, TimeSpanMin, RiskLevel, Devices, FirstLogon, LastLogon
| order by DeviceCount desc, TimeSpanMin asc
```
