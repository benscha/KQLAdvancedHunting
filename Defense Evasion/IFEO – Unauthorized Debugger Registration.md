# *IFEO – Unauthorized Debugger Registration*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1562.012 | Disable or Modify Linux Audit System | https://attack.mitre.org/techniques/T1562/012/ |


#### Description
This rule detects the modification or creation of a 'Debugger' value within the 'Image File Execution Options' (IFEO) registry key, which can be abused for persistence or defense evasion. It flags instances where the configured debugger is not part of a predefined list of known legitimate debuggers.

#### Risk
Defense Evasion

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- https://www.linkedin.com/posts/mauricefielenbach_threatintel-threathunting-dfir-share-7440844391843319808-RttM/

## Defender XDR
```KQL
// Bases on a Linkedin Post of Maurice Fielenbach. thx for your great Content 🤘
// List of known and legitimate debuggers
let AllowedDebuggers = dynamic([
    "vsjitdebugger.exe",
    "WerFault.exe",
    "procexp.exe",
    "devenv.exe",
    "windbg.exe",
    "ntsd.exe",
    "cdb.exe"
]);
DeviceRegistryEvents
// Most selective filter first
| where RegistryValueName =~ "Debugger"
| where ActionType in~ ("RegistryValueSet", "RegistryKeyCreated")
// Use contains instead of has for path matching
| where RegistryKey contains @"\Image File Execution Options\"
// Extract the affected program from the registry path
| extend TargetExecutable = tostring(split(RegistryKey, '\\')[-1])
| where isnotempty(TargetExecutable)
// Extract and normalize the debugger filename for robust comparison
| extend MaliciousDebugger = RegistryValueData
| extend DebuggerFileName = trim('"', tostring(split(MaliciousDebugger, '\\')[-1]))
| extend DebuggerFileName = tostring(split(DebuggerFileName, ' ')[0])
// Filter out legitimate debuggers
| where DebuggerFileName !in~ (AllowedDebuggers)
| project
    Timestamp,
    DeviceName,
    ActionType,
    TargetExecutable,
    MaliciousDebugger,
    DebuggerFileName,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    RegistryKey
| sort by Timestamp desc
```
