# *BiDi Swap URL in DeviceNetworkEvents*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1036.002 | Right-to-Left Override | https://attack.mitre.org/techniques/T1036/002/ |
| TA1001 | Data Obfuscation | https://attack.mitre.org/techniques/T1001/ |

#### Description

This rule detects the presence of percent-encoded Bi-Directional (BiDi) control characters in URLs within network events. Specifically, it looks for '%E2%80%AE' (Right-to-Left Override - RLO), '%E2%80%8E' (Left-to-Right Mark - LRM), and '%E2%80%8F' (Right-to-Left Mark - RLM). These characters can be used to obfuscate URLs, making malicious links appear benign to users and potentially bypass security controls.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- https://www.bleepingcomputer.com/news/security/bidi-swap-the-bidirectional-text-trick-that-makes-fake-urls-look-real/


## Defender XDR
```KQL
//BiDi Swap Detection
let bidi_chars = dynamic(['%E2%80%AE', '%E2%80%8E', '%E2%80%8F']);
// Die wichtigsten BiDi-Zeichen sind RLO (%E2%80%AE), RLM (%E2%80%8F) und LRM (%E2%80%8E).
// Die Liste oben deckt die gängigsten Bidi-Kontroll- und nicht-druckbaren Steuerzeichen ab (U+2000 bis U+206F).
DeviceNetworkEvents
| where isnotempty(RemoteUrl)
// Suche nach den prozentkodierten BiDi-Zeichen in der URL
| where RemoteUrl has_any (bidi_chars)
| project Timestamp, DeviceName, DeviceId, RemoteUrl, ActionType, InitiatingProcessFileName, RemoteIP, RemotePort, ReportId
| extend Bidi_Character_Found = extract_all(@"(%E2%80%AE|%E2%80%8E|%E2%80%8E)", RemoteUrl)

```
