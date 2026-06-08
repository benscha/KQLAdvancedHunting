# *HEX and XOR Obfuscated Powershell ClickFix Attack*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.001 | PowerShell | https://attack.mitre.org/techniques/T1059/001/ |
| T1027 | Obfuscated Files or Information | https://attack.mitre.org/techniques/T1027 |
| T1140 | Deobfuscate/Decode Files or Information | https://attack.mitre.org/techniques/T1140 |
| T1204.001 | User Execution: Malicious Link | https://attack.mitre.org/techniques/T1204/001 |

#### Description

Shortly i've seen a ClickFix Variant with obfuscated Powershellcode This rule detects highly obfuscated PowerShell command-line executions that exhibit characteristics of XOR decryption, script block creation/execution, and potentially long hexadecimal payloads. It specifically looks for PowerShell processes initiated by common browser or system executables, which could indicate a user-driven execution of a malicious script. The rule assigns scores based on the presence of keywords and patterns related to XOR operations ('bxor', 'ToInt32', '[convert]', 'Substring'), script execution ('[ScriptBlock]::Create', 'IEX', 'Invoke-Expression'), and long hexadecimal strings, as well as suspicious parent processes. A high total score indicates a strong likelihood of malicious activity.


#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
// ClickFix - PowerShell Multi-Obfuscation Detection
// MITRE: T1059.001, T1027, T1140, T1204.001
let ClickFixParentProcesses = dynamic([
	"chrome.exe", "msedge.exe", "firefox.exe",
	"brave.exe", "opera.exe", "explorer.exe",
	"rundll32.exe", "mshta.exe", "wscript.exe", "cscript.exe"
]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
// --- XOR Decryption ---
| extend Score_XorDecryption =
	iff(ProcessCommandLine has "bxor", 3, 0) +
	iff(ProcessCommandLine has "ToInt32", 1, 0) +
	iff(ProcessCommandLine matches regex @"(?i)\[convert\]", 1, 0) +
	iff(ProcessCommandLine matches regex @"Substring\(.{0,20},\s*2", 2, 0)
// --- HEX Encoding ---
| extend Score_HexEncoding =
	// 0x41,0x42,... Style (Char-Array from Hex-Literals)
	iff(ProcessCommandLine matches regex @"0x[0-9a-fA-F]{2}(,0x[0-9a-fA-F]{2}){8,}", 3, 0) +
	// -f '0x{0:X2}' Format string trick
	iff(ProcessCommandLine matches regex @"(?i)-f\s*['""]0x\{", 2, 0) +
	// [char]0x41 Style
	iff(ProcessCommandLine matches regex @"(?i)\[char\]\s*0x[0-9a-fA-F]{2}", 2, 0) +
	// Long pure hex blob (e.g. from this sample)
	iff(ProcessCommandLine matches regex @"[0-9a-f]{300,}", 2, 0) +
	// \x41\x42 Style (Escape Sequences)
	iff(ProcessCommandLine matches regex @"(\\x[0-9a-fA-F]{2}){8,}", 2, 0)
// --- Base64 Encoding ---
| extend Score_Base64 =
	iff(ProcessCommandLine has "FromBase64String", 3, 0) +
	iff(ProcessCommandLine has_any ("-EncodedCommand", "-enc", "-ec"), 2, 0) +
	// Long Base64 string (Minimum length ~100 characters)
	iff(ProcessCommandLine matches regex @"[A-Za-z0-9+/]{100,}={0,2}", 2, 0)
// --- Execution Methods ---
| extend Score_Execution =
	iff(ProcessCommandLine has "[ScriptBlock]::Create", 3, 0) +
	iff(ProcessCommandLine matches regex @"\.\s*\(\s*\[ScriptBlock\]", 2, 0) +
	iff(ProcessCommandLine has_any ("IEX", "Invoke-Expression"), 2, 0) +
	iff(ProcessCommandLine has "Invoke-Command", 1, 0)
// --- Payload Indicators ---
| extend Score_Payload =
	iff(ProcessCommandLine matches regex @"[0-9a-f]{300,}", 2, 0) +
	iff(ProcessCommandLine matches regex @"(?i)(http|ftp)s?://", 2, 0) +
	iff(ProcessCommandLine has_any ("DownloadString", "DownloadFile", "WebClient", "Net.Http"), 2, 0)
// --- ClickFix Delivery Context ---
| extend Score_SuspiciousParent =
	iff(InitiatingProcessFileName has_any (ClickFixParentProcesses), 3, 0)
// --- Total Score ---
| extend TotalScore = Score_XorDecryption
					+ Score_HexEncoding
					+ Score_Base64
					+ Score_Execution
					+ Score_Payload
					+ Score_SuspiciousParent
// --- Obfuscation Method Tags (for Triage) ---
| extend ObfuscationMethods = strcat(
	iff(Score_XorDecryption >= 3, "XOR ", ""),
	iff(Score_HexEncoding   >= 2, "HEX ", ""),
	iff(Score_Base64		>= 3, "BASE64 ", ""),
	iff(Score_Payload	   >= 2, "PAYLOAD ", "")
)
// Threshold: Execution must always be present
// + at least one encoding method with Score >= 2
| where Score_Execution >= 3
	and (Score_XorDecryption >= 3 or Score_HexEncoding >= 2 or Score_Base64 >= 3)
	and TotalScore >= 8
| project
	Timestamp,
	DeviceName,
	AccountName,
	AccountDomain,
	InitiatingProcessFileName,
	InitiatingProcessCommandLine,
	ProcessCommandLine,
	SHA256,
	FolderPath,
	ObfuscationMethods,
	TotalScore,
	Score_XorDecryption,
	Score_HexEncoding,
	Score_Base64,
	Score_Execution,
	Score_Payload,
	Score_SuspiciousParent
| extend Severity = case(
	TotalScore >= 16, "High",
	TotalScore >= 10, "Medium",
	"Low"
)
| sort by TotalScore desc
```
