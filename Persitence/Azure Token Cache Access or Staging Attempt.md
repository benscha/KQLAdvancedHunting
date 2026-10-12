# *Azure Token Cache Access or Staging Attempt*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1539 | Steal Web Session Cookie | https://attack.mitre.org/techniques/T1539 |
| T1005 | Data from Local System | https://attack.mitre.org/techniques/T1005 |
| T1560 | Archive Collected Data | https://attack.mitre.org/techniques/T1560 |

#### Description

Detects process command lines attempting to copy, read, or archive Azure token caches, configuration files, or broker plugin data (such as msal_token_cache, azurermcontext.json, accesstokens.json) using utilities like PowerShell, Robocopy, Xcopy, or archiving tools.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- BruCon Continuous Access Evasion Evading Microsoft CAE from Nikhil Mittal


## Defender XDR
```KQL
// Hunting rule: explicit attempts to copy, read, or archive Azure token caches.
// This is process-command-line telemetry, not proof of a successful cache read.
let lookback = 7d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where isnotempty(ProcessCommandLine)
| extend CommandLine = tolower(ProcessCommandLine)
| where
	(
		CommandLine contains "azurermcontext.json"
		or CommandLine contains "msal_token_cache"
		or CommandLine contains "accesstokens.json"
		or CommandLine contains "tokenbroker\\cache"
		or CommandLine contains "azure\\accounts"
		or CommandLine contains "microsoft.aad.brokerplugin"
	)
	and
	(
		CommandLine contains "copy-item"
		or CommandLine contains "compress-archive"
		or CommandLine contains "get-content"
		or CommandLine contains "readalltext"
		or CommandLine contains "readallbytes"
		or CommandLine contains "copy "
		or CommandLine contains "xcopy"
		or CommandLine contains "robocopy"
		or CommandLine contains "7z"
		or CommandLine contains "rar "
		or CommandLine contains "tar "
	)
| project
	Timestamp,
	DeviceName,
	DeviceId,
	AccountName,
	FileName,
	FolderPath,
	ProcessCommandLine,
	ProcessId,
	SHA1,
	InitiatingProcessFileName,
	InitiatingProcessCommandLine,
	InitiatingProcessParentFileName,
	ReportId
| order by Timestamp desc
```
