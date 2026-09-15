# *Suspicious Collection of AI Assistant Session Data*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1005 | Data from Local System | https://attack.mitre.org/techniques/T1005 |
| T1083 | File and Directory Discovery | https://attack.mitre.org/techniques/T1083 |
| T1552.001 | Unsecured Credentials: Credentials In Files | https://attack.mitre.org/techniques/T1552/001/ |

#### Description

Detects non-AI assistant processes accessing sensitive Claude Code, Cursor, Continue, Aider, Codeium, or Windsurf data paths. The query prioritizes explicit file collection actions, secret-focused searches, recursive enumeration, and access to another user's AI assistant data while suppressing known Claude Code and shared development environment activity. 

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- https://www.linkedin.com/posts/mauricefielenbach_threatintel-dfir-cybersecurity-share-7468712997298016256-Rs6h/?utm_source=social_share_send&utm_medium=ios_app&rcm=ACoAAA3PxAIBcfr6M0unx3xMtHTyCNuehMi3uNQ thx to Maurice Fielenbach

## Defender XDR
```KQL
let LookbackTime = 7d;
let AiToolSensitivePaths = @'\.claude[\\\/](projects|todos|history)[\\\/]|\.claude\.json\b|\.cursor[\\\/](chats|history)[\\\/]|\.continue[\\\/](sessions|history)[\\\/]|\.aider\.chat\.history|\.codeium[\\\/]history[\\\/]|\.windsurf[\\\/]chats[\\\/]';
let ClaudeBootstrap = @'\.claude[\\\/]shell-snapshots[\\\/]snapshot-[a-zA-Z0-9_-]+\.sh';
let ClaudeTemporaryDirectory = @'(?:/private)?/tmp/claude-[a-zA-Z0-9_-]+';
let HomeDirectoryUser = @'(?:[A-Za-z]:\\Users\\|/Users/|/home/)([^\\/"]+)';
let RecursiveEnumeration = @'(-Recurse|-r\b|find\s+\S+\s+-type)';
let SecretKeywords = @'(api[_-]?key|apikey|password|pwd\b|secret|token|auth|credential|cred\b|private[_-]?key|privkey|pkey|access[_-]?key|accesskey|client[_-]?secret|bearer)';
let SearchTool = @'(Select-String|findstr|grep|ripgrep|\brg\b|-Pattern)';
let CollectionAction = @'(Get-Content|\bgc\b|Copy-Item|\bcat\b|\bcp\b|\btype\b|\bcopy\b|Compress-Archive|\btar\b|\bzip\b)';
let AllowlistProcesses = dynamic(["claude.exe", "claude", "code.exe", "msmpeng.exe", "searchindexer.exe", "searchprotocolhost.exe"]);
DeviceProcessEvents
| where TimeGenerated >= ago(LookbackTime)
| extend CleanedCmd = replace_regex(ProcessCommandLine, ClaudeBootstrap, "")
| where CleanedCmd matches regex AiToolSensitivePaths
| where InitiatingProcessFileName !in~ (AllowlistProcesses) and InitiatingProcessParentFileName !in~(AllowlistProcesses) and InitiatingProcessCommandLine !in~(AllowlistProcesses)
| where FileName !in~ (AllowlistProcesses)
| extend HasClaudeTemporaryDirectory = InitiatingProcessCommandLine matches regex ClaudeTemporaryDirectory
| extend IsClaudeCodeWrapper = ProcessCommandLine matches regex ClaudeBootstrap or HasClaudeTemporaryDirectory
| extend PathOwner = tolower(extract(HomeDirectoryUser, 1, CleanedCmd))
| extend AccountNameLower = tolower(AccountName)
| extend AccountLocalPart = tolower(tostring(split(AccountName, "@")[0]))
| extend InitiatingAccountNameLower = tolower(InitiatingProcessAccountName)
| extend PathOwnerMismatch = isnotempty(PathOwner) and isnotempty(AccountNameLower) and PathOwner != AccountNameLower and PathOwner != AccountLocalPart
| extend HasInitiatingAccountMismatch = isnotempty(InitiatingAccountNameLower) and isnotempty(AccountNameLower) and InitiatingAccountNameLower != AccountNameLower
// Exclude known WSL/remote development identities and shared profiles to avoid expected access being treated as a user mismatch.
| where AccountName != "wslg" and PathOwner !in~ ("vscode", "codespace")
| where not(IsClaudeCodeWrapper and not(PathOwnerMismatch))
| extend HasRecursiveEnumeration = CleanedCmd matches regex RecursiveEnumeration
| extend HasSecretKeyword = CleanedCmd matches regex SecretKeywords
| extend HasSearchTool = CleanedCmd matches regex SearchTool
| extend HasCollectionAction = CleanedCmd matches regex CollectionAction
| extend IsHighConfidence = PathOwnerMismatch or (HasCollectionAction and (HasSecretKeyword or HasSearchTool or HasRecursiveEnumeration)) or (HasSecretKeyword and HasSearchTool and HasRecursiveEnumeration)
| where IsHighConfidence
| extend RiskScore =
	(iff(HasCollectionAction, 3, 0)) +
	(iff(HasSecretKeyword, 2, 0)) +
	(iff(HasSearchTool, 1, 0)) +
	(iff(HasRecursiveEnumeration, 1, 0)) +
	(iff(PathOwnerMismatch, 4, 0)) +
	(iff(HasInitiatingAccountMismatch, 1, 0))
| extend Verdict = strcat(
	iff(PathOwnerMismatch, "Access to another user's AI assistant data", "Non-AI tool process accessing a sensitive AI assistant path"),
	iff(HasCollectionAction, " | File read, copy, or archive action", ""),
	iff(HasSecretKeyword, " | Secret keyword in command", ""),
	iff(HasSearchTool, " | Pattern search (Select-String/grep/findstr)", ""),
	iff(HasRecursiveEnumeration, " | Recursive directory enumeration", "")
	)
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessAccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, PathOwner, PathOwnerMismatch, HasInitiatingAccountMismatch, IsClaudeCodeWrapper, HasCollectionAction, RiskScore, Verdict
| order by RiskScore desc, TimeGenerated desc
```
