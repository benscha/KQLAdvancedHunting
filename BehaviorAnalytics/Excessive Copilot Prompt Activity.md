# *Excessive Copilot Prompt Activity*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |

#### Description

Detects when a user generates an unusually high number of prompts to Copilot within a short period (e.g., 50 prompts in an hour). This could indicate automated activity, data exfiltration attempts, or misuse of the Copilot service.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
CopilotActivity
| where RecordType == "CopilotInteraction"
| extend LLM = parse_json(LLMEventData)
| extend Messages = LLM.Messages
| mv-expand Messages
| where tostring(Messages.isPrompt) == "true"
| summarize PromptCount = count() by ActorName, bin(TimeGenerated, 1h)
| where PromptCount > 50        // adjust threshold
```
