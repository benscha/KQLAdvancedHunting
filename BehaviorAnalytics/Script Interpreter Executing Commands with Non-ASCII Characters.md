# *Script Interpreter Executing Commands with Non-ASCII Characters*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1027 | Obfuscated Files or Information | https://attack.mitre.org/techniques/T1027/ |
| T1059 | Command and Scripting Interpreter | https://attack.mitre.org/techniques/T1059/ |

#### Description
This rule detects the execution of script interpreters (such as PowerShell, cmd, bash, python, etc.) where the command line contains non-ASCII characters, specifically Cyrillic, Arabic, or Chinese Unicode characters. This pattern can be indicative of obfuscation techniques used by adversaries to evade detection or to target specific region

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References

## Defender XDR
```KQL
let CyrillicChar = datatable (CyrillicCharacter: string)
[
    // (Uppercase)
    "А", "Б", "В", "Г", "Д", "Е", "Ё", "Ж", "З", "И", "Й", "К", "Л", "М", "Н", 
    "О", "П", "Р", "С", "Т", "У", "Ф", "Х", "Ц", "Ч", "Ш", "Щ", "Ъ", "Ы", "Ь", 
    "Э", "Ю", "Я",
    //  (Lowercase)
    "а", "б", "в", "г", "д", "е", "ё", "ж", "з", "и", "й", "к", "л", "м", "н", 
    "о", "п", "р", "с", "т", "у", "ф", "х", "ц", "ч", "ш", "щ", "ъ", "ы", "ь", 
    "э", "ю", "я"
];
let ArabicChar = datatable (ArabicCharacter: string)
[
    "ا",  "ب", "ت", "ث", "ج", "ح", "خ", "د", "ذ", "ر", "ز", "س", "ش", "ص", "ض", "ط", "ظ", "ع", "غ", "ف", "ق", "ك", "ل", "م", "ن", "ه", "و", "ي"
];
let ChineseunicodeChar = "[\u4e00-\u9fff]";
let ScriptInterpreter = datatable (OS: string, ScriptInterpreter: string)
[
    // macOS & Linux
    "macOS / Linux", "/bin/bash",
    "macOS / Linux", "/bin/sh",
    "macOS / Linux", "/bin/zsh",
    "macOS / Linux", "/usr/bin/python",
    "macOS / Linux", "/usr/bin/python3",
    "macOS / Linux", "/usr/bin/perl",
    "macOS / Linux", "/usr/bin/ruby",
    "macOS / Linux", "/usr/bin/osascript",
    "macOS / Linux", "/usr/bin/php",
    // Windows
    "Windows", "powershell.exe",
    "Windows", "pwsh.exe", // PowerShell Core
    "Windows", "cmd.exe",
    "Windows", "wscript.exe", // Windows Script Host 
    "Windows", "cscript.exe", // Windows Script Host 
    "Windows", "mshta.exe", // HTML Application Host 
    "Windows", "regsvr32.exe", 
    "Windows", "rundll32.exe"
];
DeviceProcessEvents
| where FileName has_any (ScriptInterpreter)
| where ProcessCommandLine has_any ( CyrillicChar) or ProcessCommandLine has_any (ArabicChar) or ProcessCommandLine matches regex ChineseunicodeChar
```
