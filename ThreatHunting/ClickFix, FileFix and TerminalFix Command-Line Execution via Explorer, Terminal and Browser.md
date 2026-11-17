# *ClickFix, FileFix and TerminalFix Command-Line Execution via Explorer, Terminal and Browser*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1204.004 | User Execution: Malicious Copy and Paste | https://attack.mitre.org/techniques/T1204/004 |
| T1059.001 | Command and Scripting Interpreter: PowerShell | https://attack.mitre.org/techniques/T1059/001 |
| T1218 | System Binary Proxy Execution | https://attack.mitre.org/techniques/T1218 |



#### Description

This query detects ClickFix style social engineering, where a fake CAPTCHA or verification page tricks the user into pasting and running a command. It monitors DeviceProcessEvents from the last hour for processes launched from the three typical paste targets: the Run dialog via explorer.exe (directly or through cmd.exe), Windows Terminal (TerminalFix) and browser file dialogs that spawn script interpreters or LOLBins (FileFix). Each process is labelled with a Variant column describing the likely delivery path.

The distinct command lines are refanged and internal UNC paths of the own domain are normalised, then matched against a set of regular expressions taken from the ClickFixObserver project (data/patterns.regex.json, CF-xxx is the JSON index). The patterns cover download and execute chains such as irm or iwr piped into iex, LOLBins like mshta, msiexec, certutil, bitsadmin, rundll32, regsvr32, finger, pcalua and msbuild, WebDAV and DNS staging, Base64 and Deflate obfuscation, clipboard execution and lure text like "I am not a robot" hidden in comments. A command is reported if it hits at least one strong pattern, or a weak pattern (hidden PowerShell window) combined with a network indicator.

Results are joined back to the original process events and enriched with the matched pattern IDs, names, categories and a pattern count. Adjust the Browsers and BrowserChildren lists, the internal domain in the UNC normalisation and the lookback window to your environment. Admin scripts started from the Run dialog can cause false positives.

#### Author
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
// ClickFix/FileFix/TerminalFix Command-Line Detection
// thx 2 clickfix.observer
// Patterns: benscha/ClickFixObserver data/patterns.regex.json, CF-xxx = JSON index
let PatternInfo = datatable(PatternId:string, PatternName:string, PatternCategory:string, Strength:string)
[
    "CF-000", "irm URL | iex", "Download & Execute", "Strong",
    "CF-023", "mshta with remote URL/script protocol", "LOLBin", "Strong",
    "CF-024", "PowerShell Hidden Window", "Stealth", "Weak",
    "CF-025", "Encoded Command (Base64)", "Obfuscation", "Strong",
    "CF-026", "iwr/curl/wget | iex", "Download & Execute", "Strong",
    "CF-027", "iex(iwr/irm/WebClient)", "Download & Execute", "Strong",
    "CF-028", "conhost --headless", "Stealth", "Strong",
    "CF-029", "msiexec /i remote URL quiet", "LOLBin", "Strong",
    "CF-030", "certutil -urlcache -f", "LOLBin", "Strong",
    "CF-031", "bitsadmin /transfer", "LOLBin", "Strong",
    "CF-032", "cmd /c curl -o %temp%/%appdata%", "Download & Execute", "Strong",
    "CF-033", "wscript/cscript script from Temp/AppData", "LOLBin", "Strong",
    "CF-036", "Lure text: I am not a robot", "Lure", "Strong",
    "CF-037", "Lure text: reCAPTCHA Verification ID", "Lure", "Strong",
    "CF-038", "Lure comment # Verification/Captcha", "Lure", "Strong",
    "CF-039", "FileFix: PowerShell with # path comment", "Lure", "Strong",
    "CF-044", "iwr -OutFile + gc -Raw | iex", "Download & Execute", "Strong",
    "CF-045", "nslookup DNS staging", "Download & Execute", "Strong",
    "CF-046", "finger.exe payload", "LOLBin", "Strong",
    "CF-047", "rundll32 WebDAV path", "LOLBin", "Strong",
    "CF-048", "WebDAV UNC / net use / pushd", "LOLBin", "Strong",
    "CF-049", "cmdkey to IP", "LOLBin", "Strong",
    "CF-050", "regsvr32 from UNC IP", "LOLBin", "Strong",
    "CF-051", "cmd /v:on variable obfuscation", "Obfuscation", "Strong",
    "CF-052", "pcalua -a proxy execution", "LOLBin", "Strong",
    "CF-053", "rem comment Captcha/Verification", "Lure", "Strong",
    "CF-054", "Base64+Deflate/-bxor/ScriptBlock Invoke", "Obfuscation", "Strong",
    "CF-055", "Get-Clipboard + iex", "Download & Execute", "Strong",
    "CF-056", "msbuild project from Temp/AppData", "LOLBin", "Strong",
    "CF-069", "sal a iex;irm | a", "Obfuscation", "Strong"
];
let Browsers = dynamic(["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe"]);
let BrowserChildren = dynamic(["powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe", "conhost.exe", "wscript.exe", "cscript.exe", "curl.exe"]);
let Processes = materialize(
    DeviceProcessEvents
    | where Timestamp >= ago(1h)
    | where ActionType == "ProcessCreated"
    | where isnotempty(ProcessCommandLine)
    | where InitiatingProcessFileName =~ "explorer.exe"
        or (InitiatingProcessFileName =~ "cmd.exe" and InitiatingProcessParentFileName =~ "explorer.exe")
        or (InitiatingProcessFileName =~ "windowsterminal.exe" and FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe"))
        or (InitiatingProcessFileName in~ (Browsers) and FileName in~ (BrowserChildren))
    | extend Variant = case(
        InitiatingProcessFileName =~ "windowsterminal.exe", "TerminalFix candidate",
        InitiatingProcessFileName in~ (Browsers), "FileFix browser-dialog candidate",
        "Explorer / Run or FileFix candidate")
    | project Timestamp, ReportId, DeviceId, DeviceName, AccountUpn, FileName,
        ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, Variant
);
let MatchingCommands = Processes
    | distinct ProcessCommandLine
    | extend MatchInput = replace_string(ProcessCommandLine, "[.]", ".")
    | extend MatchInput = replace_regex(MatchInput, @"(?i)\\\\(?:[a-z0-9-]+\.)*fhnw\.ch(?:@ssl)?(?:@[0-9]{1,5})?\\", "INTERNAL_UNC/")
    | extend HasNetIndicator = MatchInput matches regex @"(?i)https?://|\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|\\\\[^\\\s]+@(?:ssl|[0-9]{1,5})\\|\b(?:iwr|irm|curl|wget|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|downloaddata|net\.webclient|start-bitstransfer|bitsadmin)\b"
    | extend MatchedPatterns = set_difference(pack_array(
  iff(MatchInput matches regex @"(?is)(?:\b(?i:irm)\s+(?:'(?:https?://)?[^\s""'<>|;`()]+'|""(?:https?://)?[^\s""'<>|;`()]+""|(?:https?://)?[^\s""'<>|;`()]+)|\((?i:irm)\s+(?:'(?:https?://)?[^\s""'<>|;`()]+'|""(?:https?://)?[^\s""'<>|;`()]+""|(?:https?://)?[^\s""'<>|;`()]+)\s*\))\s*\|\s*(?i:iex)\b;?", "CF-000", ""),
  iff(MatchInput matches regex @"(?is)mshta(?:\.exe)?\s+(?:https?:|vbscript:|javascript:)", "CF-023", ""),
  iff(MatchInput matches regex @"(?is)powershell[^|\n]*\s-(?:w|win\w*)\s+(?:h|hidden|1)\b", "CF-024", ""),
  iff(MatchInput matches regex @"(?is)-e(?:c|n\w*)?\s+[A-Za-z0-9+/=]{40,}", "CF-025", ""),
  iff(MatchInput matches regex @"(?is)(?:iwr|invoke-webrequest|curl|wget)\b[^\n|]*\|\s*(?:iex|invoke-expression)", "CF-026", ""),
  iff(MatchInput matches regex @"(?is)iex\s*\(?\s*\(?\s*(?:iwr|irm|new-object\s+net\.webclient)", "CF-027", ""),
  iff(MatchInput matches regex @"(?is)conhost(?:\.exe)?\s+--headless", "CF-028", ""),
  iff(MatchInput matches regex @"(?is)msiexec(?:\.exe)?\s+/i\s+https?://[^\s]+\s+/(?:q|qn|quiet)", "CF-029", ""),
  iff(MatchInput matches regex @"(?is)certutil[^\n]*-urlcache[^\n]*-f", "CF-030", ""),
  iff(MatchInput matches regex @"(?is)bitsadmin\s+/transfer", "CF-031", ""),
  iff(MatchInput matches regex @"(?is)cmd\s+/c\s+curl[^\n]*-o\s+%(?:temp|appdata)%", "CF-032", ""),
  iff(MatchInput matches regex @"(?is)(?:wscript|cscript)[^\n]*(?:%temp%|appdata)[^\n]*\.(?:js|vbs|wsf)", "CF-033", ""),
  iff(MatchInput matches regex @"(?is)I am not a robot", "CF-036", ""),
  iff(MatchInput matches regex @"(?is)reCAPTCHA Verification ID", "CF-037", ""),
  iff(MatchInput matches regex @"(?is)#\s*[✅✔]?\s*(?:I am not a robot|Verification ID|reCAPTCHA|Captcha)", "CF-038", ""),
  iff(MatchInput matches regex @"(?is)powershell[^\n]*#\s*[A-Z]:\\[^\n]*", "CF-039", ""),
  iff(MatchInput matches regex @"(?is)(?i:\b(?:invoke-webrequest|iwr)\b.{0,200}-outfile\b.{0,300}(?:get-content|\bgc\b)\b.{0,100}-raw\b.{0,100}(?:invoke-expression|\biex\b))", "CF-044", ""),
  iff(MatchInput matches regex @"(?is)(?i:(?:\bnslookup(?:\.exe)?\s{1,20}(?:-[^\s|&()]{1,80}\s{1,20}){0,3}[^\s|&()]{1,200}\s{1,20}(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b.{0,100}\|\s{0,20}findstr\b|\bfor\s{1,20}/f\b.{0,200}\bnslookup(?:\.exe)?\s{1,20}(?:-[^\s|&()]{1,80}\s{1,20}){0,3}[^\s|&()]{1,200}\s{1,20}(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b))", "CF-045", ""),
  iff(MatchInput matches regex @"(?is)(?i:(?:\bfinger(?:\.exe)?\b.{0,160}\|\s{0,20}(?:cmd|powershell|pwsh)(?:\.exe)?\b|\b(?:copy|xcopy)\b[^\r\n&|]{0,120}\bfinger\.exe[""']?\s{1,20}[""']?(?:%(?:temp|tmp|appdata)%|[a-z]:\\[^\r\n""'&|]{0,100}\\(?:temp|appdata))\\[^\s""'&|]{1,100}\.exe\b))", "CF-046", ""),
  iff(MatchInput matches regex @"(?is)(?i:\brundll32(?:\.exe)?\s{1,20}[""']?\\\\[^\s\\""']{1,200}@(?:80|ssl(?:@443)?)\\[^\s""']{1,200},\s{0,20}#[0-9]{1,5})", "CF-047", ""),
  iff(MatchInput matches regex @"(?is)(?i:(?:\\\\[^\s\\""']{1,200}@(?:ssl(?:@[0-9]{1,5})?|[0-9]{1,5})\\[^\s""']{1,200}|\b(?:net\s{1,20}use|pushd)\b.{0,100}\\\\(?:[a-z0-9-]{1,63}\.){1,5}[a-z]{2,63}\\[^\s""']{1,200}))", "CF-048", ""),
  iff(MatchInput matches regex @"(?is)(?i:\bcmdkey(?:\.exe)?\b.{0,100}/(?:add|generic):(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b.{0,100}/user:)", "CF-049", ""),
  iff(MatchInput matches regex @"(?is)(?i:\bregsvr32(?:\.exe)?\b.{0,100}\\\\(?:[0-9]{1,3}\.){3}[0-9]{1,3}\\[^\s""']{1,200})", "CF-050", ""),
  iff(MatchInput matches regex @"(?is)(?i:\bcmd(?:\.exe)?\s{1,20}/v:on\s{1,20}/c\b.{0,100}\bset\s{1,20}[""']?[a-z0-9_]{1,40}=[^\r\n&|]{1,80}&\s{0,20}\bset\s{1,20}[""']?[a-z0-9_]{1,40}=[^\r\n&|]{1,80}&\s{0,20}[""']?![a-z0-9_]{1,40}![a-z0-9.^""']{0,40}![a-z0-9_]{1,40}!)", "CF-051", ""),
  iff(MatchInput matches regex @"(?is)(?i:\bpcalua(?:\.exe)?\s{1,20}-a\s{1,20}(?:[a-z]:\\[^\s""]{1,100}\\)?(?:powershell|pwsh|cmd|mshta|rundll32|regsvr32)(?:\.exe)?\b.{0,200}(?:https?://|\\\\|(?:[0-9]{1,3}\.){3}[0-9]{1,3}))", "CF-052", ""),
  iff(MatchInput matches regex @"(?is)(?i:\brem\s{1,20}.{0,40}(?:not\s{1,20}a\s{1,20}robot|verification\s{1,20}(?:id|code|hash)|recaptcha|captcha)\b)", "CF-053", ""),
  iff(MatchInput matches regex @"(?is)(?is:(?:\bFromBase64String\s{0,20}\(.{0,500}\b(?:DeflateStream|GZipStream)\b|-bxor\b).{0,500}(?:\b(?:iex|Invoke-Expression)\b|\.Invoke\s{0,20}\()|&\s{0,20}\(?\s{0,20}\[ScriptBlock\]\s{0,20}::\s{0,20}Create\s{0,20}\(|\[ScriptBlock\]\s{0,20}::\s{0,20}Create\s{0,20}\(.{0,200}\.Invoke\s{0,20}\()", "CF-054", ""),
  iff(MatchInput matches regex @"(?is)(?is:(?:\bGet-Clipboard\b.{0,200}\b(?:Invoke-Expression|iex)\b|\b(?:Invoke-Expression|iex)\b.{0,200}\bGet-Clipboard\b))", "CF-055", ""),
  iff(MatchInput matches regex @"(?is)(?i:\bmsbuild(?:\.exe)?\b.{0,100}(?:%(?:temp|tmp|appdata|localappdata)%|\$env:(?:temp|tmp|appdata|localappdata)|\\(?:appdata|temp)\\).{0,200}\.(?:csproj|vbproj|proj|targets)\b)", "CF-056", ""),
  iff(MatchInput matches regex @"(?is)sal\s+a\s+iex;irm\s+(?:https?://)?[^\s""'<>|;`()]+\|a", "CF-069", "")
    ), dynamic([""]))
    | where array_length(MatchedPatterns) > 0
    | mv-expand PatternId = MatchedPatterns to typeof(string)
    | lookup kind=leftouter PatternInfo on PatternId
    | summarize
        MatchedPatternIds = make_set(PatternId),
        MatchedPatternNames = make_set(PatternName),
        MatchedCategories = make_set(PatternCategory),
        StrongHits = countif(Strength == "Strong"),
        WeakHits = countif(Strength == "Weak")
        by ProcessCommandLine, HasNetIndicator
    | where StrongHits > 0 or (WeakHits > 0 and HasNetIndicator);
Processes
| join kind=inner (MatchingCommands) on ProcessCommandLine
| project-away ProcessCommandLine1
| extend PatternCount = array_length(MatchedPatternIds)
| order by Timestamp desc
```
