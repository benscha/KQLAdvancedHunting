# *Suspicious unsigned File executed in User writeable Folder*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059 | Command ans Scripting Interpreter | https://attack.mitre.org/techniques/T1059/ |
| T1533.002 | Code Signing | https://attack.mitre.org/techniques/T1533/002/ |

#### Description
This rule detects the execution of unsigned or invalidly signed executable files from user-writable folders such as \Users\ or \ProgramData\. It specifically looks for process creation events where the initiating process's signature status is not 'Valid' and the SHA256 hash of the executable is not in a predefined whitelist. Additionally, it filters for executables with a global prevalence of less than 2500 and an unsigned signature state. This aims to identify potentially malicious or unauthorized software being run from locations where users typically have write permissions, bypassing standard software deployment and security controls.

#### Risk

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- 

## Defender XDR
```KQL
let WhitelistedHashesSHA256 = dynamic([
    "cd91d0f5560c3911710d17b6690c7c05452b7d1a14f08668e175962d022fea7c", //ffprobe.exe
    "2b3caae67f2cd1ec3d2fca81348afcdff813db41a8a0cfd5c9126505f894afb0", //Python Install Manager Installer.exe
    "d83db09332f423ec35e1fbf025f4045ca0baefec26e35a7e918cd6e921d12848" //Abelssoft CheckDrive 2026
    ]);
DeviceProcessEvents
| where ActionType == "ProcessCreated"
| where FolderPath has_any (@"\Users\",@"\ProgramData\")
| where InitiatingProcessSignatureStatus != "Valid"
| where SHA256 !in (WhitelistedHashesSHA256)
| invoke FileProfile(SHA256)
| where GlobalPrevalence < 2500
| where SignatureState != "SignedValid"
```
