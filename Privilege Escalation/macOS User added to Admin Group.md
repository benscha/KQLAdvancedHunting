# *macOS User added to Admin Group*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1078.003 | Local Accounts | https://attack.mitre.org/techniques/T1078/003/ |
| T1069.001 | Local Groups | https://attack.mitre.org/techniques/T1069/001/ |

#### Description
This rule detects when a user is added to the local 'admin' group on a macOS system using either the `dscl` or `dseditgroup` command-line utilities. It specifically looks for command-line arguments indicative of adding a user to the 'admin' group. There is a whitelist for legitimate MDM solutions like 'jamfmanager' to reduce false positives.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.003/T1078.003.md#atomic-test-2---create-local-account-with-admin-privileges---macos
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.003/T1078.003.md#atomic-test-5---add-a-newexisting-user-to-the-admin-group-using-dseditgroup-utility---macos

## Defender XDR
```KQL
//if you are using an MDM Solution whitelist in the following line
let legitimAdmin = dynamic(["jamfmanager"]); 
//User Added To Admin Group Via Dscl
//https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.003/T1078.003.md#atomic-test-2---create-local-account-with-admin-privileges---macos
let NewAdminDSCL = DeviceProcessEvents
| where FileName == "dscl"
| where ProcessCommandLine has_all ("-append", "/Groups/admin", "GroupMembership")
| extend Activity = "User Added To Admin Group Via Dscl";
//User Added To Admin Group Via DseditGroup
//https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.003/T1078.003.md#atomic-test-5---add-a-newexisting-user-to-the-admin-group-using-dseditgroup-utility---macos
let NewAdminDSEDIT = DeviceProcessEvents
| where FileName == "dseditgroup"
| where ProcessCommandLine has_all ("-o edit", "-a", "-t", "admin")
| where not(ProcessCommandLine has_any (legitimAdmin))
| extend Activity = "User Added To Admin Group Via Dseditgroup";
//Root Account Enable Via Dsenableroot
NewAdminDSCL
| union NewAdminDSEDIT
```
