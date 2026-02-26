# *Attempt to Disable Auditd Service*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1562.012 | Disable or Modify Linux Audit System | https://attack.mitre.org/techniques/T1562/012/ |


#### Description
Detects attempts to disable or stop the 'auditd' service on Linux systems using common service management utilities like systemctl, service, chkconfig, or update-rc.d. This activity could indicate an adversary attempting to impair defenses and avoid logging of their malicious actions.

#### Risk
Defense Evasion

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- 

## Defender XDR
```KQL
// Attempt to Disable Auditd Service
DeviceProcessEvents
| where ProcessCommandLine has_any ("auditd", "auditd.service")
| where FileName in~ ("systemctl", "service", "chkconfig", "update-rc.d")
| where (
    (FileName =~ "systemctl" and ProcessCommandLine has_any ("disable", "stop", "kill", "mask")) or
    (FileName =~ "service" and ProcessCommandLine has "stop") or
    (FileName =~ "chkconfig" and ProcessCommandLine has "off") or
    (FileName =~ "update-rc.d" and ProcessCommandLine has_any ("remove", "disable"))
)
// Exclude legitimate package scripts
| where InitiatingProcessFileName !~ "auditd.prerm"
```

