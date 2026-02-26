# *Attempt to Disable Syslog Service*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1562.006 | Indicator Blocking | https://attack.mitre.org/techniques/T1562/006/ |


#### Description
Detects attempts to disable or stop syslog services (syslog, rsyslog, syslog-ng) using common system utilities like systemctl, service, chkconfig, or update-rc.d. This activity could indicate an adversary attempting to impair defenses by preventing logging of their actions.

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
// Attempt to Disable Syslog Service
DeviceProcessEvents
| where ProcessCommandLine has_any ("syslog", "rsyslog", "syslog-ng", "syslog.service", "rsyslog.service", "syslog-ng.service")
| where FileName in~ ("systemctl", "service", "chkconfig", "update-rc.d")
| where (
    (FileName =~ "systemctl" and ProcessCommandLine has_any ("disable", "stop", "kill", "mask")) or
    (FileName =~ "service" and ProcessCommandLine has "stop") or
    (FileName =~ "chkconfig" and ProcessCommandLine has "off") or
    (FileName =~ "update-rc.d" and ProcessCommandLine has_any ("remove", "disable"))
)
// Exclude known log rotation or HUP signals
| where InitiatingProcessFileName !~ "rsyslog-rotate"
| where ProcessCommandLine !has "HUP"

```
