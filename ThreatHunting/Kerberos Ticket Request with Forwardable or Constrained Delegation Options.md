# *Kerberos Ticket Request with Forwardable or Constrained Delegation Options*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1558 | Steal or Forge Kerberos Tickets | https://attack.mitre.org/techniques/T1558 |


#### Description

This rule detects potential account compromise or lateral movement by monitoring for significant spikes in the number of unique devices a single user account is logging into. It calculates a rolling baseline of daily device usage per account over the last 30 days and triggers an alert when an account's maximum daily unique device count exceeds its average by more than 5 times, with a minimum threshold of 10 unique devices, excluding known system accounts and infrastructure servers.


#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
SecurityEvent 
| where EventID == 4769 
| extend xml = parse_xml(strcat("<Root>", EventData, "</Root>"))
| mv-apply Data = xml.Root.EventData.Data on (
    summarize EventDataBag = make_bag(
        pack(tostring(Data["@Name"]), tostring(Data["#text"]))
    )
)
| evaluate bag_unpack(EventDataBag, columnsConflict='replace_source')
| extend TicketOptionsLong = tolong(TicketOptions)
| extend IsForwarded = binary_and(TicketOptionsLong, 0x20000000) != 0
| extend IsConstrainedDelegation = isnotempty(TransmittedServices) and TransmittedServices != "-"
| where IsForwarded == "true" or IsConstrainedDelegation == "true"
```
