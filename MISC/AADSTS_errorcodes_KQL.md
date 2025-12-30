# *Enrich AADSTS Error Code Description*

## Query Information

#### Description

This KQL query enriches Azure AD sign-in events with human-readable AADSTS error descriptions by looking up error codes from an external CSV (https://github.com/benscha/KQLAdvancedHunting/blob/main/MISC/AADSTS_errorcodes.csv) file.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let ErrorCodes = externaldata(ErrorCode:string, Description:string)
[@"https://raw.githubusercontent.com/benscha/KQLAdvancedHunting/refs/heads/main/MISC/AADSTS_errorcodes.csv"]
with(format="csv", ignoreFirstRecord=true);
AADSignInEventsBeta
| extend ErrorCode = tostring(ErrorCode)
| lookup kind=leftouter ErrorCodes on ErrorCode
| project-rename ErrorDescription = Description
```
