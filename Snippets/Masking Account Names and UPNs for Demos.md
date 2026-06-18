# *Masking Account Names and UPNs for Demos*

## Query Information

#### Description
When presenting live demos or sharing logs from Microsoft Sentinel or Advanced Hunting, protecting Personally Identifiable Information (PII) is crucial. 

This Kusto Query Language (KQL) snippet defines two user-defined functions (`maskUpn` and `maskName`) to dynamicly mask User Principal Names (UPNs) and account names. It replaces sensitive parts with asterisks (`***`) while keeping the structure and domain visible for context.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References

## Defender XDR
```KQL
// Define a function to mask User Principal Names (UPNs)
let maskUpn = (upn: string) {
    let atPos = indexof(upn, "@");
    // Separate the local part (before @) from the domain
    let localPart = iif(atPos > 0, substring(upn, 0, atPos), upn);
    let domain = iif(atPos > 0, substring(upn, atPos), "");
    // Keep the first 2 characters of the local part if it is long enough
    let visible = iif(strlen(localPart) >= 3, substring(localPart, 0, 2), localPart);
    // Combine masked local part with the original domain
    strcat(visible, "***", domain)
};
// Define a function to mask full names (e.g., "John Doe")
let maskName = (name: string) {
    let spacePos = indexof(name, " ");
    // Split into first and last name based on the space character
    let firstName = iif(spacePos > 0, substring(name, 0, spacePos), name);
    let lastName = iif(spacePos > 0, substring(name, spacePos + 1), "");
    // Keep only the first letter of both first and last name
    let visibleFirst = iif(strlen(firstName) >= 2, substring(firstName, 0, 1), firstName);
    let visibleLast = iif(strlen(lastName) >= 2, substring(lastName, 0, 1), lastName);
    // Handle names with or without a space accordingly
    iif(spacePos > 0, strcat(visibleFirst, "***", " ", visibleLast, "***"), strcat(visibleFirst, "***"))
};
// Query the identity logon events
IdentityLogonEvents
// Apply the masking functions to create new, safe columns
| extend UPN_masked = maskUpn(tostring(AccountUpn))
| extend AccountName_masked = maskName(tostring(AccountName))
// Remove the original sensitive columns from the output
| project-away AccountUpn, AccountName
// Limit the output for demo presentation purposes
| take 50
```
