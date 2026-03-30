# *Device TVM Secure Configuration Assessment Summary*

## Query Information

#### Description
This rule summarizes the compliance status of security configurations across devices using data from DeviceTvmSecureConfigurationAssessment and DeviceTvmSecureConfigurationAssessmentKB. It identifies and prioritizes security misconfigurations by counting compliant, non-compliant, and not-applicable devices for each configuration, ordered by the highest number of non-compliant devices.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References

## Defender XDR
```KQL
DeviceTvmSecureConfigurationAssessment
| join kind=leftouter (
    DeviceTvmSecureConfigurationAssessmentKB
    | project ConfigurationId, ConfigurationName
) on ConfigurationId
| summarize 
    Total = count(),
    Compliant = countif(IsCompliant == 1),
    NonCompliant = countif(IsCompliant == 0),
    NotApplicable = countif(IsApplicable == 0)
  by ConfigurationId, ConfigurationName
| order by NonCompliant desc

```
