# KQL Advanced Hunting Queries for Microsoft Defender and Microsoft Sentinel

<div align="center">
  <img src="https://raw.githubusercontent.com/benscha/KQLAdvancedHunting/main/KQLNinja.png" alt="KQL Advanced Hunting Queries for Microsoft Defender and Sentinel - KQLNinja Logo" width="300"/>
</div>

<div align="left">

Welcome to a curated collection of production-ready **KQL (Kusto Query Language) queries** for **Microsoft Defender XDR Advanced Hunting**, **Microsoft Sentinel SIEM**, and **Microsoft Purview**. This repository provides cybersecurity analysts, SOC teams, and incident responders with advanced cyber threat intelligence and detection engineering logic to hunt for sophisticated cyber attacks.

🌐 **Featured In:** Queries from this repository are proudly indexed and featured on leading community platforms, including **[kqlsearch.com](https://kqlsearch.com)** and **[detections.ai](https://detections.ai)**.

---

## 🔍 Capabilities, Cyber Threat Hunting Tables & Coverage

| Focus Area | Core & Advanced Tables | Use Cases & Detection Scope |
| :--- | :--- | :--- |
| 📊 **Behavior Analytics & Baseline Hunting** | `SigninLogs`, `AADSignInLogs`, `BehaviorAnalytics`, `IdentityLogonEvents` | Advanced UEBA, historic sign-in baselining, anomaly detection via multi-vector analysis (uncommon IP + User-Agent + OS combinations), identifying first-time or rare account activities. |
| 💻 **Endpoint Security & Vulnerabilities** | `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`, `DeviceRegistryEvents`, `DeviceInfo` | Process anomalies, Living-off-the-Land (LotL), unauthorized Debugger Registration (IFEO), CVE/Exploit detection (e.g., Windows Shell Security Feature Bypasses), VS Code extension hunting. |
| 🔑 **Identity & Access Management** | `IdentityLogonEvents`, `AADSignInLogs`, `SigninLogs`, `IdentityInfo` | Brute force, MFA bypass, AiTM phishing link click correlations, privilege escalation, cross-tenant identity validation. |
| ☁️ **Cloud, Governance & DevOps** | `CloudAppEvents`, `OfficeActivity`, `AuditLogs`, `AzureDevOpsAuditing` | Data exfiltration, shadow IT, malicious app registrations, high-privilege takeover (Service Principal abuse), Azure DevOps critical configuration changes. |
| 📧 **Email & Collaboration** | `EmailEvents`, `EmailUrlInfo`, `EmailAttachmentInfo`, `CloudAppEvents` (Teams) | Advanced phishing, Business Email Compromise (BEC), malicious URL/Domain hits in Microsoft Teams messages. |

> 🛡️ **Incident Response Ready:** All SIEM detection rules and hunting queries are optimized for fast execution, high performance, and direct deployment in the Microsoft Defender XDR portal or Microsoft Sentinel Log Analytics workspace.

---

## 🚀 Why Use This KQL Detection Engineering Repository?

* **Production-Ready SIEM Content & Field-Tested:** Real-world KQL queries designed for proactive threat hunting, minimizing false positives while catching advanced persistent threats (APTs) and modern attack techniques.
* **Advanced UEBA & Behavior Detection Logics:** Goes beyond simple static filtering. Includes complex multi-vector baselining, historical UEBA scoring, and cross-platform log correlation.
* **Broad Enterprise Cloud Ecosystem Coverage:** Comprehensive cyber security templates covering Microsoft Defender XDR (`Device*` events), Microsoft Entra ID (Azure AD), Microsoft 365 Cloud Apps, Azure DevOps CI/CD pipelines, and emerging CVE exploits.
* **Built for SOC Customization:** Clean, modular code structures with easily adjustable timeframes, thresholds, and variables to fit your institutional security baseline instantly.

---

## 🔗 Connect & Support

* ⭐ **Support the Project:** If these KQL queries helped you improve your detections, please leave a star! It helps others discover this repository and supports open-source security tools.
* 👥 **Connect on LinkedIn:** Follow me for regular cybersecurity updates, community insights, and KQL tips: https://www.linkedin.com/in/benjamin-zulliger/?follow

Maintained with 🛡️ by **Benjamin Zulliger** 
