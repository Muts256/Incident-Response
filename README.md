## Introduction

This repository documents **practical Incident Response investigations** focused on detecting, analysing, and responding to real world security threats commonly observed in enterprise and SOC environments.

The investigations in this repository follow the **NIST Incident Response Lifecycle**, ensuring a structured and repeatable approach to handling security incidents:

- **Preparation:** Establishing visibility, logging, and readiness to detect malicious activity  
- **Detection and Analysis:** Identifying suspicious behaviour, validating alerts, and determining incident scope and impact  
- **Containment, Eradication, and Recovery:** Considering actions to limit impact, remove the threat, and restore affected systems safely  
- **Post-Incident Activity:** Documenting findings, lessons learned, and opportunities for improvement  

Each investigation demonstrates how these phases are applied in practice, from initial alert triage through to analysis and response decision-making.

The scenarios included reflect **realistic attack techniques and suspicious activity patterns**, such as:
| Investigation | Description |
|---------------|-------------|
| [Brute Force Attempts Detection](https://github.com/Muts256/Incident-Response/blob/main/Brute-Force-Attempt-Detection.md) | Detection and response to repeated authentication failures indicating a brute force attack. |
| [Suspicious PowerShell Web Requests](https://github.com/Muts256/Incident-Response/blob/main/Suspicious-PowerShell-web-requests.md) | Investigation of PowerShell activity making suspicious outbound web requests. |
| [Potential Impossible Travel](https://github.com/Muts256/Incident-Response/blob/main/Potential-Impossible-Travel.md) | Analysis of sign-ins from geographically distant locations within an infeasible timeframe. |
| [Excessive Resource Creation/Deletion](https://github.com/Muts256/Incident-Response/blob/main/Excessive-Resource-Creation-And-Or-Deletion.md) | Detection of abnormal cloud resource creation or deletion activity that may indicate compromise.
| [Linux Privilege Escalation and Data Exfiltration](https://github.com/Muts256/Incident-Response/tree/main/Linux-Privilege-Escalation-and-Data-Exfiltration) | Incident Response of suspected insider threat.  |
| [Script Execution Attack](https://github.com/Muts256/Incident-Response/blob/main/Script-Execution-Attack.md) | A script interpreter that automatically launches malicious programs within the target machine, silently |

Where applicable, investigations are mapped to **MITRE ATT&CK** techniques to provide additional context on adversary behaviour and to support threat-informed defence.

---

### Tools and Technologies

- **Microsoft Sentinel (SIEM)**
- **Microsoft Defender for Endpoint (MDE)**
- **Virtual Machine (VM)**
- **Kusto Query Language (KQL)**

---

### Topology

![image alt](https://github.com/Muts256/SNC-Public/blob/8b21c644685ec1719373c7a3eee3f2e10776058e/Images/Incident-Response/Brute-Force/In13.png)

---

### Detection Coverage (MITRE ATT&CK Aligned)

As part of the **Detection and Analysis** phase of the  **NIST SP 800-61 Incident Response Lifecycle**, these are examples of how detections and investigations can be mapped to the **MITRE ATT&CK framework**.

MITRE ATT&CK helps to:
- Understand adversary behaviour
- Validate detection coverage
- Support alert triage and investigation
- Identify detection gaps for continuous improvement

| Tactic | Technique ID | Technique Name | Detection / Investigation |
|------|-------------|---------------|---------------------------|
| Credential Access | T1110 | Brute Force | Brute Force Sign-In Detection (Sentinel Scheduled Rule) |
| Execution | T1059.001 | PowerShell | Suspicious PowerShell Web Request |
| Credential Access | T1003 | OS Credential Dumping | Mimikatz Execution Investigation |
| Command and Control | T1071.001 | Web Protocols | Suspicious Outbound HTTP Traffic |
