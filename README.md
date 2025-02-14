# incident-response-playbooks
A collection of security incident response playbooks for SOC analysts.

# 🛡 Incident Response Playbooks  

📌 **A collection of structured incident response playbooks for security teams.**  
Designed for **SOC analysts, security engineers, and blue teamers** to respond to security incidents efficiently.  

---

## 🔥 Included Playbooks:
✅ **Phishing Response**  
- Analyze email headers (Microsoft 365 / Google Workspace).  
- Extract IOCs and block malicious domains.  
- Update SIEM rules to detect similar threats.
  
✅ **Malware Triage**  
- Collect endpoint logs using **CrowdStrike / Carbon Black**.  
- Isolate infected systems and perform static analysis.  
- Reverse engineer malware samples using **FlareVM**. 

✅ **Network Intrusion Detection**  
- Investigate suspicious traffic using **Wireshark**.  
- Detect threats with **Suricata / Snort**.  
- Implement firewall rules with **Palo Alto** to mitigate attacks.

---

## 🛠 Tools & Frameworks Used:
- **SIEM:** Splunk, Elastic, Graylog  
- **Threat Intelligence:** VirusTotal, AbuseIPDB, MISP  
- **EDR/XDR:** CrowdStrike, Carbon Black  
- **Packet Analysis:** Wireshark, Suricata, Snort  
- **Frameworks:** MITRE ATT&CK, NIST CSF

## Table of Contents
- [Introduction](#introduction)
- [Incident Classification](#incident-classification)
- [Roles and Responsibilities](#roles-and-responsibilities)
- [Incident Response Procedures](#incident-response-procedures)
  - [Preparation](#preparation)
  - [Detection & Analysis](#detection--analysis)
  - [Containment](#containment)
  - [Eradication](#eradication)
  - [Recovery](#recovery)
  - [Post-Incident Activities](#post-incident-activities)
- [Automation and Orchestration](#automation-and-orchestration)
- [Communication Protocols](#communication-protocols)
- [Review and Continuous Improvement](#review-and-continuous-improvement)

## Introduction
This repository provides structured **Incident Response Playbooks** for security teams to respond efficiently to cybersecurity threats and incidents. The playbooks align with industry best practices and leverage automation where possible.

## Incident Classification
To ensure a streamlined response, classify incidents based on severity:

| Severity Level | Impact Scope | Example |
|---------------|-------------|---------|
| SEV1 - Critical | Affects multiple systems/org-wide | Ransomware outbreak |
| SEV2 - High | Significant impact on operations | Data breach |
| SEV3 - Medium | Limited operational impact | Single endpoint malware infection |
| SEV4 - Low | Minimal impact, easily contained | Phishing attempt |
| SEV5 - Informational | No immediate risk | Suspicious login attempt |

## Roles and Responsibilities
Each incident requires defined roles:

- **Incident Manager:** Oversees the response and ensures coordination.
- **Technical Lead:** Conducts technical investigations and coordinates remediation efforts.
- **Communications Manager:** Handles internal/external updates and regulatory notifications.
- **Threat Intelligence Analyst:** Assesses IOCs and provides threat intelligence insights.
- **Forensic Investigator:** Conducts digital forensics for evidence collection.

## Incident Response Procedures
### Preparation
- Maintain an up-to-date asset inventory.
- Implement logging and monitoring across systems.
- Define access controls and enforce least privilege.
- Conduct regular security awareness training.

### Detection & Analysis
- Monitor security alerts from SIEM (e.g., **Splunk**, **Elastic**).
- Analyze logs for anomalous activity using:
  ```bash
  grep 'unauthorized' /var/log/auth.log
  ```
- Perform memory analysis for malware:
  ```bash
  volatility -f memory.dump --profile=Win7SP1x64 malfind
  ```
- Use threat intelligence platforms (e.g., **VirusTotal**, **MISP**).

### Containment
- Isolate affected endpoints from the network:
  ```bash
  iptables -A INPUT -s <malicious-ip> -j DROP
  ```
- Implement firewall rules to block malicious traffic.
- Suspend compromised user accounts in **Active Directory**.

### Eradication
- Remove malicious artifacts (files, registry entries, processes).
- Apply security patches and update antivirus signatures.
- Validate system integrity post-eradication.


📌 **Contributions Welcome!** If you have an IR playbook to share, feel free to contribute. 🚀  
