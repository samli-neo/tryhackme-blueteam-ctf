# Zeek Exercises - TryHackMe CTF

[![TryHackMe](https://img.shields.io/badge/TryHackMe-Zeek%20Exercises-blue)](https://tryhackme.com/room/zeekbroexercises)
[![Difficulty](https://img.shields.io/badge/Difficulty-Medium-yellow)](https://tryhackme.com/room/zeekbroexercises)
[![Completion](https://img.shields.io/badge/Completion-93%25-success)](https://tryhackme.com/room/zeekbroexercises)

**Room**: Zeek Exercises
**Platform**: TryHackMe
**Difficulty**: Medium
**Completion**: 93% (15/16 questions)
**Date**: 2025-12-25
**Author**: Salim Hadda

---

## Overview

This room provides hands-on practice with Zeek (formerly Bro) network security monitoring tool. The exercises cover DNS tunneling detection, phishing investigation, and Log4J exploitation analysis through PCAP file investigation.

---

## Skills Demonstrated

- Network traffic analysis using Zeek
- PCAP file investigation and log analysis
- DNS tunneling detection
- Phishing campaign investigation
- Malware analysis with VirusTotal
- Log4J vulnerability exploitation detection
- Base64 decoding and command analysis
- IOC extraction and defanging

---

## Tasks Overview

### Task 1: Introduction
Initial setup and room introduction.

### Task 2: Anomalous DNS (4/4 ✅)
Investigated DNS tunneling activity by analyzing:
- IPv6 DNS records
- Connection duration analysis
- Unique DNS query identification
- Source host identification

**Key Finding**: DNS tunneling from 10.20.57.3 with 320 IPv6 DNS records

### Task 3: Phishing (6/6 ✅)
Analyzed a phishing campaign involving:
- Malicious document download from smart-fax[.]com
- VBA macro-enabled Excel file
- Secondary payload (PleaseWaitWindow.exe)
- C2 communication via hopto[.]org dynamic DNS

**Key IOCs**:
- Source: 10[.]6[.]27[.]102
- Download domain: smart-fax[.]com
- Malware: PleaseWaitWindow.exe, knr.exe
- C2 domain: hopto[.]org

### Task 4: Log4J (4/4 ✅)
Investigated Log4Shell (CVE-2021-44228) exploitation:
- Nmap scanning for vulnerable targets
- Java .class file exploitation
- Base64-encoded LDAP payloads
- File creation via decoded commands

**Key Finding**: Successfully decoded base64 payload revealing "touch pwned" command

### Task 5: Conclusion (1/1 ✅)
Room completion and recommendations for additional learning.

---

## Attack Chains Identified

### Phishing Campaign
```
Malicious Email → Excel Document (VBA Macros)
    ↓
smart-fax[.]com → chart-1530076591.xls
    ↓
VBA Execution → Download knr.exe / PleaseWaitWindow.exe
    ↓
C2 Communication → hopto[.]org (Dynamic DNS)
```

### Log4J Exploitation
```
Reconnaissance (Nmap)
    ↓
Log4J JNDI Injection
    ↓
LDAP Payload Delivery (.class files)
    ↓
Base64 Decoded Commands (touch pwned)
```

---

## Critical IOCs

### Phishing IOCs
| Type | Value | Notes |
|------|-------|-------|
| IP Address | 10.6.27.102 | Source of malicious traffic |
| Domain | smart-fax[.]com | Malware hosting |
| File | chart-1530076591.xls | Malicious Excel with VBA |
| File | PleaseWaitWindow.exe | Downloaded malware |
| File | knr.exe | Downloaded malware |
| Domain | hopto[.]org | C2 domain (Dynamic DNS) |

### Log4J IOCs
| Type | Value | Notes |
|------|-------|-------|
| Tool | Nmap | Vulnerability scanner |
| Extension | .class | Java exploit files |
| Command | touch pwned | Decoded base64 payload |

---

## Tools and Techniques

### Zeek Analysis
- **zeek**: Network traffic analyzer
- **zeek-cut**: Extract specific fields from logs
- **Log files**: dns.log, http.log, conn.log, signatures.log

### Commands Used
```bash
# Analyze PCAP with Zeek
zeek -C -r capture.pcap

# Extract specific fields
cat dns.log | zeek-cut query | sort -u | wc -l

# Filter HTTP requests
cat http.log | zeek-cut host uri

# Analyze signatures
cat signatures.log | zeek-cut uid | wc -l
```

### Base64 Decoding
```bash
# Decode LDAP payload
echo "CwNDAF4rYWFQgU5GBc" | base64 -d
```

### VirusTotal Investigation
- File hash lookups (MD5: cc28e40b46237ab6d5282199ef78c464)
- Relations tab for attack chain
- Behavior tab for DNS resolutions
- Bundled files analysis

---

## Learning Outcomes

1. **Zeek Proficiency**: Mastered Zeek log analysis for network security monitoring
2. **DNS Tunneling Detection**: Identified anomalous DNS patterns indicating data exfiltration
3. **Phishing Analysis**: Traced complete attack chain from initial infection to C2
4. **Log4J Exploitation**: Understood JNDI injection and payload delivery mechanisms
5. **IOC Extraction**: Properly defanged and documented indicators of compromise
6. **Malware Analysis**: Used VirusTotal for comprehensive file analysis

---

## Files

- `README.md` - This file
- `answers.txt` - All question answers
- `writeup.md` - Detailed step-by-step writeup
- `SUMMARY.md` - Executive summary
- `COMPLETION.md` - Completion certificate and statistics
- `/scripts/` - Analysis scripts
- `/screenshots/` - Important screenshots
- `/notes/` - Investigation notes

---

## Next Steps

As recommended by the room, continue with:
- [Snort](https://tryhackme.com/room/snort)
- [Snort Challenges 1](https://tryhackme.com/room/snortchallenges1)
- [Snort Challenges 2](https://tryhackme.com/room/snortchallenges2)
- [Wireshark](https://tryhackme.com/room/wireshark)
- [NetworkMiner](https://tryhackme.com/room/networkminer)

---

## Disclaimer

This documentation is for educational purposes only. The techniques and IOCs mentioned should only be used in authorized penetration testing or security research environments.

---

**Author**: Salim Hadda
**Date**: 2025-12-25
**Platform**: TryHackMe
**Room**: Zeek Exercises
