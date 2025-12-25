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

## 🛠️ Tools and Technologies

- **Wireshark/tshark** - PCAP analysis
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
└── c2carnage/                 # C2 Carnage CTF
    ├── README.md              # Overview
    ├── writeup.md             # Detailed technical writeup
    ├── answers.txt            # All answers
    ├── SUMMARY.md             # Executive summary with IOCs
    ├── COMPLETION.md          # Completion document
    ├── INDEX.md               # Navigation guide
    ├── scripts/               # Analysis scripts
    │   ├── complete_analysis.sh
    │   ├── analyze_pcap.sh
    │   └── analyze_c2.sh
    ├── screenshots/           # Screenshots
    └── notes/                 # Analysis notes
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
```

### Using Analysis Scripts

```bash
# Analyze a similar PCAP
cd c2carnage/scripts
./complete_analysis.sh /path/to/your.pcap
```

---

## 📊 Global Statistics

| Metric | Value |
|--------|-------|
| CTFs completed | 1 |
| Success rate | 100% |
| Total points | 600 |
| Scripts created | 3 |
| Documentation pages | 50+ |

---

## 🎓 Learning Objectives

This repository demonstrates the following skills:

### Forensic Analysis
- Malicious network traffic investigation
- Attack pattern identification
- Infection timeline reconstruction
- Indicators of compromise (IOCs) extraction

### Blue Team Operations
- Malware detection
- Network protocol analysis
- Event correlation
- Incident response

### Technical Documentation
- Structured and detailed writeups
- Reusable and commented scripts
- Reproducible methodology
- Knowledge sharing

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

- **2025-12-24**: Added C2 Carnage CTF (100% completed)
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

*Last updated: 2025-12-24*
