# TryHackMe CTF - Carnage (C2 Carnage)

![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange)
![Status](https://img.shields.io/badge/Status-Completed-success)
![Tools](https://img.shields.io/badge/Tools-Wireshark%20%7C%20tshark-blue)

## 📋 Description

Network traffic analysis room focused on investigating a multi-stage infection involving **Squirrelwaffle**, **Qakbot** and **Cobalt Strike**.

- **Room URL**: https://tryhackme.com/room/c2carnage
- **Category**: Network Traffic Analysis, Malware Analysis
- **Points**: 600
- **Difficulty**: Medium
- **Estimated Time**: 60 minutes

## 🎯 Objectives

Analyze a PCAP file to identify:
- ✅ Initial infection vector
- ✅ Downloaded malicious files
- ✅ Command & Control (C2) servers
- ✅ Post-infection traffic
- ✅ Reconnaissance and exfiltration activities
- ✅ Propagation attempts (malspam)

## 📊 Resolution Summary

### Infection Chain Identified

```
Malicious email with Word doc
         ↓
   Enable Macros
         ↓
Squirrelwaffle Dropper
         ↓
documents.zip (attirenepal.com)
         ↓
chart-1530076591.xls
         ↓
    ┌────┴────┐
    ↓         ↓
 Qakbot   Cobalt Strike
    ↓         ↓
maldivehost.net  securitybusinpuff.com
                 survmeter.live
```

### Statistics

- **Questions solved**: 20/20 ✅
- **Victim IP**: 10.9.23.102
- **Malicious domains**: 6
- **C2 servers identified**: 3
- **SMTP packets**: 1,439
- **PCAP size**: 54 MB

## 🔍 Key Points

### Initial Infection
- **Date/Time**: 2021-09-24 16:44:38 (UTC)
- **Dropper**: documents.zip
- **Source**: attirenepal.com (85.187.128.24)
- **Payload**: chart-1530076591.xls

### C2 Servers

| Type | IP | Domain | Protocol |
|------|-----|---------|-----------|
| Qakbot | 208.91.128.6 | maldivehost.net | HTTP |
| Cobalt Strike #1 | 185.106.96.158 | survmeter.live | HTTP/HTTPS |
| Cobalt Strike #2 | 185.125.204.174 | securitybusinpuff.com | HTTPS |

### SSL Certificates
- **finejewels.com.au**: GoDaddy
- **thietbiagt.com**: Let's Encrypt
- **new.americold.com**: Let's Encrypt

## 🛠️ Tools Used

- **Wireshark**: Visual PCAP analysis
- **tshark**: Automated data extraction
- **bash**: Analysis scripts
- **unzip**: Artifact extraction

## 📁 Repository Structure

```
tryhackme-ctf/c2carnage/
├── README.md                 # This file
├── writeup.md               # Detailed step-by-step writeup
├── answers.txt              # All answers to questions
├── COMPLETION.md            # Completion certificate
├── SUMMARY.md               # Executive summary with IOCs
├── INDEX.md                 # Navigation guide
├── /screenshots/            # Important screenshots
├── /scripts/                # Bash/tshark analysis scripts
└── /notes/                  # Intermediate analysis notes
```

## 🚀 Methodology

### 1. Initial Reconnaissance
```bash
# Identify victim IP
tshark -r pcap.pcap -q -z conv,ip
```

### 2. HTTP/HTTPS Analysis
```bash
# Suspicious HTTP requests
tshark -r pcap.pcap -Y "http.request" -T fields \
  -e frame.time -e http.host -e http.request.uri
```

### 3. SSL/TLS Analysis
```bash
# Extract SNI
tshark -r pcap.pcap -Y "ssl.handshake.type == 1" \
  -T fields -e tls.handshake.extensions_server_name
```

### 4. C2 Identification
```bash
# Most contacted IPs
tshark -r pcap.pcap -Y "ip.src==VICTIM_IP" \
  -T fields -e ip.dst | sort | uniq -c | sort -rn
```

## 📌 IOCs (Indicators of Compromise)

### Domains
```
attirenepal.com
finejewels.com.au
thietbiagt.com
new.americold.com
securitybusinpuff.com
survmeter.live
maldivehost.net
```

### IPs
```
85.187.128.24
208.91.128.6
185.125.204.174
185.106.96.158
```

### Files
```
documents.zip
chart-1530076591.xls
```

### Email
```
farshin@mailfa.com
```

## 💡 Lessons Learned

1. **Multi-layer analysis**: Combine HTTP, HTTPS, DNS and SMTP analysis
2. **Temporal correlation**: Track event chronology
3. **SSL certificates**: Don't blindly trust HTTPS connections
4. **C2 patterns**: Identify beaconing behaviors
5. **OSINT**: Use VirusTotal to confirm IOCs

## 🔗 Resources

- [TryHackMe Room](https://tryhackme.com/room/c2carnage)
- [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/2021/09/24/index.html)
- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [tshark Man Page](https://www.wireshark.org/docs/man-pages/tshark.html)

## 🏆 Completion

✅ Room completed successfully
✅ All questions solved (20/20)
✅ Complete documentation created

---

**Author**: Salim Hadda
**Date**: 2025-12-24
**PCAP Credits**: Brad Duncan (malware-traffic-analysis.net)
