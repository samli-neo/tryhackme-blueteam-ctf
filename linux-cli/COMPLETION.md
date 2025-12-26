# TryHackMe - Linux CLI (Shells Bells) | Completion Certificate

---

## Challenge Information

**Challenge Name**: Linux CLI - Shells Bells
**Platform**: TryHackMe
**Event**: Advent of Cyber 2025
**Day**: 1
**Difficulty**: Easy
**Category**: Linux Fundamentals, Incident Response, Log Analysis
**Room URL**: https://tryhackme.com/room/linuxcli-aoc2025-o1fpqkvxti

---

## Completion Details

**Completed By**: Salim Hadda
**Completion Date**: 2025-12-25
**Time Taken**: ~20 minutes
**Completion Rate**: 100% (9/9 questions)

### Questions Completed

| # | Question | Answer | Status |
|---|----------|--------|--------|
| 1 | Which CLI command would you use to list a directory? | `ls` | ✅ Correct |
| 2 | Identify the flag inside of the McSkidy's guide | `THM{learning-linux-cli}` | ✅ Correct |
| 3 | Which command helped you filter the logs for failed logins? | `grep` | ✅ Correct |
| 4 | Identify the flag inside the Eggstrike script | `THM{sir-carrotbane-attacks}` | ✅ Correct |
| 5 | Which command would you run to switch to the root user? | `sudo su` | ✅ Correct |
| 6 | What flag did Sir Carrotbane leave in the root bash history? | `THM{until-we-meet-again}` | ✅ Correct |

**Manual Entry Questions**: 4/4 (100%)
**Auto-Detected Flags**: 2/2 (100%)

---

## Skills Acquired

### Linux Command Line
- ✅ Basic command execution (echo, ls, cat, pwd)
- ✅ Directory navigation (cd, pwd)
- ✅ File system exploration
- ✅ Hidden file discovery (ls -la)
- ✅ File content viewing

### Security Analysis
- ✅ Log file investigation with grep
- ✅ File search with find command
- ✅ Shell script analysis
- ✅ Bash history forensics
- ✅ Malware identification

### Linux Fundamentals
- ✅ Understanding file permissions
- ✅ User privilege escalation (sudo su)
- ✅ Root user operations
- ✅ Special symbols (|, >, >>, &&)
- ✅ Wildcard pattern matching

### Incident Response
- ✅ Failed login analysis
- ✅ Attacker command identification
- ✅ Data exfiltration detection
- ✅ Malware script analysis
- ✅ Attack chain reconstruction

---

## Challenge Summary

### Scenario
Investigated a security breach at The Best Festival Company (TBFC) where Sir Carrotbane from HopSec Island deployed "Eggstrike" malware to steal and replace Christmas wishlists with EASTMAS propaganda.

### Key Discoveries
1. **Hidden Security Guide**: Found McSkidy's `.guide.txt` in `/home/mcskidy/Guides/`
2. **Failed Logins**: Identified brute force attacks from `eggbox-196.hopsec.thm`
3. **Malware Script**: Discovered `eggstrike.sh` performing wishlist theft
4. **Data Exfiltration**: Found curl commands in root bash history sending data to HopSec

### Commands Mastered
```bash
ls                                    # List directory
ls -la                                # List with hidden files
cat README.txt                        # View file
cat .guide.txt                        # View hidden file
cd Guides                             # Change directory
pwd                                   # Print working directory
grep "Failed password" auth.log       # Search logs
find /home/socmas -name *egg*         # Find files
sudo su                               # Switch to root
whoami                                # Check current user
history                               # View command history
cat .bash_history                     # View bash history file
```

---

## Attack Chain Analyzed

```
HopSec Island Attack
         ↓
Brute Force on socmas Account
         ↓
Successful Root Compromise
         ↓
Eggstrike Malware Deployment
         ↓
Wishlist Data Theft & Replacement
         ↓
Data Exfiltration to HopSec
         ↓
Message Left: "until we meet again"
```

---

## Files Investigated

| File Path | Purpose | Finding |
|-----------|---------|---------|
| `/home/mcskidy/Guides/.guide.txt` | Hidden security guide | Flag: `THM{learning-linux-cli}` |
| `/var/log/auth.log` | Authentication logs | Failed login attempts from HopSec |
| `/home/socmas/2025/eggstrike.sh` | Malware script | Wishlist theft & replacement |
| `/root/.bash_history` | Root command history | Data exfiltration commands |

---

## IOCs Identified

### Domains
- `hopsec.thm` - Attacker infrastructure
- `eggbox-196.hopsec.thm` - Brute force source
- `files.hopsec.thm` - Data exfiltration server
- `red.hopsec.thm` - C2 reporting

### Files
- `/home/socmas/2025/eggstrike.sh` - Malware
- `/tmp/dump.txt` - Stolen data
- `eastmas.txt` - Fake wishlist

---

## Learning Outcomes

### Before This Challenge
- Limited Linux CLI experience
- Unfamiliar with log analysis
- Basic understanding of file systems

### After This Challenge
- ✅ Proficient in essential Linux commands
- ✅ Can analyze authentication logs
- ✅ Can identify malicious shell scripts
- ✅ Understand bash history forensics
- ✅ Can perform privilege escalation
- ✅ Familiar with Linux special symbols

---

## Next Steps

### Recommended Follow-Up Challenges
1. [Linux Logs Investigations](https://tryhackme.com/room/linuxlogsinvestigations) - Advanced log analysis
2. [Linux Privilege Escalation](https://tryhackme.com/room/linuxprivesc) - Deeper privilege escalation
3. [Linux Fundamentals Series](https://tryhackme.com/module/linux-fundamentals) - Complete Linux mastery
4. [Bash Scripting](https://tryhackme.com/room/bashscripting) - Script analysis skills

### Skills to Develop
- Advanced grep patterns and regex
- sed/awk for log processing
- Linux process analysis (ps, top, htop)
- Network analysis (netstat, ss, tcpdump)
- More privilege escalation techniques

---

## Certificate Details

```
╔══════════════════════════════════════════════════════════════════╗
║                    COMPLETION CERTIFICATE                         ║
║                                                                   ║
║  This certifies that                                             ║
║                                                                   ║
║                    SALIM HADDA                                    ║
║                                                                   ║
║  has successfully completed                                       ║
║                                                                   ║
║            LINUX CLI - SHELLS BELLS                               ║
║            TryHackMe Advent of Cyber 2025 - Day 1                ║
║                                                                   ║
║  Completion Date: December 25, 2025                              ║
║  Difficulty: Easy                                                 ║
║  Questions Answered: 9/9 (100%)                                  ║
║                                                                   ║
║  Skills Demonstrated:                                             ║
║  • Linux CLI Fundamentals                                        ║
║  • Log File Analysis                                             ║
║  • Malware Script Investigation                                  ║
║  • Bash History Forensics                                        ║
║  • Privilege Escalation                                          ║
║                                                                   ║
╚══════════════════════════════════════════════════════════════════╝
```

---

## Acknowledgments

**Challenge Platform**: TryHackMe
**Challenge Authors**: TryHackMe, Maxablancas, TactfulTurtle
**Event**: Advent of Cyber 2025
**Community**: Blue Team learning community

---

## Personal Notes

This challenge provided an excellent introduction to Linux CLI fundamentals with a practical security context. The storyline of investigating McSkidy's kidnapping and Sir Carrotbane's Eggstrike attack made learning engaging and memorable.

**Key Takeaway**: The Linux command line is an essential tool for cybersecurity professionals. Every command tells a story, and bash history is a goldmine of forensic evidence.

**Most Valuable Lesson**: Hidden files (dotfiles) can contain both critical security information (like McSkidy's guide) and evidence of compromise (like bash history). Always check with `ls -la`.

---

**Status**: Completed (100%)
**Completion Date**: 2025-12-25
**Completed By**: Salim Hadda
**Platform**: TryHackMe

---

*"In the world of cybersecurity, the command line is mightier than the GUI."*
