# YARA Rules - YARA mean one!

[![TryHackMe](https://img.shields.io/badge/TryHackMe-Advent%20of%20Cyber%202025-red)](https://tryhackme.com)
[![Day](https://img.shields.io/badge/Day-13-green)](https://tryhackme.com/room/yara-aoc2025-q9w1e3y5u7)
[![Completion](https://img.shields.io/badge/Completion-100%25-success)](https://tryhackme.com/room/yara-aoc2025-q9w1e3y5u7)
[![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange)](https://tryhackme.com/room/yara-aoc2025-q9w1e3y5u7)

**Room**: YARA Rules - YARA mean one!
**Event**: Advent of Cyber 2025 - Day 13
**Completion**: 100% (3/3 questions)
**Date**: 2025-12-25
**Difficulty**: Medium
**Points**: 24
**Author**: Salim Hadda

---

## Overview

Learn how YARA rules can be used to detect anomalies and malicious patterns in files. In this challenge, McSkidy went missing while helping the blue team at The Best Festival Company (TBFC), but she left hidden messages in Easter preparation images. Our task is to create YARA rules to extract these messages and uncover McSkidy's location.

---

## Learning Objectives

- Understand what YARA is and when to use it
- Learn YARA rule syntax and structure (metadata, strings, conditions)
- Master different string types (text, hex, regex)
- Apply modifiers (nocase, wide, ascii, xor, base64)
- Use regular expressions in YARA rules
- Practice with YARA flags (-r recursive, -s show strings)
- Extract and decode hidden messages from files

---

## Challenge Storyline

> **The Crisis**: McSkidy has gone missing! But before disappearing, she sent images related to Easter preparations that contain a hidden message.
>
> **The Mission**: The blue team must search for the keyword "TBFC:" followed by ASCII alphanumeric keywords across the `/home/ubuntu/Downloads/easter` directory to extract the message sent by McSkidy.
>
> **The Discovery**: 5 images contain hidden TBFC codes. When extracted and arranged in ascending order, they reveal McSkidy's location: "Find me in HopSec Island"

---

## Skills Demonstrated

### YARA Fundamentals
- Understanding YARA rule architecture
- Writing meta sections with author, description, and date
- Defining string patterns for malware detection
- Creating conditional logic for rule triggers

### String Types Mastered
- **Text strings**: ASCII and case-sensitive matching
- **Hexadecimal strings**: Byte pattern matching (e.g., MZ headers)
- **Regular expressions**: Flexible pattern matching with regex

### Modifiers Applied
- **nocase**: Case-insensitive matching
- **wide/ascii**: Unicode vs single-byte character search
- **xor**: Detecting XOR-encoded obfuscated strings
- **base64**: Finding Base64-encoded payloads

### Practical Skills
- Recursive directory scanning with `-r` flag
- Extracting matched strings with `-s` flag
- Pattern matching with regex: `/TBFC:[A-Za-z0-9]+/`
- Message reconstruction from distributed clues

---

## Quick Results

| Task | Question | Answer |
|------|----------|--------|
| **Task 2: YARA Rules** |||
| 1 | How many images contain the string TBFC? | `5` |
| 2 | Regex for "TBFC:" + alphanumeric chars | `/TBFC:[A-Za-z0-9]+/` |
| 3 | Message sent by McSkidy | `Find me in HopSec Island` |

---

## Key Concepts

### YARA Rule Structure

```yara
rule TBFC_Message {
    meta:
        author = "Blue Team Analyst"
        description = "Detects TBFC hidden messages"
        date = "2025-12-25"

    strings:
        $tbfc = /TBFC:[A-Za-z0-9]+/

    condition:
        $tbfc
}
```

**Components**:
- **meta**: Rule metadata (optional but recommended)
- **strings**: Patterns to search for
- **condition**: Logic determining when rule triggers

### String Types

1. **Text Strings**:
   ```yara
   $text = "malware" nocase
   $wide_text = "suspicious" wide ascii
   ```

2. **Hexadecimal Strings**:
   ```yara
   $mz_header = { 4D 5A 90 00 }  // MZ header
   $pattern = { E3 41 ?? C8 }     // ?? = wildcard byte
   ```

3. **Regular Expressions**:
   ```yara
   $url = /http:\/\/.*malhare.*/ nocase
   $cmd = /powershell.*-enc\\s+[A-Za-z0-9+/=]+/
   ```

### Condition Logic

```yara
condition: $string1                    // Match single string
condition: any of them                 // Match any defined string
condition: all of them                 // Match all defined strings
condition: ($s1 or $s2) and not $benign  // Combined logic
condition: any of them and (filesize < 700KB)  // With file properties
```

### YARA Command Examples

```bash
# Basic scan
yara rule.yar /path/to/scan

# Recursive scan with string display
yara -r -s rule.yar /path/to/directory

# Scan with specific rule
yara -s tbfc_search.yar /home/ubuntu/Downloads/easter
```

---

## Attack Chain Discovered

```
McSkidy's Communication Strategy
         ↓
Hidden Messages in Easter Images
         ↓
5 Images with "TBFC:<code>" Patterns
         ↓
YARA Rule Creation & Scanning
         ↓
Code Word Extraction
         ↓
Ascending Order Arrangement
         ↓
Message Decoded: "Find me in HopSec Island"
```

---

## Tools Used

- **YARA**: Pattern matching and malware detection tool
- **Regex**: Pattern matching for flexible string detection
- **Bash**: Command-line operations and scanning
- **grep**: Alternative text searching (comparison)

---

## Files

- ✅ `README.md` - This overview document
- ✅ `writeup.md` - Detailed technical writeup
- ✅ `SUMMARY.md` - Executive summary
- ✅ `COMPLETION.md` - Completion certificate
- ✅ `/scripts/` - Analysis scripts
- ✅ `/screenshots/` - Evidence screenshots
- ✅ `/notes/` - Investigation notes

---

## Defensive Applications

### When to Use YARA

1. **Post-Incident Analysis**: Verify malware traces across environment
2. **Threat Hunting**: Search for known malware families
3. **Intelligence-Based Scans**: Apply shared community rules
4. **Memory Analysis**: Scan process memory for malicious fragments

### Real-World Use Cases

#### IcedID Trojan Detection
```yara
rule TBFC_Simple_MZ_Detect {
    meta:
        author = "TBFC SOC L2"
        description = "IcedID Rule"
        date = "2025-10-10"
        confidence = "low"

    strings:
        $mz = { 4D 5A }                    // MZ header (PE file)
        $hex1 = { 48 8B ?? ?? 48 89 }      // Malicious binary fragment
        $s1 = "malhare" nocase             // IOC string

    condition:
        all of them and filesize < 10485760  // < 10MB
}
```

**Usage**:
```bash
yara -r icedid_starter.yar C:\
```

**Result**:
```
icedid_starter C:\Users\WarevilleElf\AppData\Roaming\TBFC_Presents\malhare_gift_loader.exe
```

---

## Key Takeaways

1. **YARA is Powerful**: Provides speed, flexibility, and control for malware detection
2. **Regex Mastery Essential**: Critical for matching dynamic malware patterns
3. **Modifiers Enhance Detection**: Use nocase, wide, xor, base64 to catch obfuscated code
4. **Community Rules**: Leverage shared YARA rules for faster threat response
5. **Practical Applications**: Beyond CTFs - use in SOC operations, threat hunting, IR

---

## Next Steps

To continue your YARA journey:
- Explore [YARA GitHub Repository](https://github.com/VirusTotal/yara)
- Review [Awesome YARA Rules](https://github.com/InQuest/awesome-yara)
- Practice with [Malware Bazaar Samples](https://bazaar.abuse.ch/)
- Study [YARA Documentation](https://yara.readthedocs.io/)

---

## Completion Stats

- **Questions Answered**: 3/3
- **Success Rate**: 100%
- **Time Spent**: ~45 minutes
- **Images Scanned**: 5
- **Messages Decoded**: 1
- **Points Earned**: 24

---

**Completed**: 2025-12-25
**Author**: Salim Hadda
**Platform**: TryHackMe
**Event**: Advent of Cyber 2025 - Day 13
**Room**: YARA Rules - YARA mean one!

---

## Sources

Based on research from multiple TryHackMe Advent of Cyber 2025 Day 13 writeups:

- [2025 TryHackMe Advent of Cyber Day 13 Answers: YARA Rules](https://simontaplin.net/2025/12/13/2025-tryhackme-advent-of-cyber-day-12-answers-yara-rules-yara-mean-one/)
- [YARA Rules — YARA mean one! — Writeup by Cyb3r-Kr4k3s](https://cyb3r-kr4k3s.medium.com/yara-rules-yara-mean-one-writeup-day-13-advent-of-cyber-tryhackme-2025-7dd7275c91bc)
- [Advent of Cyber 2025 - Day 13: YARA Mean One! by Akshat Patel](https://medium.com/@patelaksht24/advent-of-cyber-2025-day-13-yara-mean-one-6c3e12516ae3)
- [YARA Rules — YARA mean one! Walkthrough Notes](https://medium.com/@Sle3pyHead/yara-rules-yara-mean-one-walkthrough-notes-tryhackme-0401981ece8a)
- [Multiple additional community writeups on Medium](https://medium.com/search?q=yara%20advent%20cyber%202025)

---

**Happy Hunting! 🔍**

*"In the constant battle to protect SOC-mas, YARA gives defenders clarity in chaos."*
