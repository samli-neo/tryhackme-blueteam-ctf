# TryHackMe CTF - Snort Challenge: Live Attacks

![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange)
![Status](https://img.shields.io/badge/Status-Completed-success)
![Tools](https://img.shields.io/badge/Tools-Snort%20IPS-blue)

## 📋 Description

Put your Snort skills into practice and defend against live attacks. This room focuses on using Snort in IPS mode to actively block real-time threats including brute-force attacks and reverse shells.

- **Room URL**: https://tryhackme.com/room/snortchallenges2
- **Category**: Network Security, IPS, Active Defense
- **Difficulty**: Medium
- **Estimated Time**: 90 minutes

## 🎯 Objectives

Defend J&Y Enterprise's coffee shop network by:
- ✅ Stopping SSH brute-force attacks
- ✅ Blocking reverse shell connections
- ✅ Writing active IPS rules
- ✅ Real-time threat mitigation

## 📊 Resolution Summary

### Scenario Overview

**J&Y Enterprise** - A tech-coffee shop famous for recipes like:
- WannaWhite
- ZeroSleep
- MacDown
- BerryKeep
- CryptoY
- **Shot4J** (super-secret new recipe)

**Threats Detected:**
1. SSH brute-force attack on the network
2. Reverse shell establishing outbound connection

### Tasks Completed

| Task | Description | Questions | Status |
|------|-------------|-----------|--------|
| Task 1 | Introduction | 0 | ✅ |
| Task 2 | Scenario 1: Brute-Force | 3 | ✅ |
| Task 3 | Scenario 2: Reverse-Shell | 3 | ✅ |

**Total**: 6/6 questions ✅ (100%)

## 🔍 Attack Analysis

### Scenario 1: SSH Brute-Force Attack

**Attack Details:**
- **Service**: SSH
- **Protocol/Port**: TCP/22
- **Attack Type**: Brute-force authentication attempts
- **Detection Method**: High volume of connection attempts to port 22

**J.A.V.A. Alert:**
> "We have a brute-force attack, sir. Somebody is knocking on the door!"

**IPS Response:**
```snort
alert tcp <attacker_ip> any -> any 22 (msg:"SSH Brute-Force Detected"; sid:100001; rev:1;)
```

**Flag**: `THM{81b7fef657f8aaa6e4e200d616738254}`

### Scenario 2: Reverse Shell Attack

**Attack Details:**
- **Protocol/Port**: TCP/4444
- **Tool**: Metasploit
- **Attack Type**: Outbound reverse shell connection
- **Detection Method**: Persistent outbound traffic to unusual port

**J.A.V.A. Alert:**
> "Sir, persistent outbound traffic is detected. Possibly a reverse shell..."

**Attack Pattern:**
```
Internal Host → TCP/4444 → Attacker C2 Server
   (Compromised)              (Metasploit listener)
```

**IPS Response:**
```snort
alert tcp any any -> any 4444 (msg:"Metasploit Reverse Shell Detected"; sid:100002; rev:1;)
```

**Flag**: `THM{0ead8c494861079b1b74ec2380d2cd24}`

## 🛠️ Tools Used

- **Snort IPS**: Intrusion Prevention System (active blocking mode)
- **J.A.V.A.**: AI-driven virtual assistant for anomaly detection
- **tshark**: Traffic analysis and packet inspection

## 📁 Repository Structure

```
tryhackme-ctf/snort-challenge-live-attacks/
├── README.md                 # This file
└── SUMMARY.md                # Executive summary
```

## 🚀 Methodology

### Snort IPS Mode Deployment

**Key Points to Remember:**
1. Create and test rules with `-A console` mode first
2. Use `-A full` mode with default log path to stop attacks
3. Block traffic for at least 1 minute for flag to appear
4. Write correct rules and run Snort in IPS mode

### Attack Detection Workflow

```
1. Start Snort in Sniffer Mode
   ↓
2. Identify Anomaly (port, protocol, frequency)
   ↓
3. Write IPS Rule
   ↓
4. Test with -A console
   ↓
5. Deploy with -A full
   ↓
6. Monitor for Flag Appearance
```

### Example Commands

**Sniffer Mode:**
```bash
snort -A console -i eth0
```

**IPS Mode:**
```bash
snort -c local.rules -A full -l . -r traffic.pcap
```

## 📌 IOCs (Indicators of Compromise)

### SSH Brute-Force
```
Service: SSH
Port: TCP/22
Pattern: Multiple rapid connection attempts
Severity: High
```

### Reverse Shell
```
Tool: Metasploit Framework
Port: TCP/4444
Direction: Outbound
Pattern: Persistent connection to external IP
Severity: Critical
```

## 💡 Lessons Learned

1. **Outbound Traffic Monitoring**: Don't just focus on inbound threats - attackers already inside need to communicate out
2. **Dwell Time**: Average 1-3 months - regular traffic analysis is crucial
3. **Default Ports**: Attackers often use default Metasploit port (4444) without customization
4. **Active Defense**: IPS mode can automatically block threats in real-time
5. **Bidirectional Rules**: Monitor both inbound and outbound traffic patterns

## 🔒 Defensive Strategies

### For SSH Brute-Force:
- Implement rate limiting on SSH connections
- Use fail2ban for automatic IP blocking
- Require key-based authentication
- Monitor authentication logs continuously

### For Reverse Shells:
- Block common C2 ports (4444, 4443, etc.)
- Monitor outbound connections to suspicious IPs
- Implement egress filtering
- Use application whitelisting

## 🎭 Scenario Characters

- **YOU**: Security analyst defending J&Y Enterprise
- **J.A.V.A.**: Just Another Virtual Assistant (AI-driven SOC helper)
- **THE NARRATOR**: Story guide

## 🔗 Resources

- [TryHackMe Room](https://tryhackme.com/room/snortchallenges2)
- [Snort IPS Documentation](https://www.snort.org/documents)
- [Metasploit Framework](https://www.metasploit.com/)
- [SSH Security Best Practices](https://www.ssh.com/academy/ssh/security)

## 🏆 Completion

✅ Room completed successfully
✅ All scenarios defended (2/2)
✅ All questions solved (6/6)
✅ 100% completion rate
✅ Real-time threat mitigation demonstrated

---

**Author**: Salim Hadda
**Date**: 2025-12-26
**Skills**: Snort IPS, Active Defense, Incident Response
