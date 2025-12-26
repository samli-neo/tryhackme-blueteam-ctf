# Snort Challenge: Live Attacks - Executive Summary

## Overview

Successfully defended J&Y Enterprise's network against live cyber attacks using Snort IPS in active blocking mode. Demonstrated real-time threat detection and mitigation capabilities for:
- SSH brute-force attacks
- Reverse shell connections

## Completion Statistics

| Metric | Value |
|--------|-------|
| **Difficulty** | Medium |
| **Total Scenarios** | 2 |
| **Total Questions** | 6 |
| **Correct Answers** | 6 |
| **Success Rate** | 100% |
| **Time Spent** | 90 minutes |
| **Attacks Blocked** | 2 |

## Scenario Breakdown

### Scenario 1: SSH Brute-Force Attack

**Threat Actor Activity:**
- Multiple rapid connection attempts to SSH service
- Automated password guessing attacks
- Attempts to compromise authentication

**Detection:**
- Service: SSH
- Port: TCP/22
- Pattern: High-frequency connection attempts from single source

**Response:**
- Created Snort IPS rule to block attacking IP
- Deployed rule with `-A full` mode
- Successfully blocked attack for required duration
- Retrieved flag from desktop upon successful mitigation

**Flag**: `THM{81b7fef657f8aaa6e4e200d616738254}`

**Impact Prevented:**
- Unauthorized access to system
- Potential data breach
- Lateral movement within network

### Scenario 2: Reverse Shell Connection

**Threat Actor Activity:**
- Established outbound connection to C2 server
- Used Metasploit default port (4444)
- Attempted persistent remote access

**Detection:**
- Protocol: TCP
- Port: 4444
- Direction: Outbound
- Tool: Metasploit Framework
- Pattern: Persistent connection to external IP

**Response:**
- Identified anomalous outbound traffic
- Created IPS rule to block port 4444 traffic
- Successfully terminated reverse shell
- Retrieved flag from desktop

**Flag**: `THM{0ead8c494861079b1b74ec2380d2cd24}`

**Impact Prevented:**
- Remote code execution
- Data exfiltration
- Persistence mechanisms
- Further system compromise

## Technical Implementation

### IPS Rule Deployment Process

1. **Reconnaissance**
   ```bash
   snort -A console -i eth0
   ```
   - Identified attack source and destination
   - Determined attack port and protocol

2. **Rule Development**
   - Wrote custom Snort rules for each attack
   - Tested with `-A console` mode
   - Validated rule syntax and effectiveness

3. **Active Blocking**
   ```bash
   snort -c local.rules -A full -l .
   ```
   - Deployed rules in IPS mode
   - Blocked traffic for minimum 1 minute
   - Confirmed successful mitigation via flag appearance

### Rules Created

**SSH Brute-Force Prevention:**
```snort
alert tcp <attacker_ip> any -> any 22 (msg:"SSH Brute-Force Blocked"; sid:100001; rev:1;)
```

**Reverse Shell Detection:**
```snort
alert tcp any any -> any 4444 (msg:"Metasploit Reverse Shell Blocked"; sid:100002; rev:1;)
```

## Threat Intelligence

### Attack Vectors Identified

| Attack Type | Port | Protocol | Tool | Severity |
|-------------|------|----------|------|----------|
| Brute-Force | 22 | TCP | SSH Client | High |
| Reverse Shell | 4444 | TCP | Metasploit | Critical |

### Indicators of Compromise

**SSH Brute-Force:**
- Excessive failed authentication attempts
- Single source IP with multiple connection attempts
- Short time intervals between attempts

**Reverse Shell:**
- Outbound connection to port 4444
- Persistent connection attempts
- Default Metasploit configuration

## Defensive Achievements

### Detection Capabilities
✅ Real-time traffic monitoring
✅ Anomaly identification
✅ Attack pattern recognition
✅ Outbound traffic analysis

### Response Capabilities
✅ Dynamic rule creation
✅ Active threat blocking
✅ IPS mode deployment
✅ Automated mitigation

### Prevention Outcomes
✅ Blocked unauthorized SSH access
✅ Terminated reverse shell connection
✅ Protected critical assets (Shot4J recipe)
✅ Maintained network security posture

## Lessons Learned

### 1. Bidirectional Monitoring is Critical
- Inbound attacks (brute-force) are obvious
- Outbound attacks (reverse shells) indicate compromise
- **Both** directions must be monitored continuously

### 2. Dwell Time Awareness
- Attackers can remain undetected for 1-3 months
- Regular traffic analysis is essential
- Outbound traffic review prevents data exfiltration

### 3. Default Configurations are Exploitable
- Attackers use default Metasploit port (4444)
- Many don't customize tools
- Signature-based detection remains effective

### 4. Active vs Passive Defense
- IDS = Detection only (alert and log)
- IPS = Prevention (block malicious traffic)
- Active defense requires careful rule testing

### 5. Testing Before Deployment
- Always test with `-A console` first
- Verify rules don't cause false positives
- Deploy to production with `-A full` mode

## Recommendations

### Immediate Actions
1. Deploy comprehensive IPS rules for SSH (port 22)
2. Block common C2 ports (4444, 4443, 8080, 8443)
3. Implement rate limiting on authentication services
4. Enable outbound traffic monitoring

### Short-term Improvements
1. Implement fail2ban for automated blocking
2. Require SSH key-based authentication
3. Deploy honeypots to detect reconnaissance
4. Create custom rule sets for organization

### Long-term Strategy
1. Implement SIEM for correlation and alerting
2. Deploy EDR solutions on endpoints
3. Conduct regular red team exercises
4. Maintain updated threat intelligence feeds

## Business Impact

### Assets Protected
- **Shot4J Recipe**: Super-secret coffee recipe secured
- **Customer Data**: POS and customer information safe
- **Network Infrastructure**: No lateral movement occurred
- **Business Continuity**: Zero downtime maintained

### J&Y Enterprise Security Posture
- **Before**: Vulnerable to brute-force and reverse shells
- **After**: Active IPS protection deployed
- **Result**: Real-time threat blocking capability

## Conclusion

This challenge successfully demonstrated the effectiveness of Snort IPS in active defense scenarios. By detecting and blocking both inbound brute-force attacks and outbound reverse shell connections, the security posture of J&Y Enterprise was significantly improved.

The key takeaway is the importance of **bidirectional traffic monitoring** - while preventing attackers from getting in is crucial, detecting and blocking compromised systems from communicating out is equally important for comprehensive network security.

**Status**: ✅ 100% Complete
**Attacks Blocked**: 2/2
**Network**: Secured
**Date**: 2025-12-26

---

**Analyst**: Salim Hadda
**Assistant**: J.A.V.A. (Just Another Virtual Assistant)
**Platform**: TryHackMe
**Category**: Active Defense & Incident Response
