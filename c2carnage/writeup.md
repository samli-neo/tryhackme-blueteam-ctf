# TryHackMe - C2 Carnage - Complete Writeup

## Room Information
- **Name**: Carnage
- **Difficulty**: Medium
- **URL**: https://tryhackme.com/room/c2carnage
- **Category**: Network Traffic Analysis, Malware Analysis
- **Tools used**: tshark, Wireshark, bash

## Scenario

Eric Fischer from Bartell Ltd's purchasing department received an email from a known contact with a Word attachment. When opening the document, he accidentally clicked on "Enable Content". The SOC department immediately received an alert indicating that Eric's workstation was making suspicious outbound connections. The pcap was retrieved from the network sensor.

**Objective**: Analyze the network traffic and discover malicious activities.

---

## Methodology

### Step 1: Obtaining the PCAP

The PCAP file comes from malware-traffic-analysis.net, shared by Brad Duncan.

```bash
# Download the PCAP
wget https://www.malware-traffic-analysis.net/2021/09/24/2021-09-24-Squirrelwaffle-with-Qakbot-and-Cobalt-Strike.pcap.zip

# Extract with password (format: infected_YYYYMMDD)
unzip -P infected_20210924 2021-09-24-Squirrelwaffle-with-Qakbot-and-Cobalt-Strike.pcap.zip
```

**Initial analysis**:
```bash
# Identify victim IP
tshark -r pcap.pcap -q -z conv,ip | head -30
# Result: Victim IP = 10.9.23.102
```

---

### Step 2: Initial Infection Analysis

#### Q1-Q3: First malicious download

```bash
# Search for first HTTP requests
tshark -r pcap.pcap -Y "http.request and ip.src==10.9.23.102" \
  -T fields -e frame.time -e http.host -e http.request.uri | head -5
```

**Results**:
- **Date/time**: `2021-09-24 16:44:38` (Q1 - in UTC)
- **Domain**: `attirenepal.com` (Q3)
- **File**: `/incidunt-consequatur/documents.zip` (Q2)

#### Q4: ZIP content without downloading

```bash
# Export HTTP objects
tshark -r pcap.pcap --export-objects "http,/tmp/http_objects"

# List content
unzip -l /tmp/http_objects/documents.zip
```

**Result**: `chart-1530076591.xls` (Q4)

#### Q5-Q6: Web server information

```bash
# Extract HTTP headers
tshark -r pcap.pcap -Y "http.response and ip.src==85.187.128.24" \
  -T fields -e http.server -e http.response.line
```

**Results**:
- **Server**: `LiteSpeed` (Q5)
- **Version**: `PHP/7.2.34` (Q6) - Found in x-powered-by header

---

### Step 3: Malicious Domains Analysis

#### Q7-Q8: Involved domains and SSL certificates

```bash
# Search for suspicious HTTPS connections
tshark -r pcap.pcap -Y "ssl.handshake.type == 1" \
  -T fields -e tls.handshake.extensions_server_name | \
  grep -v "microsoft\|windows\|adobe" | sort -u
```

**Three malicious domains identified**:
1. `finejewels.com.au` (HTTPS, GoDaddy certificate)
2. `thietbiagt.com` (HTTPS, Let's Encrypt certificate)
3. `new.americold.com` (HTTPS, TLS timeframe 16:45:11-16:45:30 UTC)

```bash
# Extract certificate authorities
tshark -r pcap.pcap -Y "x509ce.dNSName matches \"finejewels\"" \
  -T fields -e x509sat.printableString | grep -i "godaddy"
```

**Result Q8**: `GoDaddy` - CA for finejewels.com.au

---

### Step 4: Cobalt Strike Identification

#### Q9-Q12: Cobalt Strike C2 servers

**Identification methodology**:
1. Analysis of most contacted IPs
2. Reverse DNS lookup
3. Traffic pattern analysis

```bash
# Most contacted IPs
tshark -r pcap.pcap -Y "ip.src==10.9.23.102" \
  -T fields -e ip.dst | sort | uniq -c | sort -rn | head -20
```

**Suspicious IPs identified**:
- `185.106.96.158` (first C2 server, sequential order)
- `185.125.204.174` (second C2 server, sequential order)

```bash
# DNS resolution for IPs
tshark -r pcap.pcap -Y "dns.a == 185.106.96.158 or dns.a == 185.125.204.174" \
  -T fields -e dns.qry.name -e dns.a
```

**Domain mapping**:
- `185.106.96.158` → `survmeter.live` (Q11)
- `185.125.204.174` → `securitybusinpuff.com` (Q12)
- **Sequential order** (Q9): `185.106.96.158, 185.125.204.174`

**Q10: Host header for first C2 IP**:
```bash
# Critical: HTTP Host header, NOT TLS SNI!
tshark -r pcap.pcap -Y "ip.dst==185.106.96.158 and http.request" \
  -T fields -e http.host | head -1
```
**Result**: `ocsp.verisign.com` (OCSP traffic on port 80)

**VirusTotal verification**: These IPs are confirmed as Cobalt Strike C2 servers

---

### Step 5: Post-Infection Traffic

#### Q13-Q16: Active C2 analysis

```bash
# Search for malicious POST traffic
tshark -r pcap.pcap -Y "http and ip.src==10.9.23.102" \
  -T fields -e http.host -e http.request.uri | grep -v "microsoft\|windows"
```

**Post-infection domain**: `maldivehost.net` (Q13)

```bash
# Analyze POST data
tshark -r pcap.pcap -Y "http.host==maldivehost.net and http.request" \
  -T fields -e http.request.uri -e frame.len
```

**Results**:
- **URI**: `/zLIisQRWZI9/OQsaDixzHTgtfjMcGypGenpldWF5eWV9f3k=`
- **First 11 characters**: `zLIisQRWZI9` (Q14 - WITHOUT leading slash!)
- **First packet length**: `281` bytes (Q15)

```bash
# Extract Server header
tshark -r pcap.pcap -qz follow,tcp,ascii,104 | grep "^Server:"
```

**Server header** (Q16):
```
Apache/2.4.49 (cPanel) OpenSSL/1.1.1l mod_bwlimited/1.4
```

---

### Step 6: Reconnaissance and Exfiltration

#### Q17-Q18: IP check

```bash
# Search for API DNS queries
tshark -r pcap.pcap -Y "dns.qry.name contains \"ip\"" \
  -T fields -e frame.time -e dns.qry.name | grep -iE "ipify|whatismyip"
```

**Results**:
- **Time (EDT)**: `2021-09-24 13:00:04 -0400`
- **Time UTC**: `2021-09-24 17:00:04` (Q17)
- **API domain**: `api.ipify.org` (Q18)

**Explanation**: The malware uses api.ipify.org to check the victim's public IP

---

### Step 7: MALSPAM Activity

#### Q19-Q20: Malicious SMTP traffic

```bash
# SMTP analysis
tshark -r pcap.pcap -Y "smtp" | wc -l
# Result: 1439 packets

# First MAIL FROM address
tshark -r pcap.pcap -Y "smtp.req.command == \"MAIL\"" \
  -T fields -e smtp.req.parameter | head -1
```

**Results**:
- **First address**: `farshin@mailfa.com` (Q19)
- **Number of SMTP packets**: `1439` (Q20)

**Analysis**: The infected machine attempts to send spam, probably to propagate the infection

---

## Infection Chain (Kill Chain)

1. **Delivery**: Email with malicious Word document
2. **Exploitation**: Macros enabled → Squirrelwaffle loader
3. **Installation**: Download `documents.zip` from `attirenepal.com`
4. **C2 Communication**:
   - HTTPS connections to `finejewels.com.au`, `thietbiagt.com`, `new.americold.com`
   - HTTP POST traffic to `maldivehost.net` (Qakbot)
   - Cobalt Strike HTTPS connections to `survmeter.live` and `securitybusinpuff.com`
5. **Actions**:
   - External IP check (api.ipify.org)
   - Spam sending attempts (MALSPAM)

---

## Indicators of Compromise (IOCs)

### Files
- `documents.zip` (initial dropper)
- `chart-1530076591.xls` (malicious Excel file)

### Domains
- `attirenepal.com` - Initial dropper hosting
- `finejewels.com.au` - Payload download
- `thietbiagt.com` - Payload download
- `new.americold.com` - Payload download
- `securitybusinpuff.com` - Cobalt Strike C2 #2
- `survmeter.live` - Cobalt Strike C2 #1
- `maldivehost.net` - Qakbot C2
- `api.ipify.org` - IP reconnaissance (legitimate but abused by malware)

### IP Addresses
- `85.187.128.24` - attirenepal.com
- `208.91.128.6` - maldivehost.net
- `185.106.96.158` - Cobalt Strike C2 #1
- `185.125.204.174` - Cobalt Strike C2 #2

### Email
- `farshin@mailfa.com` - Malicious spam

---

## Recommendations

1. **Immediate isolation** of machine 10.9.23.102
2. **Network blocking** of all IOC IPs and domains
3. **Full antivirus scan** of the system
4. **Revoke credentials** potentially compromised
5. **Training** on the risks of Office macros
6. **Update systems** (Apache 2.4.49 has known CVEs)
7. **Complete forensic analysis** of the workstation
8. **Network traffic monitoring** to detect other infections

---

## Useful Tools and Commands

```bash
# General statistics
tshark -r pcap.pcap -qz io,phs

# IP conversations
tshark -r pcap.pcap -qz conv,ip

# HTTP statistics
tshark -r pcap.pcap -qz http,tree

# Export objects
tshark -r pcap.pcap --export-objects "http,output_dir"

# Follow TCP stream
tshark -r pcap.pcap -qz follow,tcp,ascii,STREAM_NUMBER

# Useful filters
# - HTTP requests: http.request
# - HTTP responses: http.response
# - SSL handshake: ssl.handshake.type == 1
# - DNS queries: dns.flags.response == 0
# - SMTP: smtp
```

---

## Conclusion

This analysis demonstrates a typical multi-stage infection involving:
- **Squirrelwaffle** (initial dropper)
- **Qakbot** (banking trojan/loader)
- **Cobalt Strike** (post-exploitation framework)

The infection chain shows a sophisticated attack using multiple domains and IPs for resilience. The use of legitimate SSL certificates (GoDaddy, Let's Encrypt) helps evade detection.

**Status**: ✅ 20/20 questions solved

---

**Created by**: Salim Hadda
**Date**: 2025-12-24
**Sources**:
- malware-traffic-analysis.net (Brad Duncan)
- TryHackMe C2 Carnage Room
