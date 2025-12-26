# Investigating with ELK 101 - Executive Summary

## Overview

Successfully completed TryHackMe's "Investigating with ELK 101" room, demonstrating proficiency in:
- Using Elastic Stack (ELK) for SOC log analysis
- Kibana Discover tab for log investigation
- KQL (Kibana Query Language) for searching logs
- Creating visualizations and dashboards
- VPN log analysis for security incidents

## Completion Statistics

| Metric | Value |
|--------|-------|
| **Difficulty** | Medium |
| **Total Questions** | 13 |
| **Correct Answers** | 13 |
| **Success Rate** | 100% |
| **Time Spent** | 180 minutes |
| **Lab IP** | 10.65.186.250 |
| **Status** | ✅ Completed |

## Task Breakdown

### Task 1: Introduction (0 questions) ✅
- Overview of ELK Stack use in SOC
- Understanding log investigation workflows

### Task 2: Elastic Stack Overview (2/2) ✅

**Concepts Learned**:
- ELK Stack components and architecture
- Elasticsearch: Search and analytics engine (JSON documents)
- Logstash: Data processing pipeline (Input → Filter → Output)
- Beats: Lightweight data shippers (Filebeat, Winlogbeat, Packetbeat, etc.)
- Kibana: Visualization and exploration tool

**Questions Answered**:
1. **Logstash is used to visualize the data** → `nay` (Kibana visualizes, Logstash processes)
2. **Elasticstash supports all data formats apart from JSON** → `nay` (Elasticsearch uses JSON)

### Task 3: Lab Connection (0 questions) ✅

**Lab Details**:
- Machine IP: 10.65.186.250
- Credentials: Analyst / analyst123
- Index Pattern: vpn_connections
- Time Range: Dec 31, 2021 - Feb 2, 2022

### Task 4: Discover Tab (7/7) ✅

**Kibana Features Explored**:
- Index pattern selection
- Time filtering
- Fields pane exploration
- Timeline visualization
- Table creation

**Investigation Results**:
| Question | Answer | Finding |
|----------|--------|---------|
| Hits from Dec 31, 2021 to Feb 2, 2022 | 2861 | Total VPN connections in period |
| IP with maximum connections | 238.163.231.224 | Busiest source IP |
| User with maximum traffic | James | Highest volume user |
| Emanda's top Source IP | 107.14.1.247 | Primary connection source |
| IP causing Jan 11 spike | 172.201.60.191 | Anomalous traffic pattern |
| Connections from 238.163.231.224 (not NY) | 48 | Geographic inconsistency |
| Created table | Saved | IP, UserName, Source_Country |

**Security Observations**:
- Traffic spike detected on January 11, 2022
- IP 238.163.231.224 shows high activity volume
- User James generates most traffic
- Geographic anomalies suggest VPN usage patterns

### Task 5: KQL Overview (2/2) ✅

**KQL Techniques Mastered**:
- Free text search with wildcards
- Field-based search syntax
- Logical operators (AND, OR, NOT)
- Nested queries with parentheses

**Queries Created**:

**Query 1**: Filter US logs for users James or Albert
```
Source_Country:"United States" AND (UserName:James OR UserName:Albert)
```
- **Result**: 161 records

**Query 2**: Post-termination activity for Johny Brown
```
UserName:"Johny Brown"
```
- **Time Filter**: After Jan 1, 2022
- **Result**: 1 connection (security violation!)

**Critical Finding**: Terminated user Johny Brown accessed VPN after termination date, indicating potential unauthorized access or incomplete offboarding.

### Task 6: Creating Visualizations (2/2) ✅

**Visualization Analysis**:

**Failed Login Investigation**:
- **Filter**: connection_status:failed
- **Visualization Type**: Table by UserName
- **Result**: Simon had most failed attempts

**January Failure Count**:
- **Filter**: connection_status:failed AND @timestamp:[Jan 1 TO Jan 31]
- **Result**: 274 failed connection attempts

**Security Implications**:
- User Simon: Potential brute-force target or compromised account
- 274 failures in one month: Suggests automated attack attempts
- Recommended action: Implement account lockout policies

### Task 7: Creating Dashboards (0 questions) ✅

**Dashboard Components Added**:
1. Saved searches from Discover tab
2. Visualizations created in Task 6
3. Custom arrangements for optimal viewing
4. Saved for future monitoring

**Dashboard Purpose**:
- Single pane of glass for VPN monitoring
- Real-time visibility into connection patterns
- Quick identification of anomalies

### Task 8: Conclusion (0 questions) ✅

Successfully demonstrated comprehensive understanding of:
- ELK Stack architecture and components
- Kibana interface navigation
- KQL query construction
- Visualization and dashboard creation
- Security log analysis workflows

## Skills Demonstrated

### 1. ELK Stack Knowledge
✅ Elasticsearch: Search engine for JSON documents
✅ Logstash: Data pipeline for log ingestion and processing
✅ Kibana: Web-based visualization and exploration
✅ Beats: Lightweight data shippers
✅ Architecture: Data flow from Beats → Logstash → Elasticsearch → Kibana

### 2. Kibana Proficiency
✅ Index pattern selection and management
✅ Discover tab navigation
✅ Time filter application
✅ Fields pane utilization
✅ Timeline spike analysis
✅ Table creation from fields
✅ Saved search functionality

### 3. KQL Mastery
✅ Free text searches
✅ Field-based queries: `Field:Value`
✅ AND operator: Multiple conditions
✅ OR operator: Alternative conditions
✅ NOT operator: Exclusion filtering
✅ Nested queries with parentheses
✅ Wildcard usage: `United*`

### 4. Visualization Creation
✅ Filter-based visualizations
✅ Table visualizations by field
✅ Pie charts for distribution
✅ Save and library management
✅ Correlation between multiple fields

### 5. Security Analysis
✅ Failed login pattern identification
✅ User behavior analytics
✅ Traffic anomaly detection
✅ Post-termination access investigation
✅ Geographic inconsistency analysis
✅ Timeline correlation for incidents

## Critical Findings

### Finding 1: Terminated User Access
**Severity**: Critical
- **User**: Johny Brown
- **Termination Date**: January 1, 2022
- **Post-Termination Connections**: 1
- **Implication**: Access control failure or unauthorized use
- **Recommendation**: Immediate investigation and access revocation

### Finding 2: High Failed Login Rate
**Severity**: High
- **User**: Simon
- **Failed Attempts**: Highest count
- **Total January Failures**: 274
- **Implication**: Potential brute-force attack or credential stuffing
- **Recommendation**: Implement account lockout and MFA

### Finding 3: Traffic Anomaly
**Severity**: Medium
- **Date**: January 11, 2022
- **Source IP**: 172.201.60.191
- **Pattern**: Unusual spike in connections
- **Implication**: Automated activity or data exfiltration
- **Recommendation**: Deep packet inspection and user interview

### Finding 4: Geographic Inconsistencies
**Severity**: Medium
- **IP**: 238.163.231.224
- **Pattern**: 48 connections from outside New York
- **Implication**: VPN usage, shared credentials, or IP spoofing
- **Recommendation**: Implement geofencing and impossible travel detection

### Finding 5: High-Volume User
**Severity**: Low (Informational)
- **User**: James
- **Pattern**: Maximum traffic volume
- **Implication**: Normal power user or data transfer activity
- **Recommendation**: Baseline monitoring for deviation detection

## Indicators of Compromise (IOCs)

### Network IOCs
```
IP Addresses of Interest:
- 238.163.231.224 (High connection volume)
- 107.14.1.247 (User Emanda's primary source)
- 172.201.60.191 (Traffic spike cause)
```

### User IOCs
```
Users Requiring Investigation:
- Simon (High failed login attempts)
- Johny Brown (Post-termination access)
- James (High traffic volume - baseline)
- Emanda (Geographic analysis)
```

### Temporal IOCs
```
Dates of Interest:
- January 11, 2022 (Traffic spike)
- January 1-31, 2022 (274 failed attempts)
- January 1, 2022 onwards (Terminated user activity)
```

## Lessons Learned

### 1. ELK is Flexible but Requires Configuration
- Not a traditional SIEM out-of-the-box
- Powerful when properly configured
- Requires index patterns for each log source
- Open-source nature allows customization

### 2. Time Filtering is Critical
- Always set appropriate time ranges
- Timeline visualization reveals spikes
- Historical data enables incident reconstruction
- Real-time monitoring possible with auto-refresh

### 3. KQL Enables Precision
- Field-based searches more accurate than free text
- Logical operators allow complex queries
- Wildcards useful but can cause performance issues
- Saved searches enable query reusability

### 4. Visualizations Reveal Patterns
- Raw logs difficult to analyze at scale
- Charts and tables make trends visible
- Multiple visualization types for different insights
- Dashboards provide holistic view

### 5. Correlation is Key
- Single events may be benign
- Multiple correlated events indicate threats
- User + IP + time + behavior = complete picture
- Cross-reference with multiple fields

### 6. Failed Logins are Indicators
- High failure rates suggest attacks
- Specific users targeted more than others
- January showed 274 failures (significant)
- Should trigger automated alerts

## Recommendations

### Immediate Actions
1. **Investigate Johny Brown**: Review all post-termination activity, revoke access if active
2. **Protect Simon's Account**: Force password reset, enable MFA, review for compromise
3. **Analyze Jan 11 Spike**: Deep dive into 172.201.60.191 activity for malicious patterns
4. **Review User James**: Establish baseline for normal behavior and monitor deviations

### Short-Term Improvements
1. **Implement Account Lockout**: After 5 failed attempts within 15 minutes
2. **Enable MFA**: For all VPN users, especially high-value targets
3. **Create Alerts**: For failed login thresholds, post-termination access, geographic anomalies
4. **Enhance Dashboards**: Add real-time widgets for critical metrics

### Long-Term Strategy
1. **Automate Offboarding**: Immediate access revocation upon termination
2. **Implement UEBA**: User and Entity Behavior Analytics for anomaly detection
3. **Geographic Controls**: Geofencing and impossible travel detection
4. **Regular Reviews**: Weekly dashboard reviews, monthly trend analysis
5. **Threat Intelligence**: Integrate IP reputation feeds into ELK
6. **Playbook Development**: Incident response procedures for common scenarios

## Business Impact

### Security Posture Improvements
✅ Identified post-termination access vulnerability
✅ Detected high failed login rates requiring investigation
✅ Established baseline for normal VPN usage
✅ Created monitoring dashboards for ongoing visibility

### Operational Efficiency
✅ Centralized log analysis in single platform
✅ Quick query capabilities with KQL
✅ Reusable searches and visualizations
✅ Reduced mean time to detect (MTTD)

### Risk Mitigation
✅ Prevented unauthorized access from terminated user
✅ Identified potential brute-force attacks
✅ Detected traffic anomalies for investigation
✅ Enabled proactive threat hunting

## Conclusion

This room successfully demonstrated the practical application of Elastic Stack (ELK) for SOC operations and log analysis. By investigating VPN connection logs, we identified several security concerns including post-termination access, high failed login rates, and traffic anomalies.

The key takeaway is that **ELK provides powerful search, visualization, and analysis capabilities** when properly configured for security use cases. The combination of Kibana's user interface, KQL's query language, and Elasticsearch's speed enables rapid investigation and continuous monitoring.

All learning objectives were fully achieved, demonstrating comprehensive understanding of ELK Stack components, Kibana features, KQL syntax, and security log analysis workflows.

**Status**: ✅ 100% Complete (13/13 questions)
**Key Findings**: 5 security observations identified
**Dashboards Created**: 1 VPN monitoring dashboard
**Visualizations Saved**: Multiple for failed logins and traffic patterns
**Date**: 2025-12-26

---

**Analyst**: Salim Hadda
**Platform**: TryHackMe
**Category**: SOC Operations & SIEM
**Framework**: Elastic Stack (ELK)
