# TryHackMe CTF - Investigating with ELK 101

![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange)
![Status](https://img.shields.io/badge/Status-Completed-success)
![Tools](https://img.shields.io/badge/Tools-ELK%20Stack%20%7C%20Kibana%20%7C%20KQL-blue)

## 📋 Description

Understand how SOC analysts use the Elastic Stack (ELK) for log investigations. This room covers the fundamentals of using Elasticsearch, Logstash, Kibana, and Beats for security operations and log analysis.

- **Room URL**: https://tryhackme.com/room/investigatingwithelk101
- **Category**: SOC, SIEM, Log Analysis
- **Difficulty**: Medium
- **Estimated Time**: 180 minutes
- **Part of**: SOC Level 1 Path - Core SOC Solutions

## 🎯 Objectives

Learn how to use ELK Stack for SOC operations by:
- ✅ Understanding ELK Stack components (Elasticsearch, Logstash, Kibana, Beats)
- ✅ Mastering the Kibana Discover tab for log investigation
- ✅ Writing KQL (Kibana Query Language) search queries
- ✅ Creating visualizations from log data
- ✅ Building dashboards for security monitoring
- ✅ Investigating VPN logs for security incidents

## 📊 Resolution Summary

### Tasks Completed

| Task | Description | Questions | Status |
|------|-------------|-----------|--------|
| Task 1 | Introduction | 0 | ✅ |
| Task 2 | Elastic Stack Overview | 2 | ✅ |
| Task 3 | Lab Connection | 0 | ✅ |
| Task 4 | Discover Tab | 7 | ✅ |
| Task 5 | KQL Overview | 2 | ✅ |
| Task 6 | Creating Visualizations | 2 | ✅ |
| Task 7 | Creating Dashboards | 0 | ✅ |
| Task 8 | Conclusion | 0 | ✅ |

**Total**: 13/13 questions ✅ (100%)

## 🔍 Detailed Solutions

### Task 2: Elastic Stack Overview (2/2)

**Logstash is used to visualize the data. (yay / nay)**
- Answer: `nay`
- Explanation: Kibana is used for visualization, not Logstash. Logstash is a data processing engine.

**Elasticstash supports all data formats apart from JSON. (yay / nay)**
- Answer: `nay`
- Explanation: Elasticsearch is specifically designed for JSON-formatted documents.

### Task 4: Discover Tab (7/7)

**Select the index vpn_connections and filter from 31st December 2021 to 2nd Feb 2022. How many hits are returned?**
- Answer: `2861`
- Method: Navigate to Discover tab → Select vpn_connections index → Set time filter to Dec 31, 2021 - Feb 2, 2022

**Which IP address has the maximum number of connections?**
- Answer: `238.163.231.224`
- Method: Click on Source_ip field → View top values by count

**Which user is responsible for the overall maximum traffic?**
- Answer: `James`
- Method: Click on UserName field → View top values by count

**Apply Filter on UserName Emanda; which SourceIP has max hits?**
- Answer: `107.14.1.247`
- Method: Add filter UserName:Emanda → Click on Source_ip field → View top values

**On 11th Jan, which IP caused the spike observed in the time chart?**
- Answer: `172.201.60.191`
- Method: Click on the spike on Jan 11 in the timeline → Analyze Source_ip field

**How many connections were observed from IP 238.163.231.224, excluding the New York state?**
- Answer: `48`
- Method: Add filter Source_ip:238.163.231.224 AND NOT Source_State:"New York" → Count results

**Create a table with the fields IP, UserName, Source_Country and save.**
- Answer: No answer needed
- Method: Select fields from left panel → Click on them to add to table view → Save

### Task 5: KQL Overview (2/2)

**Create a search query to filter the logs where Source_Country is the United States and show logs from User James or Albert. How many records were returned?**
- Answer: `161`
- Query: `Source_Country:"United States" AND (UserName:James OR UserName:Albert)`

**A user Johny Brown was terminated on the 1st of January, 2022. Create a search query to determine how many times a VPN connection was observed after his termination.**
- Answer: `1`
- Query: `UserName:"Johny Brown"` with time filter > Jan 1, 2022

### Task 6: Creating Visualizations (2/2)

**Which user was observed with the greatest number of failed attempts?**
- Answer: `Simon`
- Method: Filter by connection_status:failed → Create visualization by UserName → View top value

**How many wrong VPN connection attempts were observed in January?**
- Answer: `274`
- Method: Filter by connection_status:failed AND time range January 2022 → Count results

## 🛠️ Tools Used

- **Elasticsearch** - Search and analytics engine for storing and indexing JSON documents
- **Logstash** - Data processing pipeline for ingesting, filtering, and transforming logs
- **Kibana** - Web-based visualization and exploration tool
- **Beats** - Lightweight data shippers (Filebeat, Winlogbeat, Packetbeat, etc.)
- **KQL (Kibana Query Language)** - Search query language for filtering logs

## 📁 Repository Structure

```
tryhackme-ctf/investigating-with-elk-101/
├── README.md                 # This file
└── SUMMARY.md                # Executive summary
```

## 🚀 Methodology

### ELK Stack Components

**1. Elasticsearch**
- Full-text search and analytics engine
- Stores data in JSON format
- Supports RESTful API
- Acts as the database

**2. Logstash**
- Data processing engine
- Three main components:
  - **Input**: Define data sources
  - **Filter**: Normalize and parse data
  - **Output**: Send to destination (Elasticsearch, files, etc.)

**3. Beats**
- Lightweight data shippers
- Types:
  - **Filebeat**: Log files
  - **Winlogbeat**: Windows event logs
  - **Packetbeat**: Network traffic
  - **Metricbeat**: System metrics
  - **Auditbeat**: Audit data
  - **Heartbeat**: Uptime monitoring

**4. Kibana**
- Data visualization tool
- Web-based interface
- Creates dashboards and visualizations
- Provides the Discover tab for log exploration

### Kibana Discover Tab Features

**Key Elements:**
1. **Index Pattern**: Select which data source to query (e.g., vpn_connections)
2. **Search Bar**: Enter KQL queries to filter logs
3. **Time Filter**: Narrow results by time range
4. **Fields Pane**: Shows available log fields and top values
5. **Timeline**: Visual representation of event counts over time
6. **Logs View**: Displays individual log entries
7. **Add Filter**: Apply filters without writing queries

### KQL (Kibana Query Language)

**Free Text Search:**
```
United States          # Searches for exact phrase
United*               # Wildcard search
```

**Field-Based Search:**
```
Source_ip:238.163.231.224
UserName:James
```

**Logical Operators:**
```
# AND operator
"United States" AND "Virginia"

# OR operator
"United States" OR "England"

# NOT operator
"United States" AND NOT ("Florida")

# Combined
Source_Country:"United States" AND (UserName:James OR UserName:Albert)
```

### Creating Visualizations

**Steps:**
1. Navigate to Discover tab
2. Click on a field and select "Visualize"
3. Choose visualization type (table, pie chart, bar chart, etc.)
4. Drag additional fields for correlation
5. Click Save → Add title and description → Save to library

**Visualization Types:**
- **Tables**: Show data in columns
- **Pie Charts**: Show distribution of values
- **Bar Charts**: Compare values across categories
- **Line Graphs**: Show trends over time

### Creating Dashboards

**Steps:**
1. Go to Dashboard tab
2. Click "Create dashboard"
3. Click "Add from Library"
4. Select saved searches and visualizations
5. Arrange items on dashboard
6. Save dashboard with descriptive name

## 📌 Investigation Scenarios

### Scenario: VPN Log Analysis

**Dataset**: VPN connection logs for January-February 2022

**Key Findings:**
1. **Busiest IP**: 238.163.231.224 (most connections)
2. **Top User**: James (highest traffic volume)
3. **User Emanda**: Primary source IP 107.14.1.247
4. **Anomaly Spike**: Jan 11, 2022 - caused by IP 172.201.60.191
5. **Geographic Analysis**: 48 connections from 238.163.231.224 outside New York
6. **Failed Attempts**: User Simon had most failed login attempts
7. **January Failures**: 274 wrong VPN connection attempts
8. **Terminated User**: Johny Brown (terminated Jan 1, 2022) - 1 post-termination connection

### Security Observations

**Red Flags Identified:**
- High number of failed authentication attempts (274 in one month)
- User Simon: Potential brute-force target or compromised account
- Terminated user activity: Johny Brown accessed VPN after termination
- Traffic spike on specific date: May indicate automated attack or data exfiltration
- Geographic inconsistencies: Same IP connecting from different states

**Recommended Actions:**
1. Investigate failed login attempts for user Simon
2. Review Johny Brown's post-termination access (Jan 1, 2022)
3. Analyze traffic spike on Jan 11 for malicious activity
4. Implement stricter authentication controls
5. Review VPN access policies and automated blocking

## 💡 Lessons Learned

### 1. ELK vs Traditional SIEM
- ELK is not a traditional SIEM but widely used as one
- Highly flexible and scalable
- Open-source components
- Requires manual configuration for security use cases

### 2. Index Patterns Are Critical
- Each log source needs its own index pattern
- Normalizes different log formats into fields
- Enables consistent querying across diverse data

### 3. Time Filtering is Essential
- Always set appropriate time ranges
- Reduces noise and improves query performance
- Timeline visualization helps identify anomalies

### 4. Field-Based Queries are More Precise
- Free text searches can be ambiguous
- Field-based searches target specific data
- Combine multiple fields with logical operators

### 5. Visualizations Enhance Understanding
- Raw logs are difficult to analyze at scale
- Visualizations reveal patterns quickly
- Dashboards provide single pane of glass for monitoring

### 6. Wildcards Have Limitations
- KQL looks for whole words/terms
- Wildcard (*) required for partial matches
- Be specific to avoid false positives

## 🔒 SOC Applications

### For Log Analysis:
1. **Centralized Logging**: Collect logs from all systems in one place
2. **Real-time Monitoring**: Detect anomalies as they occur
3. **Historical Analysis**: Investigate past incidents with time filters
4. **Correlation**: Link events across multiple log sources

### For Incident Response:
1. **Quick Searches**: Use KQL to rapidly find relevant logs
2. **Timeline Reconstruction**: Visualize event sequences
3. **User Activity Tracking**: Monitor specific users or IPs
4. **IOC Hunting**: Search for indicators of compromise

### For Threat Hunting:
1. **Baseline Analysis**: Identify normal behavior patterns
2. **Anomaly Detection**: Spot deviations using visualizations
3. **Hypothesis Testing**: Create queries to test threat scenarios
4. **Proactive Discovery**: Find threats before they cause damage

## 🎓 Key Concepts Mastered

### ELK Architecture
- ✅ Data flow: Beats → Logstash → Elasticsearch → Kibana
- ✅ Each component has specific purpose
- ✅ Horizontal scalability for large environments
- ✅ RESTful API for automation

### Kibana Features
- ✅ Discover tab for log exploration
- ✅ Visualizations for data representation
- ✅ Dashboards for consolidated views
- ✅ Saved searches for reusable queries

### KQL Syntax
- ✅ Free text vs field-based searches
- ✅ Logical operators (AND, OR, NOT)
- ✅ Wildcard usage
- ✅ Nested queries with parentheses

### Security Analysis
- ✅ Failed login pattern analysis
- ✅ User behavior analytics
- ✅ Network traffic investigation
- ✅ Timeline correlation

## 🔗 Resources

- [TryHackMe Room](https://tryhackme.com/room/investigatingwithelk101)
- [Elastic Stack Documentation](https://www.elastic.co/guide/index.html)
- [Kibana User Guide](https://www.elastic.co/guide/en/kibana/current/index.html)
- [KQL Documentation](https://www.elastic.co/guide/en/kibana/current/kuery-query.html)
- [Elasticsearch Reference](https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html)
- [Logstash Documentation](https://www.elastic.co/guide/en/logstash/current/index.html)

## 🏆 Completion

✅ Room completed successfully (100%)
✅ All 13 questions solved
✅ All tasks completed with full understanding
✅ VPN log investigation completed
✅ Visualizations and dashboards created
✅ KQL proficiency demonstrated

---

**Author**: Salim Hadda
**Date**: 2025-12-26
**Skills**: ELK Stack, Kibana, KQL, Log Analysis, SIEM Operations

**Sources**:
- [TryHackMe Investigating with ELK 101 Walkthrough by 0xRahuL](https://rahulcyberx.medium.com/investigating-with-elk-101-complete-tryhackme-walkthrough-250cce44a0ef)
- [TryHackMe Investigating with ELK 101 Answers by Simon Taplin](https://simontaplin.net/2024/12/29/answers-for-the-tryhackme-investigating-with-elk-101-room/)
