# SSH Brute Force Detection & Authentication Analysis Using Splunk

---

##  Overview

This project focused on analyzing Zeek SSH logs within Splunk to identify suspicious authentication activity and investigate potential brute-force behavior.

The investigation involved parsing SSH telemetry, reviewing authentication outcomes, and identifying high-volume SSH activity from source systems within the environment.

---

##  Objective

To perform SSH threat hunting and detect suspicious authentication patterns indicative of unauthorized access attempts.

---

##  Lab Setup

- **Log Source:** Zeek (`ssh.log`)
- **SIEM:** Splunk
- **Environment:** Virtual Lab (Kali Linux + VirtualBox)

---

##  Dataset

The SSH logs contained:

- Source IP addresses
- Destination IP addresses
- Authentication results
- SSH client/server versions
- Connection activity

---

##  Detection Methodology

### 1. SSH Log Ingestion

- Uploaded SSH logs into Splunk
- Assigned custom sourcetype: `zeek_ssh`
- Verified successful event parsing

---

### 2. Manual Field Extraction

Used regex (`rex`) to normalize SSH authentication data.

```spl
index=main sourcetype=zeek_ssh
| rex field=_raw "(?<ts>\d+\.\d+)\s+(?<uid>\S+)\s+(?<src_ip>\d+\.\d+\.\d+\.\d+)\s+(?<src_port>\d+)\s+(?<dest_ip>\d+\.\d+\.\d+\.\d+)\s+(?<dest_port>\d+)\s+(?<auth_result>\S+)"
| stats count by src_ip auth_result
| sort - count
```

---

### 3. Failed Authentication Hunting

Focused specifically on failed SSH authentication activity.

```spl
index=main sourcetype=zeek_ssh
| rex field=_raw "(?<ts>\d+\.\d+)\s+(?<uid>\S+)\s+(?<src_ip>\d+\.\d+\.\d+\.\d+)\s+(?<src_port>\d+)\s+(?<dest_ip>\d+\.\d+\.\d+\.\d+)\s+(?<dest_port>\d+)\s+(?<auth_result>\S+)"
| search auth_result="failure"
| stats count by src_ip
| sort - count
| head 10
```

---

##  Analysis & Findings

### Observed Authentication Activity

The investigation identified:

- High-volume SSH activity from specific source systems
- Repeated failed authentication attempts
- Concentrated login behavior from dominant IP addresses
- Authentication patterns consistent with brute-force style activity

---

### Top Observed Source Systems

| Source IP | Activity Count |
|---|---|
| 192.168.202.141 | 2365 |
| 192.168.202.110 | 613 |
| 192.168.204.45 | 574 |

---

##  SOC Insight

Authentication monitoring is essential for detecting unauthorized access attempts and credential-based attacks.

Repeated SSH authentication failures may indicate:
- brute-force attacks
- password spraying
- attacker reconnaissance
- lateral movement attempts

Effective authentication visibility strengthens threat detection and investigation workflows within SOC environments.

---

## Key Takeaway

Threat hunting using SSH telemetry provides valuable insight into attacker behavior and suspicious authentication activity.

Detection engineering depends heavily on accurate authentication analysis and behavioral monitoring.

---

##  Next Steps

- Build SSH authentication dashboards
- Create brute-force detection alerts
- Correlate SSH activity with DNS and HTTP telemetry
- Expand authentication anomaly detection workflows

---

## 🖼 Sample Output

Add screenshots here showing:
- SSH authentication analysis
- failed authentication activity
- top source IPs
- Splunk threat hunting queries

Example:

```markdown
![SSH Brute Force Detection](ssh-bruteforce-detection.png)
```

---

##  Skills Demonstrated

- Splunk SPL
- Threat Hunting
- Authentication Analysis
- SSH Monitoring
- Brute Force Detection
- Detection Engineering
- SIEM Operations
- Log Parsing
- Zeek Log Analysis
- SOC Investigation
