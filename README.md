# WebGuard SIEM — Web Attack Detection & Monitoring Platform

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge\&logo=python\&logoColor=white)
![HTML5](https://img.shields.io/badge/Dashboard-HTML5-E34F26?style=for-the-badge\&logo=html5\&logoColor=white)
![Cybersecurity](https://img.shields.io/badge/Domain-Cybersecurity-FF2952?style=for-the-badge\&logo=shield\&logoColor=white)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK%20Mapped-blue?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**A mini SIEM platform that simulates web attacks, performs real-time detection, enriches alerts with threat intelligence, maps detections to MITRE ATT&CK, and visualizes incidents through a SOC-style dashboard.**

</div>

---

# Overview

**WebGuard SIEM** is an educational cybersecurity project designed to replicate the workflow of a real **Security Information and Event Management (SIEM)** system.

The platform simulates web attacks, generates Apache access logs, performs signature and behavioral detection, enriches alerts with threat intelligence, and displays results in a SOC-style monitoring dashboard.

This project demonstrates **core SOC analyst and detection engineering skills** including:

* Log analysis
* Attack detection
* Threat intelligence enrichment
* MITRE ATT&CK mapping
* Risk-based alert prioritization
* SIEM query development

---

# Key Features

| Capability            | Description                                                           |
| --------------------- | --------------------------------------------------------------------- |
| Attack Simulation     | Generates SQLi, XSS, LFI, RFI, Command Injection, Directory Traversal |
| Real-Time Monitoring  | Log stream monitoring similar to `tail -f`                            |
| Signature Detection   | Regex patterns for common web attack payloads                         |
| Behavioral Detection  | Brute force, error spikes, request anomalies                          |
| Threat Intelligence   | IP enrichment using GeoIP, ASN, and reputation scoring                |
| MITRE ATT&CK Mapping  | Alerts mapped to tactics and techniques                               |
| Risk Scoring          | Threat scoring system prioritizing critical alerts                    |
| Sigma Rule Export     | Detection rules exported as Sigma YAML                                |
| SOC Dashboard         | Interactive dashboard for security monitoring                         |
| Geographic Attack Map | Visualization of attacker locations                                   |

---

# System Architecture

```
Attack Simulator
        ↓
Apache / Nginx Log Generator
        ↓
Real-Time Log Monitor
        ↓
Detection Engine
        ↓
Threat Intelligence Enrichment
        ↓
MITRE ATT&CK Mapping
        ↓
Risk Scoring Engine
        ↓
SOC Monitoring Dashboard
```

This architecture models the pipeline used in **enterprise SIEM platforms**.

---

# Project Structure

```
webguard-siem/
│
├── 1_simulate_attacks.py
├── 2_generate_logs.py
├── 3_detection_engine.py
├── realtime_monitor.py
│
├── threat_intel.py
├── mitre_risk.py
│
├── soc_dashboard_v2.html
│
├── sample_logs/
│   ├── web_access.log
│   ├── detection_alerts.json
│   └── rt_alerts.json
│
├── sigma_rules/
│   ├── rule_sql_injection.yml
│   ├── rule_xss.yml
│   └── rule_brute_force.yml
│
└── README.md
```

---

# Quick Start

## Clone the Repository

```bash
git clone https://github.com/yourusername/webguard-siem.git
cd webguard-siem
```

---

## Run the Detection Pipeline

Generate attack simulations:

```bash
python 1_simulate_attacks.py
```

Generate Apache logs:

```bash
python 2_generate_logs.py
```

Run detection engine:

```bash
python 3_detection_engine.py
```

Start real-time monitoring:

```bash
python realtime_monitor.py --simulate
```

---

## Open the Dashboard

Open the HTML dashboard in your browser:

```
soc_dashboard_v2.html
```

No server required.

---

# Dashboard

The SOC dashboard contains **multiple analyst views**:

| Tab          | Description                     |
| ------------ | ------------------------------- |
| Overview     | Attack statistics and timeline  |
| Alerts       | Detailed detection alerts       |
| Threat Intel | IP enrichment information       |
| MITRE ATT&CK | Technique mapping               |
| Risk Scores  | Attack prioritization           |
| Geo Map      | Attacker location visualization |
| Sigma Rules  | Detection rule library          |

---

# Detection Coverage

### Signature Detections

| Attack               | MITRE Technique |
| -------------------- | --------------- |
| SQL Injection        | T1190           |
| Command Injection    | T1059           |
| Cross-Site Scripting | T1059.007       |
| Directory Traversal  | T1083           |
| Local File Inclusion | T1083           |
| Brute Force          | T1110           |

---

### Behavioral Detection

The platform detects:

* Login brute-force attacks
* HTTP error spikes
* 404 enumeration scanning
* abnormal request volumes

---

# Supported SIEM Queries

Example **Splunk detection query**:

```spl
index=web_logs
| where match(uri, "(?i)(union.*select|drop.*table|sleep\(|xp_cmdshell)")
| stats count by src_ip, uri
| sort -count
```

Example **Elasticsearch detection query**:

```json
{
  "query": {
    "regexp": {
      "uri": ".*(\\.\\./|etc/passwd).*"
    }
  }
}
```

---

# Technology Stack

| Layer           | Technology        |
| --------------- | ----------------- |
| Language        | Python            |
| Dashboard       | HTML / JavaScript |
| Visualization   | Chart.js          |
| Threat Intel    | ipinfo.io API     |
| Detection Rules | Sigma YAML        |

---

# Learning Outcomes

This project demonstrates practical knowledge in:

* Security log analysis
* Detection engineering
* SOC monitoring workflows
* Threat intelligence enrichment
* MITRE ATT&CK usage
* SIEM query writing
* security analytics dashboards

---

# Disclaimer

This project is intended **strictly for educational purposes**.
All attack traffic is simulated and generates synthetic logs only.

Do not attempt to run attack techniques against systems without authorization.

---

# License

MIT License

---

⭐ If you found this project useful, consider giving it a star.
