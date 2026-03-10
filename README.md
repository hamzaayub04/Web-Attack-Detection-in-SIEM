# WebGuard SIEM — Web Attack Detection Platform

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![HTML5](https://img.shields.io/badge/HTML5-Dashboard-E34F26?style=for-the-badge&logo=html5&logoColor=white)
![Security](https://img.shields.io/badge/Domain-Cybersecurity-FF2952?style=for-the-badge&logo=shield&logoColor=white)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK%20Mapped-blue?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**A mini SIEM platform simulating real-world web attack detection, threat intelligence enrichment, MITRE ATT&CK mapping, and SOC-level dashboarding.**

[Features](#-features) • [Architecture](#-architecture) • [Quick Start](#-quick-start) • [Dashboard](#-dashboard-preview) • [Detection Coverage](#-detection-coverage) • [API Setup](#-api-setup)

</div>

---

## Overview

WebGuard SIEM is an educational cybersecurity project that replicates the core workflow of a professional Security Information & Event Management (SIEM) platform. It simulates web attacks, streams logs in real time, runs signature and behavioral detection, enriches IPs with threat intelligence, maps detections to MITRE ATT&CK, and presents everything through a SOC-grade analytics dashboard.

**Built for:**
- Cybersecurity students learning detection engineering
- Portfolio projects demonstrating SOC analyst skills
- Practicing SIEM concepts without enterprise tooling

---

## Features

| Feature | Description |
|---|---|
| **Attack Simulation** | Generates realistic SQLi, XSS, LFI, RFI, Command Injection, encoded payload traffic |
| **Real-Time Log Monitoring** | `tail -f` style log stream watcher — detects attacks the moment a line is written |
| **Signature Detection** | 50+ regex patterns across 10 attack categories |
| **Behavioral Detection** | Threshold rules: brute force, error spikes, 404 cascades, request anomalies |
| **Threat Intel Enrichment** | IP → Country, ASN, Hosting Provider, Reputation Score, TOR/VPN detection |
| **MITRE ATT&CK Mapping** | Every alert tagged with Technique ID, Sub-technique, and Tactic |
| **Risk Scoring** | 0–10 per-alert score with dynamic modifiers (TOR +1.5, KnownMalicious +2.0) |
| **Sigma Rule Export** | Detection rules exported as `.yml` files importable into real SIEM platforms |
| **SOC Dashboard** | 7-tab interactive HTML dashboard — no server needed, opens in any browser |
| **Geographic Map** | SVG world map showing attack origin by IP geolocation |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Attack Simulator                      │
│   SQLi · XSS · LFI · CMDi · Traversal · Encoded · RFI  │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│              Apache / Nginx Log Generator               │
│         Mixed attack + normal baseline traffic          │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│            Real-Time Log Stream Monitor                 │
│              tail -f  →  parse  →  detect               │
└────────────────────────┬────────────────────────────────┘
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
  Signature Detection         Behavioral Detection
  (regex patterns)            (sliding-window thresholds)
              └──────────┬──────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│           Threat Intelligence Enrichment                │
│   ipinfo.io  →  Country, ASN, Org                       │
│   AbuseIPDB  →  Reputation Score, Reports, TOR flag     │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│              MITRE ATT&CK Mapping                       │
│   Technique ID · Sub-Technique · Tactic · Mitigations   │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│                  Risk Scoring Engine                    │
│   Base Score + Dynamic Modifiers → Threat Level         │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│                   SOC Dashboard                         │
│   Overview · Alerts · Threat Intel · MITRE · Risk ·     │
│   Geo Map · Sigma Rules                                 │
└─────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
web-attack-siem/
│
├── 1_simulate_attacks.py      # Attack payload generator
├── 2_generate_logs.py         # Apache Combined Log Format generator
├── 3_detection_engine.py      # Offline batch detection + Splunk/Elastic queries
├── threat_intel.py            # IP enrichment (ipinfo.io + AbuseIPDB + offline DB)
├── mitre_risk.py              # MITRE ATT&CK mapping + Risk scoring + Sigma export
├── realtime_monitor.py        # Live log stream watcher with full pipeline
│
├── soc_dashboard_v2.html      # 7-tab SOC dashboard (open in browser)
│
├── sample_logs/
│   ├── web_access.log         # Generated Apache logs
│   ├── attack_simulation.json # Raw attack records
│   ├── labeled_logs.json      # Logs with ground-truth labels
│   ├── detection_alerts.json  # Batch detection output
│   └── rt_alerts.json         # Real-time detection stream output
│
├── sigma_rules/
│   ├── rule_sql_injection.yml
│   ├── rule_xss.yml
│   ├── rule_lfi.yml
│   ├── rule_command_injection.yml
│   ├── rule_brute_force.yml
│   ├── rule_scanner_tool.yml
│   └── rule_encoded_attack.yml
│
└── README.md
```

---

## Quick Start

### Prerequisites

```
Python 3.8+    # No external packages required (stdlib only)
Any browser    # For the dashboard
```

Optional for Sigma YAML export:

```bash
pip install pyyaml
```

### 1 — Clone the Repository

```bash
git clone https://github.com/yourusername/webguard-siem.git
cd webguard-siem
```

### 2 — Open the Dashboard (Instant, No Setup)

```bash
# macOS / Linux
open soc_dashboard_v2.html

# Windows
start soc_dashboard_v2.html
```

> Works completely offline. No server required.

### 3 — Run the Full Python Pipeline

```bash
# Create the log directory
mkdir sample_logs

# Simulate attack traffic → attack_simulation.json
python 1_simulate_attacks.py

# Generate mixed Apache access logs → web_access.log
python 2_generate_logs.py

# Run batch detection → detection_alerts.json
python 3_detection_engine.py

# View MITRE mapping + risk scores + export Sigma rules
python mitre_risk.py

# Test IP enrichment
python threat_intel.py
```

### 4 — Launch Real-Time Monitor

```bash
# Recommended: simulate attacks AND monitor simultaneously
python realtime_monitor.py --simulate --speed 0.8

# Monitor an existing log file
python realtime_monitor.py --log sample_logs/web_access.log

# With live API enrichment
python realtime_monitor.py --simulate \
  --ipinfo YOUR_IPINFO_TOKEN \
  --abuseipdb YOUR_ABUSEIPDB_KEY
```

To stop the monitor at any time:

```
Ctrl + C
```

The monitor catches the signal cleanly and prints a full session summary before exiting.

---

## Dashboard Preview

The dashboard has **7 tabs**, each reflecting a real SOC analyst workflow:

| Tab | Contents |
|---|---|
| **Overview** | Stat cards, 24h attack timeline, live alert feed, attacks-per-minute chart, top threat IPs |
| **Live Alerts** | Full filterable alert table — filter by severity and attack type |
| **Threat Intel** | Per-IP enrichment: country, ASN, TOR/VPN flags, AbuseIPDB score, abuse report count |
| **MITRE ATT&CK** | Technique mapping table, tactic distribution chart, kill chain phase visualization |
| **Risk Scores** | IP risk leaderboard with aggregate scores, per-attack-type risk bar chart |
| **Geo Map** | SVG world map with attack origin markers color-coded by threat level |
| **Sigma Rules** | Exportable YAML rules, Splunk SPL + Elastic DSL query library, payload encoder/decoder |

---

## Detection Coverage

### Signature-Based Detections

| Attack Type | MITRE Technique | Tactic | Base Risk Score |
|---|---|---|---|
| SQL Injection | T1190 | Initial Access | 9.0 / 10 |
| Command Injection | T1059 | Execution | 10.0 / 10 |
| Remote File Inclusion | T1190 | Initial Access | 9.5 / 10 |
| Local File Inclusion | T1083 | Discovery | 8.5 / 10 |
| Brute Force | T1110.001 | Credential Access | 8.0 / 10 |
| Directory Traversal | T1083 | Discovery | 7.5 / 10 |
| Cross-Site Scripting | T1059.007 | Execution | 7.0 / 10 |
| Encoded / Obfuscated Payload | T1027 | Defense Evasion | 7.0 / 10 |
| Scanner Tool | T1595.002 | Reconnaissance | 5.0 / 10 |

### Behavioral Detections

| Rule | Trigger |
|---|---|
| **Brute Force** | ≥ 10 POST `/login` with status 401 within 60 seconds from one IP |
| **Error Spike** | ≥ 60% of requests returning 4xx/5xx within 120 seconds from one IP |
| **404 Cascade** | ≥ 20 consecutive 404 responses from one IP |
| **Request Volume Anomaly** | IP request count exceeds 3× the session average |

### Risk Score Modifiers

```
Base Score  (per attack type, 0–10)
  + 2.0     Known malicious IP  (AbuseIPDB confidence ≥ 80)
  + 1.5     TOR exit node
  + 0.8     VPN / proxy
  + 0.5     HTTP 500 response   (exploit may have succeeded)
  + 0.3     Encoded payload     (evasion attempt)
  + 1.0     Multi-attack bonus  (per extra attack type above 2)
  - 1.0     Internal RFC1918 IP
  ─────────────────────────────
  Capped at 10.0

Threat Levels:
  CRITICAL   ≥ 80  (aggregate IP score)
  HIGH       ≥ 50
  MEDIUM     ≥ 20
  LOW        < 20
```

---

## API Setup

The system runs fully offline using a built-in threat database. To enable live enrichment:

### ipinfo.io — Geolocation + ASN

Free tier: **50,000 requests / month**

1. Register at [ipinfo.io/signup](https://ipinfo.io/signup)
2. Copy your token
3. Pass it at runtime:

```bash
python realtime_monitor.py --simulate --ipinfo YOUR_TOKEN
```

### AbuseIPDB — Reputation + Reports

Free tier: **1,000 requests / day**

1. Register at [abuseipdb.com/register](https://www.abuseipdb.com/register)
2. Generate an API key
3. Pass it at runtime:

```bash
python realtime_monitor.py --simulate --abuseipdb YOUR_KEY
```

Or use the enricher directly in Python:

```python
from threat_intel import ThreatIntelEnricher

enricher = ThreatIntelEnricher(
    ipinfo_token="YOUR_TOKEN",
    abuseipdb_key="YOUR_KEY"
)

result = enricher.enrich("185.220.101.45")
print(enricher.summary(result))
```

---

## Sigma Rule Export

Running `python mitre_risk.py` generates a `sigma_rules/` directory with one `.yml` file per detection type. These are immediately importable into enterprise SIEM platforms.

Example output:

```yaml
title: SQL Injection Attempt
id: b5e3b7d1-9e4a-4c8f-8b2d-1a5f3e7c9d0b
status: stable
description: Detects SQL injection patterns in web server request URIs
author: WebGuard SIEM
tags:
  - attack.initial_access
  - attack.t1190
  - owasp.a03_2021
logsource:
  category: webserver
detection:
  selection:
    c-uri|contains:
      - "' OR '"
      - "UNION SELECT"
      - "DROP TABLE"
      - "SLEEP("
      - "xp_cmdshell"
  condition: selection
level: critical
```

**Supported SIEM platforms:** Splunk · Elastic/Kibana · Microsoft Sentinel · IBM QRadar · Graylog

---

## SIEM Query Reference

**Splunk SPL — SQL Injection**
```spl
index=web_logs
| where match(uri, "(?i)(union.*select|drop.*table|sleep\(|' or 1=1|xp_cmdshell)")
| stats count by src_ip, uri, user_agent
| sort -count
```

**Splunk SPL — Brute Force**
```spl
index=web_logs method=POST uri="/login" status=401
| bucket _time span=1m
| stats count by _time, src_ip
| where count > 10
| sort -count
```

**Elasticsearch DSL — LFI Detection**
```json
{
  "query": {
    "bool": {
      "should": [
        { "regexp": { "uri": ".*(\\.\\./|%2e%2e%2f){2,}.*" } },
        { "match_phrase": { "uri": "etc/passwd" } },
        { "match_phrase": { "uri": "php://filter" } }
      ]
    }
  }
}
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.8+ (zero external dependencies) |
| Dashboard | HTML5 / CSS3 / Vanilla JavaScript |
| Charts | Chart.js 4.4 (CDN) |
| Map | Inline SVG |
| Log Format | Apache Combined Log Format |
| Rule Format | Sigma YAML |
| Threat Intel APIs | ipinfo.io, AbuseIPDB (both optional) |

---

## Learning Outcomes

Working through this project teaches:

- How SIEM tools ingest, parse, and analyze web server logs in real time
- Writing regex-based detection signatures for common web attacks
- Building behavioral and threshold-based anomaly detection
- Threat intelligence enrichment workflows used by SOC analysts
- Applying the MITRE ATT&CK framework to detection engineering
- Risk-based alert prioritization and scoring methodology
- Writing Sigma rules compatible with enterprise SIEM platforms
- Splunk SPL and Elasticsearch DSL query authoring

---

## Disclaimer

This project is built strictly for **educational and research purposes**. All attack simulations generate synthetic log data only. No real network traffic is produced and no real systems are targeted or affected in any way. Do not use any component of this project against systems you do not own or have explicit written permission to test.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for full details.

---

## Acknowledgements

- [MITRE ATT&CK](https://attack.mitre.org/) — Adversarial Tactics, Techniques, and Common Knowledge framework
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) — Web application security risk categories
- [Sigma Project](https://github.com/SigmaHQ/sigma) — Generic signature format for SIEM systems
- [ipinfo.io](https://ipinfo.io) — IP geolocation and ASN data
- [AbuseIPDB](https://www.abuseipdb.com) — IP reputation and abuse reporting database

---

<div align="center">

**If this project helped you, consider giving it a ⭐**

</div>
