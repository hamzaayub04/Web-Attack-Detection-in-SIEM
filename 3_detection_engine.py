"""
╔══════════════════════════════════════════════════════════════════╗
║      DETECTION ENGINE — SIEM Query & Alert System               ║
║  Detects: SQLi, XSS, LFI, CMDi, DirTraversal, Error Spikes,    ║
║           Encoded Payloads, Brute Force, Scanner Activity        ║
╚══════════════════════════════════════════════════════════════════╝
"""

import re
import json
import urllib.parse
import base64
from datetime import datetime
from collections import defaultdict, Counter

# ─────────────────────────────────────────────
# DETECTION SIGNATURES
# ─────────────────────────────────────────────

SQLI_PATTERNS = [
    r"(\%27|\'|\-\-|\%23|#)",                            # Quote/comment injection
    r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
    r"\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b",
    r"(sleep\s*\(|benchmark\s*\(|waitfor\s+delay)",      # Time-based blind SQLi
    r"(information_schema|sys\.tables|pg_tables)",        # DB enumeration
    r"(\bor\b|\band\b)\s+[\'\d][\s\S]*=[\s\S]*[\'\d]",  # OR/AND bypass
    r"xp_cmdshell|sp_executesql|exec\s*\(",               # MSSQL-specific
    r"(char|nchar|varchar)\s*\(",                         # String functions
]

XSS_PATTERNS = [
    r"<\s*script[\s\S]*?>",                               # <script> tag
    r"javascript\s*:",                                    # javascript: URI
    r"on\w+\s*=",                                        # Event handlers (onload=, onerror=)
    r"<\s*(iframe|object|embed|applet|form)",             # Dangerous tags
    r"(alert|confirm|prompt)\s*\(",                       # JS dialog functions
    r"document\.(cookie|write|location)",                 # DOM access
    r"(%3C|<)\s*script",                                  # URL/partial encoded
    r"&#x?[0-9a-fA-F]+;",                                # HTML entity encoding
    r"expression\s*\(",                                   # CSS expression
    r"vbscript\s*:",                                      # VBScript
]

LFI_PATTERNS = [
    r"\.\./",                                             # Directory traversal
    r"\.\.\\",                                            # Windows traversal
    r"(%2e%2e%2f|%2e%2e/|\.\.%2f)",                     # URL-encoded traversal
    r"(%252e%252e|%c0%ae)",                               # Double/unicode encoded
    r"(etc/passwd|etc/shadow|etc/hosts)",                 # Linux sensitive files
    r"(windows/system32|win\.ini|boot\.ini)",             # Windows sensitive files
    r"php://(filter|input|data|expect)",                  # PHP wrappers
    r"(proc/self|/proc/\d+)",                             # Linux proc filesystem
    r"(data://|expect://|zip://|phar://)",                # PHP stream wrappers
]

RFI_PATTERNS = [
    r"(https?|ftp)://[^/\s]+/.*\.(php|txt|htm|asp|aspx)",  # Remote file
    r"(include|require|include_once|require_once)\s*\(?\s*['\"]?https?://",
    r"file\s*=\s*(https?|ftp)://",
    r"page\s*=\s*https?://",
]

CMDI_PATTERNS = [
    r"[;&|`]\s*(ls|cat|id|whoami|uname|pwd|echo|wget|curl|nc|bash|sh|python|perl|ruby)",
    r"\$\(.*\)",                                          # Command substitution
    r"`[^`]+`",                                           # Backtick execution
    r"(;|\||&)\s*(cat|wget|curl|bash|nc|python)\s",
    r"\b(ping|nmap|traceroute)\s+-[a-z]",
    r"(\/bin\/|\/usr\/bin\/|cmd\.exe|powershell)",
    r"%0a\s*(id|whoami|ls|cat)",                         # Newline injection
    r"\|\s*nc\s+-e",                                     # Netcat reverse shell
]

DIR_TRAVERSAL_PATTERNS = [
    r"(\.\.\/){2,}",                                      # Multiple traversals
    r"(\.\.\\){2,}",
    r"(%2e%2e%2f){2,}",
    r"(%252e){2,}",                                       # Double-encoded
    r"(\.\.%2f){2,}",
]

ENCODED_ATTACK_PATTERNS = [
    r"%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}",  # Triple URL-encoded
    r"%25[0-9a-fA-F]{2}",                                 # Double URL-encoded
    r"\\u[0-9a-fA-F]{4}",                                 # Unicode escape
    r"&#x[0-9a-fA-F]+;",                                  # Hex HTML entities
    r"[A-Za-z0-9+/]{30,}={0,2}(?=\s|$|&|\")",           # Suspicious base64
    r"%c0%[0-9a-fA-F]{2}",                               # Overlong UTF-8
]

SUSPICIOUS_PATHS = [
    r"/\.env$", r"/\.git/", r"/wp-admin", r"/phpmyadmin",
    r"/admin/?$", r"\.php\.bak$", r"\.sql$", r"\.bak$",
    r"/server-status", r"/web\.config", r"composer\.json",
    r"\.htaccess$", r"/xmlrpc\.php", r"/cgi-bin/",
]

SUSPICIOUS_AGENTS = [
    r"sqlmap", r"nikto", r"nmap", r"masscan", r"dirbuster",
    r"acunetix", r"burpsuite", r"w3af", r"nessus", r"openvas",
    r"metasploit", r"hydra", r"medusa", r"gobuster", r"wfuzz",
]


# ─────────────────────────────────────────────
# LOG PARSER
# ─────────────────────────────────────────────

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<uri>\S+) \S+" '
    r'(?P<status>\d+) (?P<size>\d+) '
    r'"(?P<referer>[^"]*)" "(?P<agent>[^"]*)"'
)

def parse_log_line(line):
    m = LOG_PATTERN.match(line.strip())
    if not m:
        return None
    data = m.groupdict()
    data['uri_decoded'] = urllib.parse.unquote(data['uri'])
    data['status'] = int(data['status'])
    data['size'] = int(data['size'])
    return data


# ─────────────────────────────────────────────
# DETECTION FUNCTIONS
# ─────────────────────────────────────────────

def _match_patterns(text, patterns):
    """Return list of matched pattern strings"""
    text_lower = text.lower()
    matches = []
    for pattern in patterns:
        if re.search(pattern, text_lower, re.IGNORECASE):
            matches.append(pattern)
    return matches

def detect_sqli(entry):
    uri = entry['uri_decoded']
    hits = _match_patterns(uri, SQLI_PATTERNS)
    if hits:
        return {
            "type": "SQL_INJECTION",
            "severity": "CRITICAL",
            "ip": entry['ip'],
            "uri": entry['uri'],
            "matched_patterns": hits[:3],
            "description": "SQL injection attempt detected in URI parameters"
        }

def detect_xss(entry):
    uri = entry['uri_decoded']
    hits = _match_patterns(uri, XSS_PATTERNS)
    if hits:
        return {
            "type": "XSS",
            "severity": "HIGH",
            "ip": entry['ip'],
            "uri": entry['uri'],
            "matched_patterns": hits[:3],
            "description": "Cross-site scripting payload detected"
        }

def detect_lfi(entry):
    uri = entry['uri_decoded']
    hits = _match_patterns(uri, LFI_PATTERNS)
    if hits:
        return {
            "type": "LFI",
            "severity": "CRITICAL",
            "ip": entry['ip'],
            "uri": entry['uri'],
            "matched_patterns": hits[:3],
            "description": "Local file inclusion attempt detected"
        }

def detect_rfi(entry):
    uri = entry['uri_decoded']
    hits = _match_patterns(uri, RFI_PATTERNS)
    if hits:
        return {
            "type": "RFI",
            "severity": "CRITICAL",
            "ip": entry['ip'],
            "uri": entry['uri'],
            "matched_patterns": hits[:3],
            "description": "Remote file inclusion attempt detected"
        }

def detect_command_injection(entry):
    uri = entry['uri_decoded']
    hits = _match_patterns(uri, CMDI_PATTERNS)
    if hits:
        return {
            "type": "COMMAND_INJECTION",
            "severity": "CRITICAL",
            "ip": entry['ip'],
            "uri": entry['uri'],
            "matched_patterns": hits[:3],
            "description": "OS command injection attempt detected"
        }

def detect_dir_traversal(entry):
    uri = entry['uri_decoded']
    hits = _match_patterns(uri, DIR_TRAVERSAL_PATTERNS)
    if hits:
        return {
            "type": "DIR_TRAVERSAL",
            "severity": "HIGH",
            "ip": entry['ip'],
            "uri": entry['uri'],
            "matched_patterns": hits[:3],
            "description": "Directory traversal attempt detected"
        }

def detect_encoded_attacks(entry):
    uri = entry['uri']  # Raw (not decoded) to catch encoding
    hits = _match_patterns(uri, ENCODED_ATTACK_PATTERNS)
    if len(hits) >= 1:
        return {
            "type": "ENCODED_ATTACK",
            "severity": "HIGH",
            "ip": entry['ip'],
            "uri": entry['uri'],
            "matched_patterns": hits[:3],
            "description": "Suspicious encoding/obfuscation detected in request"
        }

def detect_suspicious_path(entry):
    uri = entry['uri'].lower()
    for pattern in SUSPICIOUS_PATHS:
        if re.search(pattern, uri, re.IGNORECASE):
            return {
                "type": "SUSPICIOUS_PATH",
                "severity": "MEDIUM",
                "ip": entry['ip'],
                "uri": entry['uri'],
                "matched_patterns": [pattern],
                "description": "Access to sensitive/admin path detected"
            }

def detect_suspicious_agent(entry):
    agent = entry.get('agent', '').lower()
    for pattern in SUSPICIOUS_AGENTS:
        if re.search(pattern, agent, re.IGNORECASE):
            return {
                "type": "SCANNER_TOOL",
                "severity": "HIGH",
                "ip": entry['ip'],
                "uri": entry['uri'],
                "agent": entry['agent'],
                "matched_patterns": [pattern],
                "description": f"Known attack tool user-agent detected: {pattern}"
            }

# ─────────────────────────────────────────────
# BEHAVIORAL / THRESHOLD DETECTIONS
# ─────────────────────────────────────────────

def detect_error_spike(logs, window_size=50, threshold=0.6):
    """Detect IPs generating >60% error rate over last N requests"""
    alerts = []
    ip_counter = defaultdict(list)
    for entry in logs:
        ip_counter[entry['ip']].append(entry['status'])

    for ip, statuses in ip_counter.items():
        if len(statuses) < 10:
            continue
        error_count = sum(1 for s in statuses if s >= 400)
        error_rate = error_count / len(statuses)
        if error_rate >= threshold:
            alerts.append({
                "type": "ERROR_SPIKE",
                "severity": "HIGH",
                "ip": ip,
                "total_requests": len(statuses),
                "error_count": error_count,
                "error_rate": f"{error_rate*100:.1f}%",
                "description": f"High error rate from {ip}: {error_rate*100:.1f}% errors over {len(statuses)} requests"
            })
    return alerts

def detect_brute_force(logs, max_requests=15, window_seconds=60):
    """Detect rapid repeated POST /login attempts (brute force)"""
    alerts = []
    ip_login_attempts = defaultdict(list)

    for entry in logs:
        if entry['method'] == 'POST' and '/login' in entry['uri']:
            ip_login_attempts[entry['ip']].append(entry['timestamp'])

    for ip, timestamps in ip_login_attempts.items():
        if len(timestamps) >= max_requests:
            alerts.append({
                "type": "BRUTE_FORCE",
                "severity": "CRITICAL",
                "ip": ip,
                "attempt_count": len(timestamps),
                "description": f"Brute force login detected: {len(timestamps)} POST /login requests from {ip}"
            })
    return alerts

def detect_request_spike(logs, threshold=30):
    """Detect IPs sending anomalously high request volumes"""
    alerts = []
    ip_counts = Counter(entry['ip'] for entry in logs)
    mean = sum(ip_counts.values()) / len(ip_counts) if ip_counts else 0

    for ip, count in ip_counts.items():
        if count > threshold and count > mean * 3:
            alerts.append({
                "type": "REQUEST_SPIKE",
                "severity": "MEDIUM",
                "ip": ip,
                "request_count": count,
                "average": f"{mean:.1f}",
                "description": f"Abnormal request volume: {count} requests from {ip} (avg: {mean:.1f})"
            })
    return alerts

def detect_4xx_cascade(logs, threshold=20):
    """Detect rapid 404 cascade (directory bruteforce / scanner)"""
    alerts = []
    ip_404 = defaultdict(int)
    for entry in logs:
        if entry['status'] == 404:
            ip_404[entry['ip']] += 1

    for ip, count in ip_404.items():
        if count >= threshold:
            alerts.append({
                "type": "404_CASCADE",
                "severity": "HIGH",
                "ip": ip,
                "count_404": count,
                "description": f"404 flood detected: {count} Not Found responses for {ip} — likely directory scanner"
            })
    return alerts


# ─────────────────────────────────────────────
# MAIN DETECTION ENGINE
# ─────────────────────────────────────────────

class SIEMDetectionEngine:
    def __init__(self):
        self.alerts = []
        self.per_request_detectors = [
            detect_sqli,
            detect_xss,
            detect_lfi,
            detect_rfi,
            detect_command_injection,
            detect_dir_traversal,
            detect_encoded_attacks,
            detect_suspicious_path,
            detect_suspicious_agent,
        ]

    def analyze_logs(self, log_file="sample_logs/web_access.log"):
        print("=" * 65)
        print("  SIEM DETECTION ENGINE — Analyzing Logs")
        print("=" * 65)

        parsed_logs = []
        with open(log_file, "r") as f:
            for line in f:
                entry = parse_log_line(line)
                if entry:
                    parsed_logs.append(entry)

        print(f"\n  [*] Parsed {len(parsed_logs)} log entries")

        # Per-request detections
        print("\n  [*] Running per-request signature detections...")
        for entry in parsed_logs:
            for detector in self.per_request_detectors:
                alert = detector(entry)
                if alert:
                    alert['timestamp'] = entry['timestamp']
                    self.alerts.append(alert)

        # Behavioral/threshold detections
        print("  [*] Running behavioral/threshold detections...")
        self.alerts.extend(detect_error_spike(parsed_logs))
        self.alerts.extend(detect_brute_force(parsed_logs))
        self.alerts.extend(detect_request_spike(parsed_logs))
        self.alerts.extend(detect_4xx_cascade(parsed_logs))

        return self.alerts

    def print_report(self):
        if not self.alerts:
            print("  No alerts generated.")
            return

        print(f"\n{'='*65}")
        print(f"  DETECTION REPORT — {len(self.alerts)} Alerts Found")
        print(f"{'='*65}")

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_alerts = sorted(self.alerts, key=lambda a: severity_order.get(a.get("severity", "LOW"), 3))

        severity_counts = Counter(a.get("severity", "UNKNOWN") for a in self.alerts)
        type_counts = Counter(a.get("type") for a in self.alerts)

        print("\n  [SEVERITY SUMMARY]")
        icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
        for sev, count in sorted(severity_counts.items(), key=lambda x: severity_order.get(x[0], 9)):
            print(f"    {icons.get(sev, '⚪')} {sev:<12}: {count}")

        print("\n  [ALERT TYPE BREAKDOWN]")
        for t, count in type_counts.most_common():
            bar = "▓" * min(count, 30)
            print(f"    {t:<25} {count:>4}  {bar}")

        print(f"\n  [TOP 20 ALERTS BY SEVERITY]")
        print(f"  {'─'*63}")
        for alert in sorted_alerts[:20]:
            sev = alert.get("severity", "?")
            atype = alert.get("type", "?")
            ip = alert.get("ip", "?")
            desc = alert.get("description", "")[:60]
            icon = icons.get(sev, "⚪")
            print(f"  {icon} [{sev:<8}] {atype:<22} {ip:<20}")
            print(f"         {desc}")
            if "matched_patterns" in alert:
                p = alert["matched_patterns"][0][:60] if alert["matched_patterns"] else ""
                print(f"         Pattern: {p}")
            print()

        # Save full report
        import os
        os.makedirs("sample_logs", exist_ok=True)
        with open("sample_logs/detection_alerts.json", "w") as f:
            json.dump(self.alerts, f, indent=2)
        print(f"  [✓] Full alerts saved to sample_logs/detection_alerts.json")

    def export_siem_rules(self):
        """Export detection rules in Sigma/Splunk/Elastic format"""
        rules = {
            "sigma_rules": [
                {
                    "name": "SQL Injection Attempt",
                    "logsource": {"category": "webserver"},
                    "detection": {
                        "keywords": ["' OR", "UNION SELECT", "DROP TABLE", "SLEEP(", "xp_cmdshell"],
                        "condition": "keywords"
                    },
                    "level": "critical"
                },
                {
                    "name": "XSS Attempt",
                    "logsource": {"category": "webserver"},
                    "detection": {
                        "keywords": ["<script>", "javascript:", "onerror=", "onload="],
                        "condition": "keywords"
                    },
                    "level": "high"
                },
                {
                    "name": "Directory Traversal",
                    "logsource": {"category": "webserver"},
                    "detection": {
                        "keywords": ["../", "%2e%2e%2f", "..%2f", "%252e%252e"],
                        "condition": "keywords"
                    },
                    "level": "high"
                },
            ],
            "splunk_queries": {
                "sqli": 'index=web_logs | where match(uri, "(?i)(union|select|insert|drop|sleep\\(|xp_cmdshell|\'\\s*or\\s*\'1\'=\'1)") | stats count by src_ip, uri | sort -count',
                "xss":  'index=web_logs | where match(uri, "(?i)(<script|javascript:|onerror=|onload=|alert\\()") | stats count by src_ip, uri | sort -count',
                "lfi":  'index=web_logs | where match(uri, "(\\.\\./|etc/passwd|etc/shadow|php://filter)") | stats count by src_ip, uri | sort -count',
                "error_spike": 'index=web_logs status>=400 | timechart span=1m count by src_ip | where count > 50',
                "brute_force": 'index=web_logs method=POST uri="/login" status=401 | stats count by src_ip | where count > 10 | sort -count',
                "scanner": 'index=web_logs | where match(user_agent, "(?i)(sqlmap|nikto|nmap|dirbuster|acunetix|burp)") | stats count by src_ip, user_agent | sort -count',
                "404_cascade": 'index=web_logs status=404 | stats count by src_ip | where count > 20 | sort -count',
            },
            "elastic_dsl": {
                "sqli_query": {
                    "query": {
                        "bool": {
                            "should": [
                                {"regexp": {"request": ".*(\\'|\\%27|union.*select|drop.*table|sleep\\().*"}},
                                {"match_phrase": {"request": "xp_cmdshell"}},
                                {"match_phrase": {"request": "information_schema"}},
                            ],
                            "minimum_should_match": 1
                        }
                    }
                },
                "brute_force_agg": {
                    "aggs": {
                        "login_attempts": {
                            "filter": {"bool": {"must": [
                                {"term": {"request.method": "POST"}},
                                {"term": {"request.url": "/login"}},
                                {"term": {"response": 401}}
                            ]}},
                            "aggs": {
                                "by_ip": {
                                    "terms": {"field": "clientip", "size": 10},
                                    "aggs": {"count": {"value_count": {"field": "clientip"}}}
                                }
                            }
                        }
                    }
                }
            }
        }

        with open("sample_logs/siem_rules_export.json", "w") as f:
            json.dump(rules, f, indent=2)
        print("\n  [✓] SIEM rules exported to sample_logs/siem_rules_export.json")
        return rules


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    engine = SIEMDetectionEngine()
    alerts = engine.analyze_logs()
    engine.print_report()
    engine.export_siem_rules()
