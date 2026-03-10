import yaml          # pip install pyyaml  (stdlib fallback included)
import json
from datetime import datetime
from collections import defaultdict

# ─────────────────────────────────────────────────────────
#  MITRE ATT&CK MAPPING TABLE
#  Source: https://attack.mitre.org/
# ─────────────────────────────────────────────────────────

MITRE_MAP = {
    "SQL_INJECTION": {
        "technique_id":   "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic":         "Initial Access",
        "tactic_id":      "TA0001",
        "sub_technique":  None,
        "description":    "Adversary exploits SQL injection to gain initial foothold or extract data.",
        "url":            "https://attack.mitre.org/techniques/T1190/",
        "mitigations":    ["M1048 - Application Isolation", "M1050 - Exploit Protection", "WAF Rules"],
        "data_sources":   ["Application Log", "Network Traffic"],
    },
    "XSS": {
        "technique_id":   "T1059.007",
        "technique_name": "Command and Scripting Interpreter: JavaScript",
        "tactic":         "Execution",
        "tactic_id":      "TA0002",
        "sub_technique":  "T1059.007",
        "description":    "Malicious scripts injected into web pages executed in victim's browser.",
        "url":            "https://attack.mitre.org/techniques/T1059/007/",
        "mitigations":    ["M1021 - Restrict Web-Based Content", "CSP Headers"],
        "data_sources":   ["Application Log", "Web Proxy"],
    },
    "LFI": {
        "technique_id":   "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic":         "Discovery",
        "tactic_id":      "TA0007",
        "sub_technique":  None,
        "description":    "Adversary uses path traversal to read local files (passwd, configs).",
        "url":            "https://attack.mitre.org/techniques/T1083/",
        "mitigations":    ["M1035 - Limit Access to Resource over Network", "Input Validation"],
        "data_sources":   ["Application Log", "File System"],
    },
    "RFI": {
        "technique_id":   "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic":         "Initial Access",
        "tactic_id":      "TA0001",
        "sub_technique":  None,
        "description":    "Remote file inclusion to execute malicious remote code.",
        "url":            "https://attack.mitre.org/techniques/T1190/",
        "mitigations":    ["M1048 - Application Isolation", "Disable allow_url_include"],
        "data_sources":   ["Application Log", "Network Traffic"],
    },
    "COMMAND_INJECTION": {
        "technique_id":   "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic":         "Execution",
        "tactic_id":      "TA0002",
        "sub_technique":  "T1059.004",
        "description":    "OS commands injected via web parameters for remote code execution.",
        "url":            "https://attack.mitre.org/techniques/T1059/",
        "mitigations":    ["M1038 - Execution Prevention", "Input Sanitization"],
        "data_sources":   ["Command", "Process", "Application Log"],
    },
    "DIR_TRAVERSAL": {
        "technique_id":   "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic":         "Discovery",
        "tactic_id":      "TA0007",
        "sub_technique":  None,
        "description":    "Directory traversal sequences to access files outside webroot.",
        "url":            "https://attack.mitre.org/techniques/T1083/",
        "mitigations":    ["M1035 - Limit File Access", "Canonicalize Paths"],
        "data_sources":   ["Application Log", "File System"],
    },
    "ENCODED_ATTACK": {
        "technique_id":   "T1027",
        "technique_name": "Obfuscated Files or Information",
        "tactic":         "Defense Evasion",
        "tactic_id":      "TA0005",
        "sub_technique":  "T1027.010",
        "description":    "Payloads encoded (base64, double URL, unicode) to evade WAF/IDS.",
        "url":            "https://attack.mitre.org/techniques/T1027/",
        "mitigations":    ["M1049 - Antivirus/Antimalware", "Deep Packet Inspection"],
        "data_sources":   ["Application Log", "Network Traffic Content"],
    },
    "BRUTE_FORCE": {
        "technique_id":   "T1110",
        "technique_name": "Brute Force",
        "tactic":         "Credential Access",
        "tactic_id":      "TA0006",
        "sub_technique":  "T1110.001",
        "description":    "Automated password guessing against login endpoints.",
        "url":            "https://attack.mitre.org/techniques/T1110/",
        "mitigations":    ["M1036 - Account Use Policies", "M1032 - MFA", "Rate Limiting"],
        "data_sources":   ["Application Log", "Authentication Log"],
    },
    "SCANNER_TOOL": {
        "technique_id":   "T1595",
        "technique_name": "Active Scanning",
        "tactic":         "Reconnaissance",
        "tactic_id":      "TA0043",
        "sub_technique":  "T1595.002",
        "description":    "Automated vulnerability scanner probing the web application.",
        "url":            "https://attack.mitre.org/techniques/T1595/",
        "mitigations":    ["M1056 - Pre-compromise", "WAF Bot Protection"],
        "data_sources":   ["Network Traffic", "Application Log"],
    },
    "ERROR_SPIKE": {
        "technique_id":   "T1595",
        "technique_name": "Active Scanning",
        "tactic":         "Reconnaissance",
        "tactic_id":      "TA0043",
        "sub_technique":  "T1595.001",
        "description":    "High error-rate scanning activity suggesting automated probing.",
        "url":            "https://attack.mitre.org/techniques/T1595/",
        "mitigations":    ["Rate Limiting", "IP Reputation Blocking"],
        "data_sources":   ["Network Traffic", "Application Log"],
    },
    "404_CASCADE": {
        "technique_id":   "T1595",
        "technique_name": "Active Scanning",
        "tactic":         "Reconnaissance",
        "tactic_id":      "TA0043",
        "sub_technique":  "T1595.001",
        "description":    "Rapid 404 generation from directory brute-force tools.",
        "url":            "https://attack.mitre.org/techniques/T1595/",
        "mitigations":    ["DirBuster Signatures", "Rate Limiting", "Honeypot Paths"],
        "data_sources":   ["Application Log"],
    },
    "REQUEST_SPIKE": {
        "technique_id":   "T1499",
        "technique_name": "Endpoint Denial of Service",
        "tactic":         "Impact",
        "tactic_id":      "TA0040",
        "sub_technique":  "T1499.002",
        "description":    "Abnormal request volume from single IP — possible DDoS or scraping.",
        "url":            "https://attack.mitre.org/techniques/T1499/",
        "mitigations":    ["M1037 - Filter Network Traffic", "CDN Rate Limiting"],
        "data_sources":   ["Network Traffic", "Application Log"],
    },
}

# ─────────────────────────────────────────────────────────
#  RISK SCORING TABLE
#  Base score 0–10, modifiers applied at runtime
# ─────────────────────────────────────────────────────────

BASE_SCORES = {
    "SQL_INJECTION":     9.0,
    "COMMAND_INJECTION": 10.0,
    "LFI":               8.5,
    "RFI":               9.5,
    "XSS":               7.0,
    "DIR_TRAVERSAL":     7.5,
    "ENCODED_ATTACK":    7.0,
    "BRUTE_FORCE":       8.0,
    "SCANNER_TOOL":      5.0,
    "ERROR_SPIKE":       5.5,
    "404_CASCADE":       4.5,
    "REQUEST_SPIKE":     4.0,
}

SCORE_MODIFIERS = {
    "tor_node":          +1.5,   # IP is TOR exit node
    "vpn_proxy":         +0.8,   # IP is VPN/proxy
    "known_malicious":   +2.0,   # IP in threat DB (score >= 80)
    "suspicious":        +0.5,   # IP score 50-79
    "500_response":      +0.5,   # Got 500 = possible successful exploit
    "encoded_payload":   +0.3,   # Encoding = evasion attempt
    "multi_attack":      +1.0,   # Same IP doing multiple attack types
    "after_hours":       +0.2,   # Attack at night (22:00-06:00 UTC)
    "internal_src":      -1.0,   # Internal IP (lower base concern)
}

THREAT_LEVEL_THRESHOLDS = [
    (90,  "CRITICAL",  "#ff1744"),
    (70,  "HIGH",      "#ff6d00"),
    (45,  "MEDIUM",    "#ffd600"),
    (20,  "LOW",       "#00e676"),
    (0,   "INFO",      "#00b0ff"),
]


# ─────────────────────────────────────────────────────────
#  RISK SCORER
# ─────────────────────────────────────────────────────────

class RiskScorer:
    def __init__(self):
        self.ip_registry = defaultdict(lambda: {
            "attacks": [], "total_score": 0.0, "attack_types": set()
        })

    def score_alert(self, alert: dict) -> dict:
        """Score a single alert, returns alert with risk metadata attached."""
        attack_type = alert.get("type", "UNKNOWN")
        base  = BASE_SCORES.get(attack_type, 5.0)
        mods  = []
        total = base

        intel = alert.get("threat_intel", {})
        if intel:
            rep = intel.get("reputation_score", 0)
            if intel.get("is_tor"):
                total += SCORE_MODIFIERS["tor_node"]
                mods.append(f"TOR+{SCORE_MODIFIERS['tor_node']}")
            if intel.get("is_vpn"):
                total += SCORE_MODIFIERS["vpn_proxy"]
                mods.append(f"VPN+{SCORE_MODIFIERS['vpn_proxy']}")
            if rep >= 80:
                total += SCORE_MODIFIERS["known_malicious"]
                mods.append(f"KnownBad+{SCORE_MODIFIERS['known_malicious']}")
            elif rep >= 50:
                total += SCORE_MODIFIERS["suspicious"]
                mods.append(f"Suspicious+{SCORE_MODIFIERS['suspicious']}")

        if alert.get("status") == 500:
            total += SCORE_MODIFIERS["500_response"]
            mods.append(f"500Resp+{SCORE_MODIFIERS['500_response']}")

        if attack_type == "ENCODED_ATTACK":
            total += SCORE_MODIFIERS["encoded_payload"]
            mods.append(f"Encoded+{SCORE_MODIFIERS['encoded_payload']}")

        if alert.get("ip", "").startswith(("10.", "172.16.", "192.168.")):
            total += SCORE_MODIFIERS["internal_src"]
            mods.append(f"Internal{SCORE_MODIFIERS['internal_src']}")

        total = max(0.0, min(10.0, total))

        # Register with IP registry
        ip = alert.get("ip", "")
        reg = self.ip_registry[ip]
        reg["attacks"].append({"type": attack_type, "score": total, "ts": alert.get("timestamp", "")})
        reg["total_score"] += total
        reg["attack_types"].add(attack_type)

        alert["risk"] = {
            "base_score":   round(base, 1),
            "final_score":  round(total, 1),
            "modifiers":    mods,
            "score_pct":    round(total * 10, 0),  # 0–100 scale
            "threat_level": self._level(total * 10),
        }
        return alert

    def ip_risk_summary(self, ip: str) -> dict:
        """Aggregate risk score for a given IP address."""
        reg = self.ip_registry.get(ip)
        if not reg or not reg["attacks"]:
            return {"ip": ip, "total_score": 0, "threat_level": "INFO", "attacks": 0}

        total   = reg["total_score"]
        count   = len(reg["attacks"])
        types   = list(reg["attack_types"])
        avg     = total / count

        # Multi-attack bonus
        if len(types) > 2:
            total += SCORE_MODIFIERS["multi_attack"] * (len(types) - 2)

        return {
            "ip":            ip,
            "total_score":   round(total, 1),
            "avg_score":     round(avg, 1),
            "attacks":       count,
            "attack_types":  types,
            "threat_level":  self._level(total),
            "color":         self._color(total),
        }

    def all_ip_summaries(self) -> list:
        ips = list(self.ip_registry.keys())
        summaries = [self.ip_risk_summary(ip) for ip in ips]
        return sorted(summaries, key=lambda x: x["total_score"], reverse=True)

    def _level(self, score: float) -> str:
        for threshold, label, _ in THREAT_LEVEL_THRESHOLDS:
            if score >= threshold:
                return label
        return "INFO"

    def _color(self, score: float) -> str:
        for threshold, _, color in THREAT_LEVEL_THRESHOLDS:
            if score >= threshold:
                return color
        return "#00b0ff"

    def print_ip_leaderboard(self):
        summaries = self.all_ip_summaries()
        print(f"\n{'═'*65}")
        print(f"  IP RISK LEADERBOARD — Top Threat Sources")
        print(f"{'═'*65}")
        print(f"  {'IP ADDRESS':<22} {'SCORE':>7}  {'ATTACKS':>7}  {'TYPES':>5}  THREAT")
        print(f"  {'─'*63}")
        for s in summaries[:10]:
            bar = "█" * min(int(s["total_score"] / 5), 20)
            print(f"  {s['ip']:<22} {s['total_score']:>7.1f}  {s['attacks']:>7}  "
                  f"{len(s['attack_types']):>5}  [{s['threat_level']}]  {bar}")


# ─────────────────────────────────────────────────────────
#  MITRE MAPPER
# ─────────────────────────────────────────────────────────

class MITREMapper:
    def map(self, attack_type: str) -> dict:
        return MITRE_MAP.get(attack_type, {
            "technique_id":   "T0000",
            "technique_name": "Unknown Technique",
            "tactic":         "Unknown",
            "tactic_id":      "TA0000",
            "sub_technique":  None,
            "description":    "No MITRE mapping available.",
            "url":            "https://attack.mitre.org/",
            "mitigations":    [],
            "data_sources":   [],
        })

    def annotate_alert(self, alert: dict) -> dict:
        mitre = self.map(alert.get("type", "UNKNOWN"))
        alert["mitre"] = mitre
        return alert

    def print_mapping_table(self):
        print(f"\n{'═'*80}")
        print(f"  MITRE ATT&CK MAPPING TABLE")
        print(f"{'═'*80}")
        print(f"  {'ATTACK TYPE':<25} {'TECH ID':<12} {'TECHNIQUE':<35} TACTIC")
        print(f"  {'─'*78}")
        for atype, m in MITRE_MAP.items():
            tid = m["sub_technique"] or m["technique_id"]
            print(f"  {atype:<25} {tid:<12} {m['technique_name'][:33]:<35} {m['tactic']}")


# ─────────────────────────────────────────────────────────
#  SIGMA RULE EXPORTER
# ─────────────────────────────────────────────────────────

SIGMA_TEMPLATES = {
    "SQL_INJECTION": {
        "title": "SQL Injection Attempt via Web Application",
        "id": "b5e3b7d1-9e4a-4c8f-8b2d-1a5f3e7c9d0b",
        "status": "stable",
        "description": "Detects SQL injection patterns in web server request URIs.",
        "author": "WebGuard SIEM",
        "date": "2024/11/22",
        "references": ["https://attack.mitre.org/techniques/T1190/", "https://owasp.org/www-community/attacks/SQL_Injection"],
        "tags": ["attack.initial_access", "attack.t1190", "owasp.a03_2021"],
        "logsource": {"category": "webserver"},
        "detection": {
            "selection": {
                "c-uri|contains": [
                    "' OR '", "' OR 1=1", "UNION SELECT", "UNION ALL SELECT",
                    "DROP TABLE", "INSERT INTO", "SLEEP(", "BENCHMARK(",
                    "xp_cmdshell", "information_schema", "' --", "';--",
                ]
            },
            "condition": "selection"
        },
        "falsepositives": ["Security scanning tools", "Penetration testing"],
        "level": "critical",
        "fields": ["c-ip", "c-uri", "cs-User-Agent", "sc-status"]
    },
    "XSS": {
        "title": "Cross-Site Scripting (XSS) Attempt",
        "id": "a4c2e9f0-8d3b-4e7a-9c1f-2b6d8e0f4a2c",
        "status": "stable",
        "description": "Detects XSS attack patterns in web request parameters.",
        "author": "WebGuard SIEM",
        "date": "2024/11/22",
        "references": ["https://attack.mitre.org/techniques/T1059/007/"],
        "tags": ["attack.execution", "attack.t1059.007", "owasp.a03_2021"],
        "logsource": {"category": "webserver"},
        "detection": {
            "selection": {
                "c-uri|contains": [
                    "<script>", "%3Cscript", "javascript:", "onerror=",
                    "onload=", "alert(", "document.cookie", "<svg/onload",
                    "<img src=x", "&#x3C;script",
                ]
            },
            "condition": "selection"
        },
        "falsepositives": ["WAF testing", "Security training platforms"],
        "level": "high",
        "fields": ["c-ip", "c-uri", "cs-User-Agent", "sc-status"]
    },
    "LFI": {
        "title": "Local File Inclusion / Path Traversal Attempt",
        "id": "c7f1a3e5-2b8d-4f9c-a0e6-3d5b7c9e1f4a",
        "status": "stable",
        "description": "Detects LFI and directory traversal attacks in web URIs.",
        "author": "WebGuard SIEM",
        "date": "2024/11/22",
        "references": ["https://attack.mitre.org/techniques/T1083/"],
        "tags": ["attack.discovery", "attack.t1083", "owasp.a01_2021"],
        "logsource": {"category": "webserver"},
        "detection": {
            "selection": {
                "c-uri|contains": [
                    "../", "..%2f", "%2e%2e%2f", "%252e%252e",
                    "etc/passwd", "etc/shadow", "php://filter",
                    "php://input", "/proc/self", "....//",
                ]
            },
            "condition": "selection"
        },
        "falsepositives": ["Legitimate file operations with relative paths"],
        "level": "critical",
        "fields": ["c-ip", "c-uri", "cs-User-Agent", "sc-status"]
    },
    "COMMAND_INJECTION": {
        "title": "OS Command Injection via Web Application",
        "id": "d9e2b4f6-3c7a-4b8e-9d1f-5a8c0e3f7b2d",
        "status": "stable",
        "description": "Detects OS command injection patterns in web request parameters.",
        "author": "WebGuard SIEM",
        "date": "2024/11/22",
        "references": ["https://attack.mitre.org/techniques/T1059/"],
        "tags": ["attack.execution", "attack.t1059", "owasp.a03_2021"],
        "logsource": {"category": "webserver"},
        "detection": {
            "selection": {
                "c-uri|contains": [
                    "; ls", "; cat", "| id", "| whoami", "`id`", "$(whoami)",
                    "; wget ", "; curl ", "| nc -e", "/bin/bash", "/bin/sh",
                    "cmd.exe", "powershell",
                ]
            },
            "condition": "selection"
        },
        "falsepositives": ["None expected in production"],
        "level": "critical",
        "fields": ["c-ip", "c-uri", "cs-User-Agent", "sc-status"]
    },
    "BRUTE_FORCE": {
        "title": "Web Application Brute Force Login Attempt",
        "id": "e1c3f5a7-4d9b-4c2e-8f6a-7b9d1f3e5c8a",
        "status": "stable",
        "description": "Detects rapid repeated POST requests to login endpoints indicating brute force.",
        "author": "WebGuard SIEM",
        "date": "2024/11/22",
        "references": ["https://attack.mitre.org/techniques/T1110/001/"],
        "tags": ["attack.credential_access", "attack.t1110.001"],
        "logsource": {"category": "webserver"},
        "detection": {
            "selection": {
                "cs-method": "POST",
                "c-uri|endswith": ["/login", "/signin", "/auth", "/wp-login.php"],
                "sc-status": 401
            },
            "timeframe": "1m",
            "condition": "selection | count() by c-ip > 10"
        },
        "falsepositives": ["Legitimate users mistyping passwords"],
        "level": "high",
        "fields": ["c-ip", "c-uri", "sc-status", "cs-User-Agent"]
    },
    "SCANNER_TOOL": {
        "title": "Web Vulnerability Scanner Detected",
        "id": "f2d4a6c8-5e0b-4d3f-9a7c-8e2f4a6b0d1e",
        "status": "stable",
        "description": "Detects known vulnerability scanner user-agent strings.",
        "author": "WebGuard SIEM",
        "date": "2024/11/22",
        "references": ["https://attack.mitre.org/techniques/T1595/002/"],
        "tags": ["attack.reconnaissance", "attack.t1595.002"],
        "logsource": {"category": "webserver"},
        "detection": {
            "selection": {
                "cs-User-Agent|contains": [
                    "sqlmap", "nikto", "nmap", "masscan", "dirbuster",
                    "gobuster", "wfuzz", "acunetix", "burp", "w3af",
                    "nessus", "openvas", "metasploit", "hydra",
                ]
            },
            "condition": "selection"
        },
        "falsepositives": ["Authorized penetration testing"],
        "level": "high",
        "fields": ["c-ip", "cs-User-Agent", "c-uri", "sc-status"]
    },
    "ENCODED_ATTACK": {
        "title": "Encoded/Obfuscated Web Attack Payload",
        "id": "a3b5c7d9-6f1e-4a2b-8c0d-9e3f5b7a1c4e",
        "status": "experimental",
        "description": "Detects double/triple URL encoding and other obfuscation techniques used to evade WAF.",
        "author": "WebGuard SIEM",
        "date": "2024/11/22",
        "references": ["https://attack.mitre.org/techniques/T1027/"],
        "tags": ["attack.defense_evasion", "attack.t1027"],
        "logsource": {"category": "webserver"},
        "detection": {
            "selection": {
                "c-uri|contains": [
                    "%252e", "%2527", "%c0%af", "\\u003c", "&#x3C;", "%25%32",
                ]
            },
            "condition": "selection"
        },
        "falsepositives": ["Legitimate multi-encoded content"],
        "level": "high",
        "fields": ["c-ip", "c-uri", "sc-status"]
    },
}


class SigmaExporter:
    def export_rule(self, attack_type: str) -> str:
        """Export a single Sigma rule as YAML string."""
        template = SIGMA_TEMPLATES.get(attack_type)
        if not template:
            return f"# No Sigma rule template for {attack_type}\n"
        try:
            import yaml
            return yaml.dump(template, default_flow_style=False, allow_unicode=True, sort_keys=False)
        except ImportError:
            # Manual YAML serialization fallback (no pyyaml needed)
            return self._manual_yaml(template)

    def export_all(self, output_dir: str = "sigma_rules") -> list:
        """Export all Sigma rules to individual YAML files."""
        import os
        os.makedirs(output_dir, exist_ok=True)
        files = []
        for attack_type, template in SIGMA_TEMPLATES.items():
            filename = f"{output_dir}/rule_{attack_type.lower()}.yml"
            with open(filename, "w") as f:
                f.write(f"# Sigma Rule — {template['title']}\n")
                f.write(f"# Generated by WebGuard SIEM | {datetime.utcnow().date()}\n\n")
                f.write(self.export_rule(attack_type))
            files.append(filename)
            print(f"  [✓] {filename}")
        return files

    def _manual_yaml(self, d: dict, indent: int = 0) -> str:
        """Minimal YAML serializer fallback."""
        lines = []
        prefix = "  " * indent
        for k, v in d.items():
            if isinstance(v, dict):
                lines.append(f"{prefix}{k}:")
                lines.append(self._manual_yaml(v, indent + 1))
            elif isinstance(v, list):
                lines.append(f"{prefix}{k}:")
                for item in v:
                    if isinstance(item, str):
                        lines.append(f"{prefix}  - '{item}'")
                    else:
                        lines.append(f"{prefix}  - {item}")
            elif v is None:
                lines.append(f"{prefix}{k}: null")
            elif isinstance(v, bool):
                lines.append(f"{prefix}{k}: {'true' if v else 'false'}")
            else:
                val = f'"{v}"' if isinstance(v, str) and any(c in v for c in ': #\n') else v
                lines.append(f"{prefix}{k}: {val}")
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────
#  CLI DEMO
# ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    mapper = MITREMapper()
    scorer = RiskScorer()
    sigma  = SigmaExporter()

    mapper.print_mapping_table()

    # Demo scoring
    print("\n\n  [RISK SCORING DEMO]")
    demo_alerts = [
        {"type": "SQL_INJECTION",     "ip": "185.220.101.45", "status": 200,
         "threat_intel": {"reputation_score": 97, "is_tor": True, "is_vpn": False}},
        {"type": "COMMAND_INJECTION", "ip": "185.220.101.45", "status": 500,
         "threat_intel": {"reputation_score": 97, "is_tor": True, "is_vpn": False}},
        {"type": "BRUTE_FORCE",       "ip": "45.33.32.156",   "status": 401,
         "threat_intel": {"reputation_score": 72, "is_tor": False, "is_vpn": False}},
        {"type": "XSS",               "ip": "198.51.100.12",  "status": 200,
         "threat_intel": {"reputation_score": 88, "is_tor": False, "is_vpn": True}},
        {"type": "SCANNER_TOOL",      "ip": "45.33.32.156",   "status": 404,
         "threat_intel": {"reputation_score": 72, "is_tor": False, "is_vpn": False}},
    ]

    for alert in demo_alerts:
        scored = scorer.score_alert(mapper.annotate_alert(alert))
        r = scored["risk"]
        m = scored["mitre"]
        print(f"\n  {'─'*55}")
        print(f"  Attack : {scored['type']}")
        print(f"  MITRE  : {m['technique_id']} — {m['technique_name']}")
        print(f"  Tactic : {m['tactic']} ({m['tactic_id']})")
        print(f"  Score  : {r['base_score']} base → {r['final_score']}/10 final [{r['threat_level']}]")
        if r["modifiers"]:
            print(f"  Mods   : {', '.join(r['modifiers'])}")

    scorer.print_ip_leaderboard()

    print("\n\n  [SIGMA RULE EXPORT]")
    sigma.export_all("sigma_rules")
