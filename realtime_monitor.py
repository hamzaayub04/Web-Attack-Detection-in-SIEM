import re
import os
import sys
import json
import time
import random
import signal
import argparse
import threading
import urllib.parse
from datetime import datetime
from collections import defaultdict, deque

# Import our modules
try:
    from threat_intel import ThreatIntelEnricher
    from mitre_risk   import MITREMapper, RiskScorer, SigmaExporter
except ImportError:
    print("[!] Run from the web-attack-siem-v2/ directory.")
    sys.exit(1)

# ─────────────────────────────────────────────────────────
#  LOG PARSER (Apache Combined Format)
# ─────────────────────────────────────────────────────────

LOG_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<uri>\S+) \S+" '
    r'(?P<status>\d+) (?P<size>\d+) '
    r'"(?P<referer>[^"]*)" "(?P<agent>[^"]*)"'
)

def parse_line(line: str) -> dict | None:
    m = LOG_RE.match(line.strip())
    if not m:
        return None
    d = m.groupdict()
    d['uri_dec'] = urllib.parse.unquote(d['uri'])
    d['status']  = int(d['status'])
    d['size']    = int(d['size'])
    return d

# ─────────────────────────────────────────────────────────
#  SIGNATURE PATTERNS (inline — no dependency on file 1)
# ─────────────────────────────────────────────────────────

PATTERNS = {
    "SQL_INJECTION":     [r"(\bOR\b|\bAND\b)\s+[\'\d][\s\S]*=|union\s+select|drop\s+table|sleep\s*\(|xp_cmdshell|information_schema|'|--|;%20select", ],
    "XSS":               [r"<\s*script|javascript\s*:|on\w+\s*=|alert\s*\(|document\.(cookie|write)|%3Cscript|&#x?[0-9a-fA-F]+;"],
    "LFI":               [r"\.\./|\.\.\\|%2e%2e%2f|etc/passwd|etc/shadow|php://filter|/proc/self|%252e%252e|data://"],
    "COMMAND_INJECTION": [r"[;&|`]\s*(ls|cat|id|whoami|wget|curl|nc|bash)|`[^`]+`|\$\(|\|.*nc\s+-e"],
    "DIR_TRAVERSAL":     [r"(\.\.\/){2,}|(\.\.\\){2,}|(%2e%2e%2f){2,}"],
    "ENCODED_ATTACK":    [r"%25[0-9a-fA-F]{2}|%252e|\\u003c|&#x[0-9a-fA-F]+;|%c0%[0-9a-fA-F]{2}"],
    "SUSPICIOUS_PATH":   [r"/(\.env|\.git|wp-admin|phpmyadmin|admin|backup\.zip|\.htaccess|web\.config|composer\.json|server-status)(/?$|/)"],
    "SCANNER_TOOL":      [r"(?i)(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wfuzz|acunetix|burp|w3af|nessus|openvas)"],
}

SEV_MAP = {
    "SQL_INJECTION": "CRITICAL", "COMMAND_INJECTION": "CRITICAL", "LFI": "CRITICAL",
    "XSS": "HIGH", "DIR_TRAVERSAL": "HIGH", "ENCODED_ATTACK": "HIGH",
    "SCANNER_TOOL": "HIGH", "SUSPICIOUS_PATH": "MEDIUM",
}

def detect_line(entry: dict) -> list:
    """Return list of alert dicts for a single log entry."""
    alerts = []
    text_uri   = entry['uri_dec'].lower()
    text_agent = entry.get('agent', '').lower()

    for atype, pats in PATTERNS.items():
        target = text_agent if atype == "SCANNER_TOOL" else text_uri
        for pat in pats:
            if re.search(pat, target, re.IGNORECASE):
                alerts.append({
                    "type":      atype,
                    "severity":  SEV_MAP.get(atype, "MEDIUM"),
                    "ip":        entry["ip"],
                    "uri":       entry["uri"],
                    "method":    entry["method"],
                    "status":    entry["status"],
                    "agent":     entry["agent"],
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "log_ts":    entry["ts"],
                })
                break
    return alerts

# ─────────────────────────────────────────────────────────
#  BEHAVIORAL TRACKERS  (stateful counters per IP)
# ─────────────────────────────────────────────────────────

class BehaviorTracker:
    """Sliding-window behavioral detection (brute force, error spikes, 404 flood)."""

    WINDOW  = 120   # seconds
    BF_THRESH  = 10   # POST /login failures
    ERR_THRESH = 25   # total 4xx/5xx
    F404_THRESH= 20   # 404 count

    def __init__(self):
        self.login_fails = defaultdict(deque)   # ip → deque of timestamps
        self.errors      = defaultdict(deque)
        self.not_found   = defaultdict(deque)

    def _prune(self, dq: deque, now: float):
        while dq and now - dq[0] > self.WINDOW:
            dq.popleft()

    def update(self, entry: dict) -> list:
        now   = time.time()
        ip    = entry["ip"]
        alerts = []

        if entry["method"] == "POST" and "/login" in entry["uri"] and entry["status"] == 401:
            q = self.login_fails[ip]
            q.append(now)
            self._prune(q, now)
            if len(q) >= self.BF_THRESH:
                alerts.append({
                    "type": "BRUTE_FORCE", "severity": "CRITICAL", "ip": ip,
                    "uri": entry["uri"], "method": "POST", "status": 401,
                    "agent": entry.get("agent",""),
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "log_ts": entry["ts"],
                    "meta": f"{len(q)} login failures in {self.WINDOW}s window"
                })

        if entry["status"] >= 400:
            q = self.errors[ip]
            q.append(now)
            self._prune(q, now)
            if len(q) >= self.ERR_THRESH:
                alerts.append({
                    "type": "ERROR_SPIKE", "severity": "HIGH", "ip": ip,
                    "uri": entry["uri"], "method": entry["method"],
                    "status": entry["status"], "agent": entry.get("agent",""),
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "log_ts": entry["ts"],
                    "meta": f"{len(q)} errors in {self.WINDOW}s window"
                })

        if entry["status"] == 404:
            q = self.not_found[ip]
            q.append(now)
            self._prune(q, now)
            if len(q) >= self.F404_THRESH:
                alerts.append({
                    "type": "404_CASCADE", "severity": "HIGH", "ip": ip,
                    "uri": entry["uri"], "method": entry["method"], "status": 404,
                    "agent": entry.get("agent",""),
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "log_ts": entry["ts"],
                    "meta": f"{len(q)} 404s in {self.WINDOW}s window"
                })
        return alerts


# ─────────────────────────────────────────────────────────
#  CONSOLE ALERT PRINTER
# ─────────────────────────────────────────────────────────

SEV_COLORS = {
    "CRITICAL": "\033[91m",   # red
    "HIGH":     "\033[33m",   # yellow
    "MEDIUM":   "\033[93m",   # bright yellow
    "LOW":      "\033[92m",   # green
}
RESET = "\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2m"
CYAN  = "\033[96m"
GREEN = "\033[92m"

def print_alert(alert: dict):
    sev   = alert.get("severity", "LOW")
    col   = SEV_COLORS.get(sev, "")
    intel = alert.get("threat_intel", {})
    mitre = alert.get("mitre", {})
    risk  = alert.get("risk", {})

    ts = datetime.utcnow().strftime("%H:%M:%S")
    print(f"\n{col}{BOLD}{'▓'*65}{RESET}")
    print(f"{col}{BOLD}  🚨 [{sev}] {alert['type'].replace('_',' ')} DETECTED  [{ts} UTC]{RESET}")
    print(f"{col}{'▓'*65}{RESET}")

    print(f"  {DIM}Source IP  :{RESET} {CYAN}{alert['ip']}{RESET}")

    if intel:
        flags = " ".join(intel.get("flags", []))
        print(f"  {DIM}Country    :{RESET} {intel.get('country','?')} ({intel.get('country_code','??')}) {flags}")
        print(f"  {DIM}ASN / ISP  :{RESET} {intel.get('asn','?')} — {intel.get('hosting','?')}")
        print(f"  {DIM}Reputation :{RESET} {intel.get('reputation_score',0)}/100 [{intel.get('threat_level','?')}] "
              f"| {intel.get('reports_count',0)} abuse reports")

    print(f"  {DIM}URI        :{RESET} {alert.get('uri','')[:80]}")
    print(f"  {DIM}Method     :{RESET} {alert.get('method','')}  Status: {alert.get('status','')}")
    print(f"  {DIM}Agent      :{RESET} {alert.get('agent','')[:60]}")

    if mitre:
        print(f"  {DIM}MITRE      :{RESET} {GREEN}{mitre.get('technique_id','?')}{RESET} — "
              f"{mitre.get('technique_name','?')}")
        print(f"  {DIM}Tactic     :{RESET} {mitre.get('tactic','?')} ({mitre.get('tactic_id','?')})")

    if risk:
        bar_len = int(risk.get("final_score", 0) * 3)
        bar = f"{col}{'█' * bar_len}{RESET}{'░' * (30 - bar_len)}"
        print(f"  {DIM}Risk Score :{RESET} {bar} {col}{BOLD}{risk.get('final_score',0)}/10 [{risk.get('threat_level','?')}]{RESET}")

    if "meta" in alert:
        print(f"  {DIM}Context    :{RESET} {alert['meta']}")


# ─────────────────────────────────────────────────────────
#  REAL-TIME LOG MONITOR
# ─────────────────────────────────────────────────────────

class RealtimeMonitor:
    def __init__(self,
                 log_file: str = "sample_logs/web_access.log",
                 alert_out: str = "sample_logs/rt_alerts.json",
                 ipinfo_token: str = None,
                 abuseipdb_key: str = None):

        self.log_file  = log_file
        self.alert_out = alert_out
        self.enricher  = ThreatIntelEnricher(ipinfo_token=ipinfo_token,
                                              abuseipdb_key=abuseipdb_key,
                                              offline_mode=True)
        self.mapper    = MITREMapper()
        self.scorer    = RiskScorer()
        self.tracker   = BehaviorTracker()
        self.running   = True
        self.stats     = defaultdict(int)
        self.all_alerts= []

    def start(self):
        print(f"\n{BOLD}{CYAN}{'═'*65}")
        print(f"  WebGuard SIEM — Real-Time Log Monitor")
        print(f"  Watching: {self.log_file}")
        print(f"  Press Ctrl+C to stop")
        print(f"{'═'*65}{RESET}\n")

        signal.signal(signal.SIGINT, self._shutdown)

        try:
            self._tail_file()
        except KeyboardInterrupt:
            self._shutdown(None, None)

    def _tail_file(self):
        """Tail the log file like `tail -f`, then block waiting for new lines."""
        if not os.path.exists(self.log_file):
            print(f"[!] Log file not found: {self.log_file}")
            print(f"    Run 2_generate_logs.py first, or use --simulate flag")
            return

        # First pass: skip existing content (seek to end)
        with open(self.log_file, "r") as f:
            f.seek(0, 2)   # seek to EOF
            print(f"  [*] Tailing {self.log_file} — waiting for new entries...\n")

            while self.running:
                line = f.readline()
                if not line:
                    time.sleep(0.05)
                    continue
                self._process_line(line)

    def _process_line(self, line: str):
        entry = parse_line(line)
        if not entry:
            return

        self.stats["total"] += 1
        alerts = detect_line(entry) + self.tracker.update(entry)

        for alert in alerts:
            # Deduplicate: skip same type from same IP within 5s
            key = f"{alert['ip']}:{alert['type']}"
            if hasattr(self, '_seen'):
                if key in self._seen and time.time() - self._seen[key] < 5:
                    continue
            else:
                self._seen = {}
            self._seen[key] = time.time()

            # Enrich → Score → MITRE
            alert = self.enricher.enrich_alert(alert)
            alert = self.scorer.score_alert(self.mapper.annotate_alert(alert))

            print_alert(alert)
            self.all_alerts.append(alert)
            self.stats[alert["type"]] += 1
            self.stats["alerts"] += 1
            self._save_alert(alert)

    def _save_alert(self, alert: dict):
        """Append alert to JSONL output file."""
        safe = {k: v for k, v in alert.items()
                if not isinstance(v, (set, type))}
        if "mitre" in safe and "mitigations" in safe.get("mitre", {}):
            pass  # already serializable
        with open(self.alert_out, "a") as f:
            f.write(json.dumps(safe, default=str) + "\n")

    def _shutdown(self, sig, frame):
        self.running = False
        print(f"\n\n{BOLD}{CYAN}{'═'*65}{RESET}")
        print(f"{BOLD}  MONITOR STOPPED — Session Summary{RESET}")
        print(f"{CYAN}{'═'*65}{RESET}")
        print(f"  Log lines processed : {self.stats['total']}")
        print(f"  Alerts generated    : {self.stats['alerts']}")
        print(f"  Alerts saved to     : {self.alert_out}")
        for k, v in sorted(self.stats.items()):
            if k not in ("total", "alerts"):
                print(f"  {k:<28}: {v}")
        self.scorer.print_ip_leaderboard()
        print()
        sys.exit(0)


# ─────────────────────────────────────────────────────────
#  ATTACK LOG GENERATOR (inline, for --simulate mode)
# ─────────────────────────────────────────────────────────

ATTACK_LINES = [
    '185.220.101.45 - - [{ts}] "GET /login?username=%27+OR+%271%27%3D%271&password=x HTTP/1.1" 200 1234 "-" "sqlmap/1.7.8"',
    '45.33.32.156 - - [{ts}] "GET /search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E HTTP/1.1" 200 890 "-" "Mozilla/5.0"',
    '203.0.113.77 - - [{ts}] "GET /page?file=../../../../etc/passwd HTTP/1.1" 200 4096 "-" "Nikto/2.1.6"',
    '172.16.254.1 - - [{ts}] "POST /login HTTP/1.1" 401 200 "https://target.com/login" "python-requests/2.28"',
    '172.16.254.1 - - [{ts}] "POST /login HTTP/1.1" 401 200 "https://target.com/login" "python-requests/2.28"',
    '172.16.254.1 - - [{ts}] "POST /login HTTP/1.1" 401 200 "https://target.com/login" "python-requests/2.28"',
    '198.51.100.12 - - [{ts}] "GET /search?q=%2527%2520OR%25201%253D1-- HTTP/1.1" 400 456 "-" "curl/7.84"',
    '185.220.101.45 - - [{ts}] "GET /ping?host=127.0.0.1%3B+cat+%2Fetc%2Fpasswd HTTP/1.1" 500 123 "-" "curl/7.84"',
    '45.33.32.156 - - [{ts}] "GET /.env HTTP/1.1" 404 123 "-" "DirBuster-1.0-RC1"',
    '45.33.32.156 - - [{ts}] "GET /.git/config HTTP/1.1" 404 123 "-" "DirBuster-1.0-RC1"',
    '45.33.32.156 - - [{ts}] "GET /wp-admin/ HTTP/1.1" 404 123 "-" "DirBuster-1.0-RC1"',
    '192.168.1.10 - - [{ts}] "GET /index.html HTTP/1.1" 200 5432 "-" "Mozilla/5.0 Chrome/120"',
    '192.168.1.11 - - [{ts}] "GET /products HTTP/1.1" 200 3210 "-" "Mozilla/5.0 Firefox/115"',
    '185.220.101.45 - - [{ts}] "GET /download?path=..%2F..%2F..%2Fetc%2Fshadow HTTP/1.1" 403 234 "-" "python-requests/2.28"',
]

def simulate_to_log(log_file: str, delay: float = 1.0):
    """Write simulated attack lines to the log file so monitor can tail it."""
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    # Write placeholder so file exists for tailing
    with open(log_file, "w") as f:
        f.write("# WebGuard SIEM — Live simulation starting...\n")

    print(f"  [*] Simulation writing to {log_file} every {delay}s...")
    i = 0
    while True:
        ts = datetime.utcnow().strftime("%d/%b/%Y:%H:%M:%S +0000")
        line = ATTACK_LINES[i % len(ATTACK_LINES)].format(ts=ts)
        with open(log_file, "a") as f:
            f.write(line + "\n")
        i += 1
        time.sleep(delay)


# ─────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WebGuard SIEM — Real-Time Log Monitor")
    parser.add_argument("--simulate",  action="store_true", help="Generate attack lines while monitoring")
    parser.add_argument("--log",       default="sample_logs/web_access.log", help="Log file to monitor")
    parser.add_argument("--out",       default="sample_logs/rt_alerts.json", help="Alert output file")
    parser.add_argument("--ipinfo",    default=None, help="ipinfo.io token (optional)")
    parser.add_argument("--abuseipdb", default=None, help="AbuseIPDB API key (optional)")
    parser.add_argument("--speed",     type=float, default=0.8, help="Simulation write interval (seconds)")
    args = parser.parse_args()

    monitor = RealtimeMonitor(
        log_file=args.log, alert_out=args.out,
        ipinfo_token=args.ipinfo, abuseipdb_key=args.abuseipdb
    )

    if args.simulate:
        # Start simulator in background thread
        sim_thread = threading.Thread(
            target=simulate_to_log, args=(args.log, args.speed), daemon=True
        )
        sim_thread.start()
        time.sleep(0.5)  # Let file be created

    monitor.start()
