"""
╔══════════════════════════════════════════════════════════╗
║     LOG GENERATOR — Apache / Nginx SIEM Format           ║
║  Mixes attack traffic with normal baseline traffic       ║
╚══════════════════════════════════════════════════════════╝
"""

import random
import json
import os
import urllib.parse
from datetime import datetime, timedelta

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
OUTPUT_LOG = "sample_logs/web_access.log"
TOTAL_NORMAL_REQUESTS = 500
TOTAL_ATTACK_REQUESTS = 200

NORMAL_IPS = [f"192.168.{random.randint(0,5)}.{random.randint(1,254)}" for _ in range(20)]
ATTACK_IPS = [
    "185.220.101.45", "198.51.100.12", "203.0.113.77",
    "45.33.32.156",   "10.0.0.99",     "172.16.254.1",
]

NORMAL_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
]

ATTACK_AGENTS = [
    "sqlmap/1.7.8#stable (https://sqlmap.org)",
    "Nikto/2.1.6",
    "python-requests/2.28.0",
    "curl/7.84.0",
    "DirBuster-1.0-RC1",
    "Acunetix Web Vulnerability Scanner/13",
    "Burp Suite Professional v2023.10",
]

NORMAL_PATHS = [
    "/", "/index.html", "/about", "/products", "/contact",
    "/api/v1/users", "/api/v1/orders", "/login", "/logout",
    "/assets/main.css", "/assets/app.js", "/favicon.ico",
    "/blog", "/blog/post-1", "/search?q=shoes",
]

ATTACK_PAYLOADS = {
    "sqli": [
        "/login?username=%27+OR+%271%27%3D%271&password=test",
        "/search?q=%27+UNION+SELECT+null%2Cusername%2Cpassword+FROM+users--",
        "/product?id=1%3B+DROP+TABLE+users%3B--",
        "/api/v1/users?id=1+AND+SLEEP%285%29--",
    ],
    "xss": [
        "/search?q=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E",
        "/comment?text=%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E",
        "/profile?name=%3Csvg%2Fonload%3Dalert%28%27xss%27%29%3E",
    ],
    "lfi": [
        "/page?file=../../../../etc/passwd",
        "/index.php?page=..%2F..%2F..%2Fetc%2Fshadow",
        "/view?doc=php://filter/convert.base64-encode/resource=index.php",
        "/download?path=....//....//....//etc/passwd",
    ],
    "cmdi": [
        "/ping?host=127.0.0.1%3B+cat+%2Fetc%2Fpasswd",
        "/tools/check?input=%7C+id",
        "/api/exec?cmd=%60whoami%60",
    ],
    "scanner": [
        "/.env", "/.git/config", "/wp-admin/", "/phpmyadmin/",
        "/admin/", "/backup.zip", "/config.php.bak", "/.htaccess",
        "/server-status", "/web.config", "/composer.json",
    ],
    "encoded": [
        "/search?q=%2527%2520OR%25201%253D1--",       # Double URL encoded
        "/page?id=PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",  # Base64
        "/file?path=%c0%ae%c0%ae%c0%afetc%c0%afpasswd",    # Unicode
    ],
}


# ─────────────────────────────────────────────
# LOG ENTRY BUILDER
# ─────────────────────────────────────────────

def make_timestamp(base_time, offset_seconds):
    t = base_time + timedelta(seconds=offset_seconds)
    return t.strftime("%d/%b/%Y:%H:%M:%S +0000")

def apache_log_line(ip, timestamp, method, uri, status, size, referer, agent):
    return f'{ip} - - [{timestamp}] "{method} {uri} HTTP/1.1" {status} {size} "{referer}" "{agent}"'

def generate_logs():
    os.makedirs("sample_logs", exist_ok=True)
    lines = []
    base_time = datetime.utcnow() - timedelta(hours=2)
    offset = 0

    print("=" * 60)
    print("  LOG GENERATOR — Building Synthetic Web Access Logs")
    print("=" * 60)

    # ── Normal traffic ──────────────────────────────────────
    print(f"\n[*] Generating {TOTAL_NORMAL_REQUESTS} normal requests...")
    for _ in range(TOTAL_NORMAL_REQUESTS):
        offset += random.randint(1, 10)
        line = apache_log_line(
            ip=random.choice(NORMAL_IPS),
            timestamp=make_timestamp(base_time, offset),
            method=random.choice(["GET", "GET", "GET", "POST"]),
            uri=random.choice(NORMAL_PATHS),
            status=random.choices([200, 200, 200, 301, 304, 404], weights=[60, 15, 10, 5, 5, 5])[0],
            size=random.randint(512, 25000),
            referer="-",
            agent=random.choice(NORMAL_AGENTS),
        )
        lines.append(("NORMAL", line))

    # ── SQL Injection traffic ────────────────────────────────
    print(f"[*] Injecting SQLi attack requests...")
    for uri in ATTACK_PAYLOADS["sqli"] * 5:
        offset += random.randint(1, 3)
        line = apache_log_line(
            ip=random.choice(ATTACK_IPS),
            timestamp=make_timestamp(base_time, offset),
            method="GET",
            uri=uri,
            status=random.choices([200, 500, 403], weights=[50, 30, 20])[0],
            size=random.randint(100, 2000),
            referer="-",
            agent=ATTACK_AGENTS[0],  # sqlmap
        )
        lines.append(("SQLI", line))

    # ── XSS traffic ─────────────────────────────────────────
    print(f"[*] Injecting XSS attack requests...")
    for uri in ATTACK_PAYLOADS["xss"] * 4:
        offset += random.randint(1, 3)
        line = apache_log_line(
            ip=random.choice(ATTACK_IPS),
            timestamp=make_timestamp(base_time, offset),
            method="GET",
            uri=uri,
            status=random.choices([200, 400], weights=[70, 30])[0],
            size=random.randint(100, 5000),
            referer="-",
            agent=random.choice(ATTACK_AGENTS[2:]),
        )
        lines.append(("XSS", line))

    # ── LFI traffic ──────────────────────────────────────────
    print(f"[*] Injecting LFI attack requests...")
    for uri in ATTACK_PAYLOADS["lfi"] * 4:
        offset += random.randint(1, 3)
        line = apache_log_line(
            ip="185.220.101.45",
            timestamp=make_timestamp(base_time, offset),
            method="GET",
            uri=uri,
            status=random.choices([200, 404, 403], weights=[40, 40, 20])[0],
            size=random.randint(100, 8000),
            referer="-",
            agent=ATTACK_AGENTS[1],  # Nikto
        )
        lines.append(("LFI", line))

    # ── Command Injection ────────────────────────────────────
    print(f"[*] Injecting Command Injection requests...")
    for uri in ATTACK_PAYLOADS["cmdi"] * 3:
        offset += random.randint(1, 3)
        line = apache_log_line(
            ip="203.0.113.77",
            timestamp=make_timestamp(base_time, offset),
            method="GET",
            uri=uri,
            status=random.choices([200, 500], weights=[60, 40])[0],
            size=random.randint(100, 3000),
            referer="-",
            agent=ATTACK_AGENTS[2],
        )
        lines.append(("CMDI", line))

    # ── Scanner / Recon (error spike) ───────────────────────
    print(f"[*] Injecting Scanner/Recon error spike...")
    scanner_ip = "45.33.32.156"
    for path in ATTACK_PAYLOADS["scanner"] * 4:
        offset += random.randint(0, 2)
        line = apache_log_line(
            ip=scanner_ip,
            timestamp=make_timestamp(base_time, offset),
            method="GET",
            uri=path,
            status=random.choices([404, 403, 401], weights=[60, 30, 10])[0],
            size=random.randint(100, 500),
            referer="-",
            agent=ATTACK_AGENTS[3],  # DirBuster
        )
        lines.append(("SCANNER", line))

    # ── Encoded payloads ─────────────────────────────────────
    print(f"[*] Injecting encoded/obfuscated payloads...")
    for uri in ATTACK_PAYLOADS["encoded"] * 3:
        offset += random.randint(1, 5)
        line = apache_log_line(
            ip="198.51.100.12",
            timestamp=make_timestamp(base_time, offset),
            method="GET",
            uri=uri,
            status=random.choices([200, 400, 403], weights=[40, 40, 20])[0],
            size=random.randint(100, 4000),
            referer="-",
            agent=random.choice(ATTACK_AGENTS),
        )
        lines.append(("ENCODED", line))

    # ── Brute force (rapid POST requests) ───────────────────
    print(f"[*] Injecting brute force login requests...")
    bf_ip = "172.16.254.1"
    for i in range(40):
        offset += random.randint(0, 1)  # Very fast = brute force
        line = apache_log_line(
            ip=bf_ip,
            timestamp=make_timestamp(base_time, offset),
            method="POST",
            uri="/login",
            status=401,
            size=random.randint(100, 300),
            referer="https://target.com/login",
            agent="python-requests/2.28.0",
        )
        lines.append(("BRUTE_FORCE", line))

    # ── Shuffle and write ────────────────────────────────────
    random.shuffle(lines)
    with open(OUTPUT_LOG, "w") as f:
        for _, line in lines:
            f.write(line + "\n")

    # Also save labeled version for ML/analysis
    labeled = [{"label": label, "log": line} for label, line in lines]
    with open("sample_logs/labeled_logs.json", "w") as f:
        json.dump(labeled, f, indent=2)

    from collections import Counter
    counts = Counter(label for label, _ in lines)

    print(f"\n{'='*60}")
    print(f"  Total Log Lines Written: {len(lines)}")
    print(f"  Output: {OUTPUT_LOG}")
    print(f"\n  [BREAKDOWN BY TYPE]")
    for k, v in counts.most_common():
        bar = "█" * (v // 5)
        print(f"    {k:<15} {v:>4}  {bar}")
    print(f"{'='*60}")

if __name__ == "__main__":
    generate_logs()
