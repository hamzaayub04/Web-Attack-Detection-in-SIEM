import json
import time
import random
import hashlib
import urllib.request
import urllib.error
from datetime import datetime

# ─────────────────────────────────────────────────────────
#  OFFLINE THREAT INTELLIGENCE DATABASE (Demo / Fallback)
#  Based on real-world known malicious IP ranges & ASNs
# ─────────────────────────────────────────────────────────

KNOWN_MALICIOUS_IPS = {
    "185.220.101.45": {
        "country": "Netherlands", "country_code": "NL",
        "asn": "AS204895", "org": "Tuxis Internet Engineering",
        "hosting": "Tuxis BV", "is_tor": True, "is_vpn": False,
        "reputation_score": 97, "threat_types": ["TOR Exit Node", "Attack Source"],
        "reports_count": 2841, "last_seen": "2024-11-20",
        "city": "Amsterdam", "region": "North Holland",
        "latitude": 52.3740, "longitude": 4.8897
    },
    "45.33.32.156": {
        "country": "United States", "country_code": "US",
        "asn": "AS63949", "org": "Akamai Technologies",
        "hosting": "Linode LLC", "is_tor": False, "is_vpn": False,
        "reputation_score": 72, "threat_types": ["Scanning", "Brute Force"],
        "reports_count": 892, "last_seen": "2024-11-19",
        "city": "Absecon", "region": "New Jersey",
        "latitude": 39.4275, "longitude": -74.4973
    },
    "198.51.100.12": {
        "country": "Germany", "country_code": "DE",
        "asn": "AS24940", "org": "Hetzner Online GmbH",
        "hosting": "Hetzner", "is_tor": False, "is_vpn": True,
        "reputation_score": 88, "threat_types": ["VPN/Proxy", "Web Attacks"],
        "reports_count": 1205, "last_seen": "2024-11-21",
        "city": "Nuremberg", "region": "Bavaria",
        "latitude": 49.4521, "longitude": 11.0767
    },
    "203.0.113.77": {
        "country": "Russia", "country_code": "RU",
        "asn": "AS197695", "org": "REG.RU",
        "hosting": "REG.RU Hosting", "is_tor": False, "is_vpn": False,
        "reputation_score": 94, "threat_types": ["Malware Distribution", "SQL Injection"],
        "reports_count": 3210, "last_seen": "2024-11-22",
        "city": "Moscow", "region": "Moscow",
        "latitude": 55.7558, "longitude": 37.6173
    },
    "172.16.254.1": {
        "country": "China", "country_code": "CN",
        "asn": "AS4134", "org": "CHINANET-BACKBONE",
        "hosting": "China Telecom", "is_tor": False, "is_vpn": False,
        "reputation_score": 85, "threat_types": ["Brute Force", "Credential Stuffing"],
        "reports_count": 1847, "last_seen": "2024-11-18",
        "city": "Beijing", "region": "Beijing",
        "latitude": 39.9042, "longitude": 116.4074
    },
    "10.0.0.99": {
        "country": "Internal Network", "country_code": "INTERNAL",
        "asn": "RFC1918", "org": "Private Network",
        "hosting": "Internal", "is_tor": False, "is_vpn": False,
        "reputation_score": 45, "threat_types": ["Insider Threat"],
        "reports_count": 0, "last_seen": "N/A",
        "city": "Internal", "region": "LAN",
        "latitude": 0.0, "longitude": 0.0
    },
}

# Simulated country data for unknown IPs
COUNTRY_POOL = [
    ("United States", "US", 37.0902, -95.7129),
    ("Germany",       "DE", 51.1657, 10.4515),
    ("Netherlands",   "NL", 52.1326, 5.2913),
    ("Russia",        "RU", 61.5240, 105.3188),
    ("China",         "CN", 35.8617, 104.1954),
    ("Brazil",        "BR", -14.235, -51.9253),
    ("Romania",       "RO", 45.9432, 24.9668),
    ("Ukraine",       "UA", 48.3794, 31.1656),
    ("United Kingdom","GB", 55.3781, -3.4360),
    ("France",        "FR", 46.2276, 2.2137),
]

HOSTING_PROVIDERS = [
    "DigitalOcean", "Linode/Akamai", "Vultr", "Hetzner Online",
    "OVHcloud", "Amazon AWS", "Google Cloud", "Microsoft Azure",
    "Cloudflare", "Tuxis BV", "Frantech Solutions (BuyVM)",
]

THREAT_TYPE_POOL = [
    ["SSH Brute Force"], ["Web Application Attacks"],
    ["SQL Injection"], ["Port Scanning"], ["TOR Exit Node"],
    ["VPN/Proxy"], ["Malware Distribution"], ["Phishing"],
    ["DDoS Participant"], ["Credential Stuffing"],
]


# ─────────────────────────────────────────────────────────
#  CACHE (avoid hammering APIs)
# ─────────────────────────────────────────────────────────

class IPCache:
    def __init__(self, ttl_seconds=3600):
        self._store = {}
        self.ttl = ttl_seconds

    def get(self, ip):
        if ip in self._store:
            entry, ts = self._store[ip]
            if time.time() - ts < self.ttl:
                return entry
        return None

    def set(self, ip, data):
        self._store[ip] = (data, time.time())


# ─────────────────────────────────────────────────────────
#  MAIN ENRICHER CLASS
# ─────────────────────────────────────────────────────────

class ThreatIntelEnricher:
    def __init__(self, ipinfo_token=None, abuseipdb_key=None, offline_mode=False):
        """
        Args:
            ipinfo_token  : Get free token at https://ipinfo.io/signup
            abuseipdb_key : Get free key at https://www.abuseipdb.com/register
            offline_mode  : True = use simulated data only (no API calls)
        """
        self.ipinfo_token   = ipinfo_token
        self.abuseipdb_key  = abuseipdb_key
        self.offline_mode   = offline_mode or (not ipinfo_token and not abuseipdb_key)
        self.cache          = IPCache()
        self._call_count    = 0

    # ── Public API ───────────────────────────────────────

    def enrich(self, ip: str) -> dict:
        """Main entry: enrich an IP with full threat context."""
        cached = self.cache.get(ip)
        if cached:
            return cached

        if self.offline_mode or ip.startswith(("10.", "172.16.", "192.168.")):
            result = self._offline_enrich(ip)
        else:
            result = self._live_enrich(ip)

        self.cache.set(ip, result)
        return result

    def enrich_alert(self, alert: dict) -> dict:
        """Add enrichment context to an existing alert dict."""
        ip = alert.get("ip", "0.0.0.0")
        intel = self.enrich(ip)
        return {**alert, "threat_intel": intel}

    def enrich_bulk(self, alerts: list) -> list:
        """Enrich a list of alerts (deduplicates IPs to save API calls)."""
        seen = {}
        enriched = []
        for alert in alerts:
            ip = alert.get("ip", "")
            if ip not in seen:
                seen[ip] = self.enrich(ip)
            enriched.append({**alert, "threat_intel": seen[ip]})
        return enriched

    # ── Live API Enrichment ──────────────────────────────

    def _live_enrich(self, ip: str) -> dict:
        geo  = self._fetch_ipinfo(ip)
        abuse = self._fetch_abuseipdb(ip)
        return self._merge(ip, geo, abuse)

    def _fetch_ipinfo(self, ip: str) -> dict:
        """Fetch geo/ASN from ipinfo.io"""
        if not self.ipinfo_token:
            return {}
        try:
            url = f"https://ipinfo.io/{ip}?token={self.ipinfo_token}"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                self._call_count += 1
                lat, lon = 0.0, 0.0
                if "loc" in data:
                    parts = data["loc"].split(",")
                    lat, lon = float(parts[0]), float(parts[1])
                return {
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "region": data.get("region", "Unknown"),
                    "org": data.get("org", "Unknown"),
                    "latitude": lat, "longitude": lon,
                }
        except Exception as e:
            return {"_ipinfo_error": str(e)}

    def _fetch_abuseipdb(self, ip: str) -> dict:
        """Fetch reputation from AbuseIPDB"""
        if not self.abuseipdb_key:
            return {}
        try:
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose"
            req = urllib.request.Request(url, headers={
                "Key": self.abuseipdb_key,
                "Accept": "application/json"
            })
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode()).get("data", {})
                self._call_count += 1
                return {
                    "reputation_score": data.get("abuseConfidenceScore", 0),
                    "reports_count":    data.get("totalReports", 0),
                    "is_tor":           data.get("isTor", False),
                    "is_vpn":           False,
                    "last_seen":        data.get("lastReportedAt", "N/A"),
                    "country_code":     data.get("countryCode", "XX"),
                    "isp":              data.get("isp", "Unknown"),
                    "domain":           data.get("domain", ""),
                    "usage_type":       data.get("usageType", ""),
                }
        except Exception as e:
            return {"_abuseipdb_error": str(e)}

    def _merge(self, ip, geo, abuse) -> dict:
        """Merge ipinfo + AbuseIPDB into unified enrichment record."""
        score = abuse.get("reputation_score", 0)
        threat_level = (
            "CRITICAL" if score >= 80 else
            "HIGH"     if score >= 50 else
            "MEDIUM"   if score >= 20 else
            "LOW"
        )
        return {
            "ip":              ip,
            "country":         geo.get("country", abuse.get("country_code", "Unknown")),
            "country_code":    abuse.get("country_code", "XX"),
            "city":            geo.get("city", "Unknown"),
            "region":          geo.get("region", "Unknown"),
            "org":             geo.get("org", abuse.get("isp", "Unknown")),
            "asn":             geo.get("org", "").split()[0] if geo.get("org") else "Unknown",
            "hosting":         abuse.get("isp", geo.get("org", "Unknown")),
            "is_tor":          abuse.get("is_tor", False),
            "is_vpn":          False,
            "reputation_score":score,
            "threat_level":    threat_level,
            "reports_count":   abuse.get("reports_count", 0),
            "last_seen":       abuse.get("last_seen", "N/A"),
            "latitude":        geo.get("latitude", 0.0),
            "longitude":       geo.get("longitude", 0.0),
            "threat_types":    [],
            "source":          "live_api",
            "enriched_at":     datetime.utcnow().isoformat() + "Z",
        }

    # ── Offline / Simulated Enrichment ───────────────────

    def _offline_enrich(self, ip: str) -> dict:
        """Deterministic simulation — same IP always gets same result."""
        if ip in KNOWN_MALICIOUS_IPS:
            data = KNOWN_MALICIOUS_IPS[ip].copy()
            score = data["reputation_score"]
        else:
            # Seed RNG from IP hash for determinism
            seed = int(hashlib.md5(ip.encode()).hexdigest()[:8], 16)
            rng  = random.Random(seed)
            country, cc, lat, lon = rng.choice(COUNTRY_POOL)
            score = rng.randint(20, 99)
            data  = {
                "country": country, "country_code": cc,
                "city": "Unknown", "region": "Unknown",
                "asn": f"AS{rng.randint(10000, 99999)}",
                "org": f"AS{rng.randint(10000,99999)} {rng.choice(HOSTING_PROVIDERS)}",
                "hosting": rng.choice(HOSTING_PROVIDERS),
                "is_tor":  score > 80,
                "is_vpn":  50 < score <= 80,
                "reputation_score": score,
                "threat_types": rng.choice(THREAT_TYPE_POOL),
                "reports_count": rng.randint(0, 3000),
                "last_seen": "2024-11-21",
                "latitude": lat, "longitude": lon,
            }

        threat_level = (
            "CRITICAL" if score >= 80 else
            "HIGH"     if score >= 50 else
            "MEDIUM"   if score >= 20 else
            "LOW"
        )

        flags = []
        if data.get("is_tor"):  flags.append("🧅 TOR Exit Node")
        if data.get("is_vpn"):  flags.append("🔒 VPN/Proxy")
        if score >= 80:         flags.append("☠️  Known Malicious")
        elif score >= 50:       flags.append("⚠️  Suspicious")

        return {
            "ip":              ip,
            "country":         data["country"],
            "country_code":    data["country_code"],
            "city":            data.get("city", "Unknown"),
            "region":          data.get("region", "Unknown"),
            "org":             data.get("org", "Unknown"),
            "asn":             data.get("asn", "Unknown"),
            "hosting":         data.get("hosting", "Unknown"),
            "is_tor":          data.get("is_tor", False),
            "is_vpn":          data.get("is_vpn", False),
            "reputation_score":score,
            "threat_level":    threat_level,
            "reports_count":   data.get("reports_count", 0),
            "last_seen":       data.get("last_seen", "N/A"),
            "latitude":        data.get("latitude", 0.0),
            "longitude":       data.get("longitude", 0.0),
            "threat_types":    data.get("threat_types", []),
            "flags":           flags,
            "source":          "offline_db",
            "enriched_at":     datetime.utcnow().isoformat() + "Z",
        }

    def summary(self, intel: dict) -> str:
        """Human-readable one-line summary of enrichment."""
        flags = intel.get("flags", [])
        flag_str = " | ".join(flags) if flags else "No flags"
        return (
            f"  Country   : {intel['country']} ({intel['country_code']})\n"
            f"  ASN/Org   : {intel['asn']} — {intel['hosting']}\n"
            f"  Reputation: {intel['reputation_score']}/100 [{intel['threat_level']}] "
            f"({intel['reports_count']} reports)\n"
            f"  Flags     : {flag_str}\n"
            f"  Threat    : {', '.join(intel.get('threat_types', ['Unknown']))}"
        )


# ─────────────────────────────────────────────────────────
#  CLI DEMO
# ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  THREAT INTEL ENRICHMENT — Demo (Offline Mode)")
    print("=" * 60)

    enricher = ThreatIntelEnricher(offline_mode=True)

    test_ips = list(KNOWN_MALICIOUS_IPS.keys()) + ["91.200.14.5", "5.188.206.100"]

    for ip in test_ips:
        intel = enricher.enrich(ip)
        print(f"\n  IP: {ip}")
        print(enricher.summary(intel))
        print(f"  {'─'*50}")

    # Example alert enrichment
    print("\n\n  [ALERT ENRICHMENT EXAMPLE]")
    sample_alert = {
        "type": "SQL_INJECTION",
        "severity": "CRITICAL",
        "ip": "185.220.101.45",
        "uri": "/login?id=1'+OR+'1'='1",
        "timestamp": datetime.utcnow().isoformat()
    }
    enriched = enricher.enrich_alert(sample_alert)
    print(f"  Alert: {enriched['type']} from {enriched['ip']}")
    print(enricher.summary(enriched["threat_intel"]))
