#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║          EMAIL SOC TOOLKIT — HEADER ANALYSIS + OSINT               ║
║          SOC Analyst Toolkit  |  Kali Linux  |  Python3            ║
╚══════════════════════════════════════════════════════════════════════╝

MODES:
  1. Header Analysis  — analyze .eml file or raw headers for phishing
  2. OSINT            — investigate a sender email address
  3. Full Pipeline    — analyze .eml AND auto-run OSINT on sender

Usage:
  python3 email_soc_toolkit.py --demo
  python3 email_soc_toolkit.py --file suspicious.eml
  python3 email_soc_toolkit.py --file suspicious.eml --osint
  python3 email_soc_toolkit.py --osint -e target@example.com
  python3 email_soc_toolkit.py --demo --osint --json report.json

⚠️  FOR AUTHORIZED INVESTIGATIONS & UNIVERSITY RESEARCH ONLY
"""

import argparse
import email
import hashlib
import json
import re
import sys
import textwrap
import time
from datetime import datetime, timezone
from email import policy
from email.parser import Parser
from urllib.request import urlopen, Request
from urllib.error import HTTPError
from urllib.parse import quote_plus


# ══════════════════════════════════════════════════════════════════════════════
#  COLORS
# ══════════════════════════════════════════════════════════════════════════════
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def section(title: str, width: int = 64):
    print(f"\n{C.CYAN}{C.BOLD}{'─'*width}\n  {title}\n{'─'*width}{C.RESET}")

def ok(msg):             print(f"  {C.GREEN}[✔]{C.RESET} {msg}")
def warn(msg):           print(f"  {C.YELLOW}[!]{C.RESET} {msg}")
def info(msg):           print(f"  {C.BLUE}[*]{C.RESET} {msg}")
def fail(msg):           print(f"  {C.RED}[✘]{C.RESET} {msg}")
def tag(lvl, txt):
    icons = {"INFO": f"{C.BLUE}[*]{C.RESET}", "OK": f"{C.GREEN}[✔]{C.RESET}",
             "WARN": f"{C.YELLOW}[!]{C.RESET}", "ALERT": f"{C.RED}[✘]{C.RESET}"}
    return f"{icons.get(lvl,'[?]')} {txt}"
def found(label, value): print(f"  {C.GREEN}[✔]{C.RESET} {C.BOLD}{label:<22}{C.RESET} {value}")
def notfound(label):     print(f"  {C.DIM}[–] {label:<22} not found{C.RESET}")


def banner():
    print(f"""{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════════════════╗
║           EMAIL SOC TOOLKIT — HEADER ANALYSIS + OSINT              ║
║           Phishing Detection  |  IP Tracing  |  Sender Profiling   ║
║           SOC Analyst Toolkit  |  Kali Linux  |  Python3           ║
╚══════════════════════════════════════════════════════════════════════╝
{C.YELLOW}  ⚠  Use only on emails you own or have written authorization to investigate.{C.RESET}
""")


# ══════════════════════════════════════════════════════════════════════════════
#  DEMO EMAIL
# ══════════════════════════════════════════════════════════════════════════════
DEMO_RAW = """\
Delivered-To: victim@example.com
Received: from mail.fakepaypal.xyz (mail.fakepaypal.xyz [198.51.100.77])
        by mx.example.com with ESMTP id abc123
        for <victim@example.com>; Mon, 23 Jun 2025 09:12:04 +0000 (UTC)
Received: from [10.0.0.5] (unknown [10.0.0.5])
        by mail.fakepaypal.xyz with SMTP id xyz456
        Mon, 23 Jun 2025 09:11:58 +0000 (UTC)
Authentication-Results: mx.example.com;
   spf=fail (sender IP is 198.51.100.77) smtp.mailfrom=paypal.com;
   dkim=none;
   dmarc=fail action=none header.from=paypal.com
Received-SPF: fail (mx.example.com: domain of paypal.com does not designate
  198.51.100.77 as permitted sender) client-ip=198.51.100.77
From: "PayPal Security" <security@paypal.com>
Reply-To: support@fakepaypal.xyz
To: victim@example.com
Date: Mon, 23 Jun 2025 09:11:50 +0000
Subject: Urgent: Your account has been limited!
Message-ID: <abc123@fakepaypal.xyz>
X-Mailer: PHPMailer 6.0
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8
X-Originating-IP: 198.51.100.77

<html><body>
Dear Customer,<br>
Your PayPal account has been limited. Click <a href="http://fakepaypal.xyz/login">here</a> to verify.
</body></html>
"""


# ══════════════════════════════════════════════════════════════════════════════
#  SHARED HTTP HELPER
# ══════════════════════════════════════════════════════════════════════════════
BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Accept": "application/json, text/html,*/*",
}

def http_get(url: str, timeout: int = 8, json_resp: bool = False,
             ua: str = None):
    hdrs = dict(BROWSER_HEADERS)
    if ua:
        hdrs["User-Agent"] = ua
    try:
        req = Request(url, headers=hdrs)
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return json.loads(raw) if json_resp else raw.decode("utf-8", errors="replace")
    except HTTPError:
        return None
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE A — EMAIL HEADER PARSER
# ══════════════════════════════════════════════════════════════════════════════
def parse_email_msg(raw: str) -> email.message.Message:
    return Parser(policy=policy.default).parsestr(raw)

def extract_received_chain(msg: email.message.Message) -> list[dict]:
    hops = []
    received_headers = msg.get_all("Received") or []
    ip_re   = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
    from_re = re.compile(r'from\s+([\w.\-]+)\s', re.IGNORECASE)
    by_re   = re.compile(r'by\s+([\w.\-]+)\s',   re.IGNORECASE)
    for i, hdr in enumerate(reversed(received_headers), 1):
        ips = ip_re.findall(hdr)
        fm  = from_re.search(hdr)
        by  = by_re.search(hdr)
        hops.append({
            "hop":       i,
            "from_host": fm.group(1) if fm else "unknown",
            "by_host":   by.group(1) if by else "unknown",
            "ips":       [ip for ip in ips
                          if not ip.startswith(("10.", "192.168.", "127."))],
            "raw":       hdr.strip()[:120],
        })
    return hops

def geolocate_ip(ip: str) -> dict:
    data = http_get(
        f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,query",
        ua="EmailSOCToolkit/1.0", json_resp=True
    )
    if data and data.get("status") == "success":
        return data
    return {"query": ip, "country": "N/A", "city": "N/A",
            "regionName": "N/A", "isp": "N/A", "org": "N/A"}

def parse_auth_results(msg: email.message.Message) -> dict:
    hdr = msg.get("Authentication-Results", "")
    def _get(key):
        m = re.search(rf'{key}=([\w]+)', hdr, re.IGNORECASE)
        return m.group(1).lower() if m else "none"
    return {"spf": _get("spf"), "dkim": _get("dkim"), "dmarc": _get("dmarc")}

def analyze_phishing(msg: email.message.Message,
                     hops: list, auth: dict) -> list[dict]:
    findings = []

    if auth["spf"] in ("fail", "softfail"):
        findings.append({"severity": "HIGH", "indicator": "SPF Failure",
            "detail": f"SPF check {auth['spf'].upper()} — sending IP not authorized"})

    if auth["dkim"] in ("none", "fail"):
        findings.append({"severity": "MEDIUM", "indicator": "DKIM Missing/Failed",
            "detail": "Email not signed or signature invalid — content may be tampered"})

    if auth["dmarc"] == "fail":
        findings.append({"severity": "HIGH", "indicator": "DMARC Failure",
            "detail": "DMARC policy failed — From domain spoofing likely"})

    from_addr = msg.get("From", "")
    reply_to  = msg.get("Reply-To", "")
    if reply_to:
        fd = re.search(r'@([\w.\-]+)', from_addr)
        rd = re.search(r'@([\w.\-]+)', reply_to)
        if fd and rd and fd.group(1) != rd.group(1):
            findings.append({"severity": "HIGH",
                "indicator": "From/Reply-To Domain Mismatch",
                "detail": f"From: {fd.group(1)} | Reply-To: {rd.group(1)}"})

    lfd = re.search(r'@([\w.\-]+)', from_addr)
    if lfd:
        claimed = lfd.group(1).lower()
        for hop in hops:
            if claimed not in hop["from_host"].lower() and hop["from_host"] != "unknown":
                findings.append({"severity": "MEDIUM",
                    "indicator": "Sending Host Doesn't Match From Domain",
                    "detail": f"Claimed: {claimed} | Actual sender: {hop['from_host']}"})
                break

    mailer = msg.get("X-Mailer", "") + msg.get("X-Sender", "")
    if any(x in mailer.lower() for x in ["phpmailer","sendgrid","mailchimp","massmail"]):
        findings.append({"severity": "LOW", "indicator": "Bulk/Script Mailer Detected",
            "detail": f"X-Mailer: {mailer.strip()}"})

    subject = msg.get("Subject", "")
    urgency = [w for w in ["urgent","limited","suspended","verify","action required",
               "account locked","unusual activity","immediately","warning"]
               if w in subject.lower()]
    if urgency:
        findings.append({"severity": "MEDIUM", "indicator": "Urgency Language in Subject",
            "detail": f"Keywords: {', '.join(urgency)}"})

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ("text/plain", "text/html"):
                body += str(part.get_payload(decode=True) or "")
    else:
        body = str(msg.get_payload(decode=True) or "")

    urls = re.findall(r'href=["\']?(https?://[^\s"\'<>]+)', body, re.IGNORECASE)
    if urls and lfd:
        for url in urls:
            ud = re.search(r'https?://([^/]+)', url)
            if ud and claimed not in ud.group(1).lower():
                findings.append({"severity": "HIGH",
                    "indicator": "Hyperlink Domain Mismatch",
                    "detail": f"Link → {ud.group(1)} | From claims → {claimed}"})
                break

    return findings

def compute_risk_score(findings: list) -> tuple[int, str]:
    weights = {"HIGH": 30, "MEDIUM": 15, "LOW": 5}
    score = min(sum(weights.get(f["severity"], 0) for f in findings), 100)
    if score >= 70:   verdict = f"{C.RED}HIGH RISK — Likely Phishing/Spoofing{C.RESET}"
    elif score >= 35: verdict = f"{C.YELLOW}MEDIUM RISK — Suspicious{C.RESET}"
    elif score >= 10: verdict = f"{C.YELLOW}LOW RISK — Minor Anomalies{C.RESET}"
    else:             verdict = f"{C.GREEN}CLEAN — No significant threats detected{C.RESET}"
    return score, verdict

def print_header_report(msg, hops, auth, findings, geo_results):
    section("📧  EMAIL METADATA")
    for f in ["From","To","Subject","Date","Message-ID","Reply-To","X-Mailer"]:
        val = msg.get(f, f"{C.DIM}(not present){C.RESET}")
        print(f"  {C.BOLD}{f:<15}{C.RESET} {val}")

    section("🔐  AUTHENTICATION  (SPF / DKIM / DMARC)")
    icons = {"pass": f"{C.GREEN}PASS{C.RESET}", "fail": f"{C.RED}FAIL{C.RESET}",
             "softfail": f"{C.YELLOW}SOFTFAIL{C.RESET}", "none": f"{C.DIM}NONE{C.RESET}"}
    for key in ("spf","dkim","dmarc"):
        print(f"  {key.upper():<8} {icons.get(auth[key], auth[key])}")

    section("🌐  EMAIL ROUTING  (Received Chain)")
    for hop in hops:
        print(f"\n  {C.BOLD}Hop {hop['hop']}{C.RESET}")
        print(f"  {'From:':<10} {hop['from_host']}")
        print(f"  {'By:':<10} {hop['by_host']}")
        for ip in hop["ips"]:
            print(f"  {'IP:':<10} {ip}")

    if geo_results:
        section("🗺️   IP GEOLOCATION")
        for geo in geo_results:
            print(f"\n  {C.BOLD}{geo.get('query','?')}{C.RESET}")
            print(f"  {'Location:':<12} {geo.get('city','?')}, "
                  f"{geo.get('regionName','?')}, {geo.get('country','?')}")
            print(f"  {'ISP/Org:':<12} {geo.get('isp','?')} / {geo.get('org','?')}")

    section("⚠️   PHISHING / SPOOFING INDICATORS")
    if not findings:
        print(f"  {tag('OK', 'No phishing indicators detected.')}")
    else:
        colors = {"HIGH": C.RED, "MEDIUM": C.YELLOW, "LOW": C.BLUE}
        for f in findings:
            c = colors.get(f["severity"], "")
            print(f"\n  {c}{C.BOLD}[{f['severity']}]{C.RESET}  {f['indicator']}")
            print(f"  {C.DIM}         {f['detail']}{C.RESET}")

    section("🎯  RISK ASSESSMENT")
    score, verdict = compute_risk_score(findings)
    bar = f"{'█' * int(score/5)}{'░' * (20 - int(score/5))}"
    c = C.RED if score >= 70 else (C.YELLOW if score >= 35 else C.GREEN)
    print(f"\n  Risk Score: {c}{C.BOLD}{score}/100{C.RESET}  [{c}{bar}{C.RESET}]")
    print(f"  Verdict:    {verdict}\n")

    if findings:
        section("🛡️   MITRE ATT&CK MAPPING")
        mitre = {
            "SPF Failure":                        ("T1566.001","Phishing: Spearphishing Attachment"),
            "DKIM Missing/Failed":                ("T1566.002","Phishing: Spearphishing Link"),
            "DMARC Failure":                      ("T1036.005","Masquerading: Match Legitimate Name"),
            "From/Reply-To Domain Mismatch":      ("T1036",    "Masquerading"),
            "Hyperlink Domain Mismatch":          ("T1566.002","Phishing: Spearphishing Link"),
            "Urgency Language in Subject":        ("T1598",    "Phishing for Information"),
            "Bulk/Script Mailer Detected":        ("T1586",    "Compromise Accounts"),
            "Sending Host Doesn't Match From Domain": ("T1036.005","Masquerading"),
        }
        seen = set()
        for f in findings:
            t = mitre.get(f["indicator"])
            if t and t[0] not in seen:
                seen.add(t[0])
                print(f"  {C.CYAN}{t[0]}{C.RESET}  {t[1]}")
        print(f"\n  {C.DIM}Reference: https://attack.mitre.org/tactics/TA0001/{C.RESET}")


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE B — OSINT ENGINE
# ══════════════════════════════════════════════════════════════════════════════
def validate_email_addr(addr: str) -> dict:
    result = {"valid": False, "username": "", "domain": ""}
    if re.match(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', addr):
        parts = addr.split("@")
        result.update({"valid": True, "username": parts[0], "domain": parts[1]})
    return result

def derive_usernames(username: str) -> list[str]:
    candidates = [username]
    for sep in [".", "_", "-"]:
        if sep in username:
            candidates.append(username.replace(sep, ""))
            parts = username.split(sep)
            if len(parts) >= 2:
                candidates.append(parts[0])
                candidates.append(parts[0] + parts[-1])
    return list(dict.fromkeys(candidates))

def dns_mx_lookup(domain: str) -> list[str]:
    data = http_get(f"https://dns.google/resolve?name={domain}&type=MX", json_resp=True)
    if data and data.get("Answer"):
        return [r["data"] for r in data["Answer"] if r.get("type") == 15]
    return []

def whois_domain(domain: str) -> dict:
    data = http_get(f"https://rdap.org/domain/{domain}", json_resp=True)
    if not data:
        return {}
    try:
        registrar = next(
            (e["fn"][0] for e in data.get("entities", [])
             if "registrar" in e.get("roles", []) and e.get("fn")), "N/A")
        events = {e["eventAction"]: e["eventDate"] for e in data.get("events", [])}
        return {
            "registrar":  registrar,
            "registered": events.get("registration", "N/A")[:10],
            "expires":    events.get("expiration",   "N/A")[:10],
            "status":     ", ".join(data.get("status", [])),
        }
    except Exception:
        return {}

def check_gravatar(addr: str) -> dict:
    md5 = hashlib.md5(addr.strip().lower().encode()).hexdigest()
    # Try JSON profile first
    data = http_get(f"https://www.gravatar.com/{md5}.json", json_resp=True)
    if data:
        try:
            entry = data["entry"][0]
            return {
                "found":        True,
                "display_name": entry.get("displayName", "N/A"),
                "profile_url":  entry.get("profileUrl", "N/A"),
                "avatar_url":   f"https://www.gravatar.com/avatar/{md5}?s=200",
                "location":     entry.get("currentLocation", "N/A"),
                "about":        entry.get("aboutMe", "N/A")[:120],
                "accounts":     [a.get("name","") for a in entry.get("accounts", [])],
                "urls":         [u.get("value","") for u in entry.get("urls", [])],
            }
        except Exception:
            pass
    # Fallback: check if avatar image exists (d=404 returns 404 if no account)
    try:
        req = Request(
            f"https://www.gravatar.com/avatar/{md5}?d=404",
            headers=BROWSER_HEADERS
        )
        with urlopen(req, timeout=5) as resp:
            if resp.status == 200:
                return {
                    "found":       True,
                    "display_name": "N/A (no public profile)",
                    "profile_url": f"https://www.gravatar.com/{md5}",
                    "avatar_url":  f"https://www.gravatar.com/avatar/{md5}?s=200",
                    "location": "N/A", "about": "N/A",
                    "accounts": [], "urls": [],
                }
    except HTTPError:
        pass
    except Exception:
        pass
    return {"found": False}

PLATFORMS = [
    ("GitHub",     "https://github.com/{}"),
    ("GitLab",     "https://gitlab.com/{}"),
    ("Twitter/X",  "https://twitter.com/{}"),
    ("Instagram",  "https://www.instagram.com/{}/"),
    ("TikTok",     "https://www.tiktok.com/@{}"),
    ("Reddit",     "https://www.reddit.com/user/{}/"),
    ("LinkedIn",   "https://www.linkedin.com/in/{}"),
    ("Pinterest",  "https://www.pinterest.com/{}/"),
    ("Tumblr",     "https://{}.tumblr.com"),
    ("Medium",     "https://medium.com/@{}"),
    ("Dev.to",     "https://dev.to/{}"),
    ("Keybase",    "https://keybase.io/{}"),
    ("Pastebin",   "https://pastebin.com/u/{}"),
    ("HackerNews", "https://news.ycombinator.com/user?id={}"),
    ("Steam",      "https://steamcommunity.com/id/{}"),
    ("Twitch",     "https://www.twitch.tv/{}"),
    ("Replit",     "https://replit.com/@{}"),
    ("Fiverr",     "https://www.fiverr.com/{}"),
]

def probe_platform(name: str, url_tpl: str, username: str) -> dict:
    url = url_tpl.format(username)
    try:
        req = Request(url, headers=BROWSER_HEADERS)
        try:
            with urlopen(req, timeout=7) as resp:
                status = resp.status
        except HTTPError as e:
            status = e.code
        if status == 200:
            return {"platform": name, "username": username, "url": url, "found": True}
    except Exception:
        pass
    return {"platform": name, "username": username, "url": url, "found": False}

def generate_dork_links(addr: str, username: str, domain: str) -> list[dict]:
    dorks = [
        ("Email mentions on web",  f'"{addr}"'),
        ("Email on Pastebin",      f'site:pastebin.com "{addr}"'),
        ("Email on GitHub",        f'site:github.com "{addr}"'),
        ("Username on GitHub",     f'site:github.com "{username}"'),
        ("Email in documents",     f'"{addr}" filetype:pdf OR filetype:docx'),
        ("LinkedIn profile",       f'site:linkedin.com "{username}"'),
        ("Email in forums",        f'"{addr}" site:reddit.com OR site:stackoverflow.com'),
        ("Domain + email combo",   f'"{addr}" site:{domain}'),
    ]
    base = "https://www.google.com/search?q="
    return [{"label": l, "url": base + quote_plus(q)} for l, q in dorks]

def run_osint(addr: str, no_social: bool = False) -> dict:
    """Run full OSINT on an email address. Returns results dict."""
    addr = addr.strip().lower()
    struct = validate_email_addr(addr)
    if not struct["valid"]:
        fail(f"Invalid email address: {addr}")
        return {}

    username  = struct["username"]
    domain    = struct["domain"]
    usernames = derive_usernames(username)

    info(f"OSINT target:        {C.BOLD}{addr}{C.RESET}")
    info(f"Candidate usernames: {', '.join(usernames)}")

    info("Looking up MX / WHOIS...")
    mx    = dns_mx_lookup(domain)
    whois = whois_domain(domain)

    info("Checking Gravatar (profile + avatar fallback)...")
    gravatar = check_gravatar(addr)

    social_hits, social_miss = [], []
    if not no_social:
        info(f"Scanning {len(PLATFORMS)} platforms...")
        checked = {}
        for name, url_tpl in PLATFORMS:
            for uname in usernames:
                if name in checked:
                    break
                result = probe_platform(name, url_tpl, uname)
                time.sleep(0.25)
                if result["found"]:
                    checked[name] = True
                    social_hits.append(result)
                    ok(f"Found on {name}: {result['url']}")
                    break
            if name not in checked:
                social_miss.append({"platform": name})

    hibp  = {"note": "HIBP requires API key — check manually",
             "manual_url": f"https://haveibeenpwned.com/account/{quote_plus(addr)}"}
    dorks = generate_dork_links(addr, username, domain)

    return {
        "email": addr, "struct": struct, "mx": mx, "whois": whois,
        "gravatar": gravatar, "social_hits": social_hits,
        "social_miss": social_miss, "hibp": hibp, "dorks": dorks,
    }

def print_osint_report(r: dict):
    addr = r["email"]

    section("📧  EMAIL STRUCTURE")
    ok("Valid email address")
    found("Username", r["struct"]["username"])
    found("Domain",   r["struct"]["domain"])

    section("🌐  DOMAIN INTELLIGENCE")
    if r["mx"]:
        found("MX Record", r["mx"][0] + (f" (+{len(r['mx'])-1} more)" if len(r["mx"])>1 else ""))
    else:
        warn("No MX records found")
    if r["whois"]:
        found("Registrar",  r["whois"].get("registrar","N/A"))
        found("Registered", r["whois"].get("registered","N/A"))
        found("Expires",    r["whois"].get("expires","N/A"))
        found("Status",     r["whois"].get("status","N/A"))
    else:
        warn("WHOIS/RDAP data unavailable")

    section("🖼️   GRAVATAR PROFILE")
    if r["gravatar"].get("found"):
        g = r["gravatar"]
        found("Display Name", g["display_name"])
        found("Profile URL",  g["profile_url"])
        found("Avatar URL",   g["avatar_url"])
        if g["location"] != "N/A": found("Location", g["location"])
        if g["about"]    != "N/A": found("About",    g["about"])
        if g["accounts"]:          found("Linked Accts", ", ".join(g["accounts"]))
        for u in g["urls"]:        found("URL", u)
    else:
        notfound("Gravatar account")
        print(f"  {C.DIM}  (Most people don't use Gravatar — this is normal){C.RESET}")

    section("🔍  SOCIAL MEDIA & PLATFORM SCAN")
    if r["social_hits"]:
        for h in r["social_hits"]:
            found(h["platform"], f"{h['url']}  {C.DIM}(username: {h['username']}){C.RESET}")
    else:
        warn("No accounts found on scanned platforms")
    if r["social_miss"]:
        print(f"\n  {C.DIM}Not found: {', '.join(h['platform'] for h in r['social_miss'])}{C.RESET}")

    section("💥  BREACH CHECK  (HaveIBeenPwned)")
    warn(r["hibp"]["note"])
    info(f"Check manually → {r['hibp']['manual_url']}")

    section("🔎  GOOGLE DORK LINKS  (Manual Follow-up)")
    info("Open these in your browser:")
    for d in r["dorks"]:
        print(f"  {C.CYAN}•{C.RESET} {d['label']}")
        print(f"    {C.DIM}{d['url']}{C.RESET}")

    section("📊  OSINT SUMMARY")
    total = len(r["social_hits"]) + (1 if r["gravatar"].get("found") else 0)
    c = C.GREEN if total > 0 else C.DIM
    print(f"\n  {C.BOLD}Email:          {C.RESET}{addr}")
    print(f"  {C.BOLD}Accounts found: {C.RESET}{c}{total} platform(s){C.RESET}")


# ══════════════════════════════════════════════════════════════════════════════
#  JSON EXPORT
# ══════════════════════════════════════════════════════════════════════════════
def export_json(path: str, header_data: dict, osint_data: dict):
    payload = {
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "header_analysis": header_data,
        "osint": osint_data,
    }
    with open(path, "w") as f:
        json.dump(payload, f, indent=2, default=str)
    ok(f"JSON report saved → {path}")


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="Email SOC Toolkit — Header Analysis + OSINT",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          python3 email_soc_toolkit.py --demo
          python3 email_soc_toolkit.py --file suspicious.eml
          python3 email_soc_toolkit.py --file suspicious.eml --osint
          python3 email_soc_toolkit.py --osint -e target@example.com
          python3 email_soc_toolkit.py --demo --osint --json report.json
        """)
    )
    src = parser.add_mutually_exclusive_group()
    src.add_argument("--file", metavar="FILE", help="Path to .eml file")
    src.add_argument("--raw",  action="store_true", help="Paste raw headers (stdin)")
    src.add_argument("--demo", action="store_true", help="Use built-in demo phishing email")

    parser.add_argument("--osint",     action="store_true", help="Run OSINT on sender email")
    parser.add_argument("-e","--email",metavar="EMAIL",     help="Email for OSINT-only mode")
    parser.add_argument("--no-geo",    action="store_true", help="Skip IP geolocation")
    parser.add_argument("--no-social", action="store_true", help="Skip social platform scan")
    parser.add_argument("--json",      metavar="FILE",      help="Export JSON report")
    args = parser.parse_args()

    # Validate: need at least one source
    if not any([args.file, args.raw, args.demo, args.email]):
        parser.print_help()
        sys.exit(1)

    banner()

    header_data = {}
    osint_data  = {}

    # ── HEADER ANALYSIS ───────────────────────────────────────────────────────
    if args.file or args.raw or args.demo:
        if args.demo:
            info("Loading built-in demo phishing email...\n")
            raw = DEMO_RAW
        elif args.file:
            try:
                with open(args.file, "rb") as f:
                    raw = f.read().decode("utf-8", errors="replace")
                info(f"Loaded: {args.file}\n")
            except FileNotFoundError:
                fail(f"File not found: {args.file}")
                sys.exit(1)
        else:
            info("Paste raw email headers. Press Ctrl+D when done:\n")
            raw = sys.stdin.read()

        msg      = parse_email_msg(raw)
        hops     = extract_received_chain(msg)
        auth     = parse_auth_results(msg)
        findings = analyze_phishing(msg, hops, auth)
        score, _ = compute_risk_score(findings)

        geo_results = []
        if not args.no_geo:
            all_ips = list(dict.fromkeys(ip for h in hops for ip in h["ips"]))
            if all_ips:
                info(f"Geolocating {len(all_ips)} IP(s)...")
                for ip in all_ips[:5]:
                    geo_results.append(geolocate_ip(ip))

        print_header_report(msg, hops, auth, findings, geo_results)

        header_data = {
            "from":       msg.get("From",""),
            "to":         msg.get("To",""),
            "subject":    msg.get("Subject",""),
            "date":       msg.get("Date",""),
            "reply_to":   msg.get("Reply-To",""),
            "auth":       auth,
            "hops":       hops,
            "geo":        geo_results,
            "findings":   findings,
            "risk_score": score,
        }

        # Auto-OSINT on sender if --osint flag given
        if args.osint and not args.email:
            sender_raw = msg.get("From","")
            m = re.search(r'[\w._%+\-]+@[\w.\-]+\.[a-zA-Z]{2,}', sender_raw)
            if m:
                sender_email = m.group(0).lower()
                section(f"🔬  AUTO-OSINT ON SENDER:  {sender_email}")
                osint_data = run_osint(sender_email, no_social=args.no_social)
                if osint_data:
                    print_osint_report(osint_data)
            else:
                warn("Could not extract sender email for OSINT")

    # ── STANDALONE OSINT ──────────────────────────────────────────────────────
    if args.email:
        section(f"🔬  OSINT MODE:  {args.email}")
        osint_data = run_osint(args.email, no_social=args.no_social)
        if osint_data:
            print_osint_report(osint_data)

    # ── TIMESTAMP ─────────────────────────────────────────────────────────────
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"\n{C.DIM}{'─'*64}")
    print(f"  Analysis complete — {ts}")
    print(f"  For SOC use: pipe --json output into your SIEM/MISP platform.")
    print(f"{'─'*64}{C.RESET}\n")

    # ── JSON EXPORT ───────────────────────────────────────────────────────────
    if args.json:
        export_json(args.json, header_data, osint_data)


if __name__ == "__main__":
    main()
