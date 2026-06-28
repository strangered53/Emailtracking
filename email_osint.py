#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║           EMAIL OSINT TOOL — ACCOUNT & INFO FINDER          ║
║              SOC Analyst Toolkit  |  Kali Linux             ║
╚══════════════════════════════════════════════════════════════╝

Usage:
  python3 email_osint.py -e target@example.com
  python3 email_osint.py -e target@example.com --json report.json
  python3 email_osint.py -e target@example.com --no-gravatar

⚠️  FOR AUTHORIZED INVESTIGATIONS & UNIVERSITY RESEARCH ONLY
"""

import argparse
import hashlib
import json
import re
import socket
import sys
import time
from datetime import datetime, timezone
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import urlencode, quote_plus


# ── Colors ────────────────────────────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def banner():
    print(f"""{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════════════╗
║           EMAIL OSINT TOOL — ACCOUNT & INFO FINDER             ║
║           SOC Analyst Toolkit  |  Kali Linux  |  Python3       ║
╚══════════════════════════════════════════════════════════════════╝
{C.YELLOW}  ⚠  Use only on emails you own or have written authorization to investigate.{C.RESET}
""")

def section(title: str):
    print(f"\n{C.CYAN}{C.BOLD}{'─'*62}")
    print(f"  {title}")
    print(f"{'─'*62}{C.RESET}")

def ok(msg):   print(f"  {C.GREEN}[✔]{C.RESET} {msg}")
def warn(msg): print(f"  {C.YELLOW}[!]{C.RESET} {msg}")
def info(msg): print(f"  {C.BLUE}[*]{C.RESET} {msg}")
def fail(msg): print(f"  {C.RED}[✘]{C.RESET} {msg}")
def found(label, value): print(f"  {C.GREEN}[✔]{C.RESET} {C.BOLD}{label:<22}{C.RESET} {value}")
def notfound(label):     print(f"  {C.DIM}[–] {label:<22} not found{C.RESET}")


# ── HTTP Helper ────────────────────────────────────────────────────────────────
HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Accept": "application/json, text/html,*/*",
}

def http_get(url: str, timeout: int = 8, json_resp: bool = False):
    try:
        req = Request(url, headers=HEADERS)
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            if json_resp:
                return json.loads(raw)
            return raw.decode("utf-8", errors="replace")
    except HTTPError as e:
        return None  # 404 / 403 etc.
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 1 — Email Validation & Domain Intel
# ══════════════════════════════════════════════════════════════════════════════
def analyze_email_structure(email: str) -> dict:
    result = {"valid": False, "username": "", "domain": "", "issues": []}
    pattern = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        result["issues"].append("Invalid email format")
        return result
    parts = email.split("@")
    result["valid"] = True
    result["username"] = parts[0]
    result["domain"] = parts[1]
    return result

def dns_mx_lookup(domain: str) -> list[str]:
    """Try to find MX records via Google DNS-over-HTTPS (no dnspython needed)."""
    try:
        data = http_get(
            f"https://dns.google/resolve?name={domain}&type=MX",
            json_resp=True
        )
        if data and data.get("Answer"):
            return [r["data"] for r in data["Answer"] if r.get("type") == 15]
    except Exception:
        pass
    return []

def whois_domain(domain: str) -> dict:
    """Query rdap.org for domain registration info."""
    data = http_get(f"https://rdap.org/domain/{domain}", json_resp=True)
    if not data:
        return {}
    result = {}
    try:
        result["registrar"] = next(
            (e["fn"][0] for e in data.get("entities", [])
             if "registrar" in e.get("roles", []) and e.get("fn")), "N/A"
        )
        events = {e["eventAction"]: e["eventDate"] for e in data.get("events", [])}
        result["registered"] = events.get("registration", "N/A")[:10]
        result["expires"]    = events.get("expiration",   "N/A")[:10]
        result["updated"]    = events.get("last changed", "N/A")[:10]
        result["status"]     = ", ".join(data.get("status", []))
    except Exception:
        pass
    return result


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 2 — Gravatar (profile photo + account existence)
# ══════════════════════════════════════════════════════════════════════════════
def check_gravatar(email: str) -> dict:
    md5 = hashlib.md5(email.strip().lower().encode()).hexdigest()
    url = f"https://www.gravatar.com/{md5}.json"
    data = http_get(url, json_resp=True)
    if not data:
        return {"found": False}
    try:
        entry = data["entry"][0]
        return {
            "found":       True,
            "display_name": entry.get("displayName", "N/A"),
            "profile_url": entry.get("profileUrl", "N/A"),
            "avatar_url":  f"https://www.gravatar.com/avatar/{md5}?s=200",
            "location":    entry.get("currentLocation", "N/A"),
            "about":       entry.get("aboutMe", "N/A")[:120],
            "accounts":    [a.get("name", "") for a in entry.get("accounts", [])],
            "urls":        [u.get("value", "") for u in entry.get("urls", [])],
        }
    except Exception:
        return {"found": False}


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 3 — Social Media Username Probe
#  Derives likely usernames from the email and checks platform URLs
# ══════════════════════════════════════════════════════════════════════════════

def derive_usernames(email: str, username: str) -> list[str]:
    """Generate candidate usernames from email address."""
    candidates = [username]
    # common separators
    for sep in [".", "_", "-"]:
        if sep in username:
            candidates.append(username.replace(sep, ""))
            parts = username.split(sep)
            if len(parts) >= 2:
                candidates.append(parts[0])
                candidates.append(parts[0] + parts[-1])
    return list(dict.fromkeys(candidates))  # deduplicate, preserve order

# Platforms to check: (name, url_template, check_method)
# check_method: "200" = 200 OK means found, "404" = 404 means NOT found
PLATFORMS = [
    # Social
    ("GitHub",      "https://github.com/{}",                  "200"),
    ("GitLab",      "https://gitlab.com/{}",                  "200"),
    ("Twitter/X",   "https://twitter.com/{}",                 "200"),
    ("Instagram",   "https://www.instagram.com/{}/",          "200"),
    ("TikTok",      "https://www.tiktok.com/@{}",             "200"),
    ("Reddit",      "https://www.reddit.com/user/{}/",        "200"),
    ("LinkedIn",    "https://www.linkedin.com/in/{}",         "200"),
    ("Pinterest",   "https://www.pinterest.com/{}/",          "200"),
    ("Tumblr",      "https://{}.tumblr.com",                  "200"),
    ("Medium",      "https://medium.com/@{}",                 "200"),
    ("Dev.to",      "https://dev.to/{}",                      "200"),
    ("Keybase",     "https://keybase.io/{}",                  "200"),
    ("Pastebin",    "https://pastebin.com/u/{}",              "200"),
    ("HackerNews",  "https://news.ycombinator.com/user?id={}", "200"),
    ("Steam",       "https://steamcommunity.com/id/{}",       "200"),
    ("Twitch",      "https://www.twitch.tv/{}",               "200"),
    ("Replit",      "https://replit.com/@{}",                 "200"),
    ("Fiverr",      "https://www.fiverr.com/{}",              "200"),
]

def probe_platform(name: str, url_template: str, username: str) -> dict:
    url = url_template.format(username)
    try:
        req = Request(url, headers=HEADERS)
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


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 4 — HaveIBeenPwned (breach check — public summary only)
# ══════════════════════════════════════════════════════════════════════════════
def check_hibp(email: str) -> dict:
    """
    HIBP v3 API requires a paid key for breach lookup.
    We check the public paste search and inform the user to verify manually.
    """
    return {
        "note": "HIBP breach lookup requires API key (https://haveibeenpwned.com/API/Key)",
        "manual_url": f"https://haveibeenpwned.com/account/{quote_plus(email)}"
    }


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 5 — Google Dorking Links (manual OSINT follow-up)
# ══════════════════════════════════════════════════════════════════════════════
def generate_dork_links(email: str, username: str, domain: str) -> list[dict]:
    dorks = [
        ("Email mentions on web",   f'"{email}"'),
        ("Email on Pastebin",       f'site:pastebin.com "{email}"'),
        ("Email on GitHub",         f'site:github.com "{email}"'),
        ("Username on GitHub",      f'site:github.com "{username}"'),
        ("Email in documents",      f'"{email}" filetype:pdf OR filetype:docx'),
        ("LinkedIn profile",        f'site:linkedin.com "{username}"'),
        ("Email in forums",         f'"{email}" site:reddit.com OR site:stackoverflow.com'),
        ("Domain + email combo",    f'"{email}" site:{domain}'),
    ]
    base = "https://www.google.com/search?q="
    return [{"label": label, "url": base + quote_plus(query)} for label, query in dorks]


# ══════════════════════════════════════════════════════════════════════════════
#  REPORT
# ══════════════════════════════════════════════════════════════════════════════
def print_report(email_addr, struct, mx, whois, gravatar,
                 social_hits, social_miss, hibp, dorks):

    section("📧  EMAIL STRUCTURE")
    if struct["valid"]:
        ok(f"Valid email address")
        found("Username",  struct["username"])
        found("Domain",    struct["domain"])
    else:
        fail("Invalid email format")
        return

    section("🌐  DOMAIN INTELLIGENCE")
    if mx:
        found("MX Records", mx[0] if len(mx) == 1 else f"{mx[0]} (+{len(mx)-1} more)")
    else:
        warn("No MX records found (domain may not receive email)")
    if whois:
        found("Registrar",   whois.get("registrar", "N/A"))
        found("Registered",  whois.get("registered", "N/A"))
        found("Expires",     whois.get("expires", "N/A"))
        found("Status",      whois.get("status", "N/A"))
    else:
        warn("WHOIS/RDAP data unavailable for this domain")

    section("🖼️   GRAVATAR PROFILE")
    if gravatar.get("found"):
        found("Display Name", gravatar["display_name"])
        found("Profile URL",  gravatar["profile_url"])
        found("Avatar",       gravatar["avatar_url"])
        if gravatar["location"] != "N/A":
            found("Location",  gravatar["location"])
        if gravatar["about"] != "N/A":
            found("About",     gravatar["about"])
        if gravatar["accounts"]:
            found("Linked Accts", ", ".join(gravatar["accounts"]))
        if gravatar["urls"]:
            for u in gravatar["urls"]:
                found("URL",  u)
    else:
        notfound("Gravatar account")

    section("🔍  SOCIAL MEDIA & PLATFORM SCAN")
    if social_hits:
        for hit in social_hits:
            found(hit["platform"], f"{hit['url']}  (username: {hit['username']})")
    else:
        warn("No accounts found on scanned platforms")
    if social_miss:
        print(f"\n  {C.DIM}Not found on: {', '.join(h['platform'] for h in social_miss)}{C.RESET}")

    section("💥  BREACH CHECK (HaveIBeenPwned)")
    warn(hibp["note"])
    info(f"Check manually → {hibp['manual_url']}")

    section("🔎  GOOGLE DORK LINKS (Manual Follow-up)")
    info("Open these in your browser for deeper OSINT:")
    for dork in dorks:
        print(f"  {C.CYAN}•{C.RESET} {dork['label']}")
        print(f"    {C.DIM}{dork['url']}{C.RESET}")

    section("📊  SUMMARY")
    total_found = len(social_hits) + (1 if gravatar.get("found") else 0)
    print(f"\n  {C.BOLD}Email:         {C.RESET}{email_addr}")
    print(f"  {C.BOLD}Accounts found:{C.RESET} {C.GREEN if total_found > 0 else C.DIM}{total_found} platform(s){C.RESET}")
    print(f"  {C.BOLD}Analyzed at:   {C.RESET}{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")

    print(f"\n{C.DIM}{'─'*62}")
    print(f"  For SOC use: feed JSON output into your SIEM/MISP for actor profiling.")
    print(f"{'─'*62}{C.RESET}\n")


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="Email OSINT Tool — Account & Info Finder",
        epilog="Example: python3 email_osint.py -e target@gmail.com --json output.json"
    )
    parser.add_argument("-e", "--email", required=True, help="Target email address")
    parser.add_argument("--json", metavar="FILE", help="Export results to JSON")
    parser.add_argument("--no-gravatar", action="store_true", help="Skip Gravatar lookup")
    parser.add_argument("--no-social", action="store_true", help="Skip social platform scan")
    args = parser.parse_args()

    banner()

    email_addr = args.email.strip().lower()
    info(f"Target: {C.BOLD}{email_addr}{C.RESET}")

    # 1. Validate
    struct = analyze_email_structure(email_addr)
    if not struct["valid"]:
        fail(f"Invalid email: {email_addr}")
        sys.exit(1)

    username = struct["username"]
    domain   = struct["domain"]
    usernames = derive_usernames(email_addr, username)
    info(f"Candidate usernames: {', '.join(usernames)}")

    # 2. Domain Intel
    info("Looking up domain DNS/WHOIS...")
    mx    = dns_mx_lookup(domain)
    whois = whois_domain(domain)

    # 3. Gravatar
    gravatar = {"found": False}
    if not args.no_gravatar:
        info("Checking Gravatar...")
        gravatar = check_gravatar(email_addr)

    # 4. Social Media Scan
    social_hits, social_miss = [], []
    if not args.no_social:
        info(f"Scanning {len(PLATFORMS)} platforms with {len(usernames)} username variant(s)...")
        checked = {}
        for name, url_tpl, method in PLATFORMS:
            best = None
            for uname in usernames:
                if name in checked:
                    break
                result = probe_platform(name, url_tpl, uname)
                time.sleep(0.3)  # be polite to servers
                if result["found"]:
                    best = result
                    checked[name] = True
                    break
            if best:
                social_hits.append(best)
                ok(f"Found on {name}: {best['url']}")
            else:
                social_miss.append({"platform": name})

    # 5. HIBP
    hibp = check_hibp(email_addr)

    # 6. Dorks
    dorks = generate_dork_links(email_addr, username, domain)

    # Print full report
    print_report(email_addr, struct, mx, whois, gravatar,
                 social_hits, social_miss, hibp, dorks)

    # JSON export
    if args.json:
        data = {
            "email":      email_addr,
            "structure":  struct,
            "mx_records": mx,
            "whois":      whois,
            "gravatar":   gravatar,
            "social_accounts_found": social_hits,
            "hibp_check": hibp,
            "google_dorks": dorks,
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
        }
        with open(args.json, "w") as f:
            json.dump(data, f, indent=2)
        ok(f"JSON report saved → {args.json}")


if __name__ == "__main__":
    main()
