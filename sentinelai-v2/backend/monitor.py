"""
AI Privacy Monitor v2 - With Full Security Action Suggestion System
Monitors DNS traffic, detects trackers, assigns risk levels,
suggests browser-specific fixes, and prints a session summary.
"""

import subprocess
import requests
import logging
import platform
import os
import json
import webbrowser
import socket
import sys
from datetime import datetime
from pathlib import Path
from functools import lru_cache
from collections import Counter

# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────
TSHARK_PATH    = r"C:\Program Files\Wireshark\tshark.exe"
NETWORK_IFACE  = "4"
OLLAMA_URL     = "http://localhost:11434/api/generate"
OLLAMA_MODEL   = "phi3"
OLLAMA_TIMEOUT = 120


def safe_print(*parts, sep=" ", end="\n"):
    """Print without crashing on Windows consoles that are not UTF-8."""
    text = sep.join(str(part) for part in parts)
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    sanitized = text.encode(encoding, errors="replace").decode(encoding, errors="replace")
    print(sanitized, end=end)

# ─────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("PrivacyMonitor")

# ─────────────────────────────────────────────
# TRACKER DATABASE — with risk levels + actions
# ─────────────────────────────────────────────
# Structure:
#   keyword → {
#       name        : human-readable tracker name
#       risk        : LOW | MEDIUM | HIGH | CRITICAL
#       data        : list of data points collected
#       block       : how to block this tracker
#       delete_url  : link to delete your data (optional)
#       vpn_needed  : whether a VPN is strongly recommended
#   }

TRACKERS: dict[str, dict] = {
    "google-analytics": {
        "name"       : "Google Analytics",
        "risk"       : "MEDIUM",
        "data"       : ["Pages visited", "Time spent on site", "Device type", "Location (city-level)", "Referral source"],
        "block"      : "Install uBlock Origin → blocks GA on all websites automatically",
        "delete_url" : "https://myactivity.google.com",
        "vpn_needed" : False,
    },
    "googletagmanager": {
        "name"       : "Google Tag Manager",
        "risk"       : "MEDIUM",
        "data"       : ["Loads other trackers", "User interactions", "Form submissions", "Click events"],
        "block"      : "Install uBlock Origin → GTM loads all other trackers, blocking it cuts many at once",
        "delete_url" : "https://myactivity.google.com",
        "vpn_needed" : False,
    },
    "doubleclick": {
        "name"       : "Google DoubleClick (Ad Tracking)",
        "risk"       : "HIGH",
        "data"       : ["Cross-site browsing history", "Purchase intent", "Ad click behaviour", "Device fingerprint", "IP address"],
        "block"      : "Install uBlock Origin + Enable 'EasyPrivacy' filter list inside it",
        "delete_url" : "https://adssettings.google.com",
        "vpn_needed" : True,
    },
    "facebook": {
        "name"       : "Facebook / Meta Tracker",
        "risk"       : "CRITICAL",
        "data"       : ["Pages you visit outside Facebook", "Purchases made", "Login status", "Device info", "Location", "Behaviour profile"],
        "block"      : "Use Firefox + install 'Facebook Container' extension → isolates FB completely",
        "delete_url" : "https://www.facebook.com/settings?tab=your_facebook_information",
        "vpn_needed" : True,
    },
    "growingio": {
        "name"       : "GrowingIO Tracker",
        "risk"       : "MEDIUM",
        "data"       : ["User behaviour analytics", "Click heatmaps", "Session recordings", "App usage patterns"],
        "block"      : "Install uBlock Origin and add GrowingIO to custom filter list",
        "delete_url" : None,
        "vpn_needed" : False,
    },
    "sentry": {
        "name"       : "Sentry Error Monitoring",
        "risk"       : "LOW",
        "data"       : ["App crash reports", "Error logs", "Browser version", "OS version"],
        "block"      : "Generally safe — used by developers to fix bugs. Block with uBlock if desired.",
        "delete_url" : None,
        "vpn_needed" : False,
    },
    "amazon-adsystem": {
        "name"       : "Amazon Ad System",
        "risk"       : "HIGH",
        "data"       : ["Purchase history", "Product views", "Search queries", "Cross-site tracking"],
        "block"      : "Install uBlock Origin + enable 'EasyPrivacy' list",
        "delete_url" : "https://www.amazon.com/adprefs",
        "vpn_needed" : True,
    },
    "criteo": {
        "name"       : "Criteo Ad Retargeting",
        "risk"       : "HIGH",
        "data"       : ["Products you viewed", "Cart contents", "Purchase intent", "Cross-site profile"],
        "block"      : "Install uBlock Origin — Criteo is in EasyPrivacy blocklist by default",
        "delete_url" : "https://www.criteo.com/privacy/disable-criteo-services-on-internet-browsers/",
        "vpn_needed" : True,
    },
    "hotjar": {
        "name"       : "Hotjar Session Recording",
        "risk"       : "HIGH",
        "data"       : ["Screen recordings of your session", "Mouse movements", "Keystrokes (partial)", "Scroll depth"],
        "block"      : "Install uBlock Origin — add 'hotjar.com' to custom filters",
        "delete_url" : "https://www.hotjar.com/legal/compliance/opt-out/",
        "vpn_needed" : False,
    },
    "mixpanel": {
        "name"       : "Mixpanel Analytics",
        "risk"       : "MEDIUM",
        "data"       : ["Feature usage", "Button clicks", "User journey", "Device info"],
        "block"      : "Install uBlock Origin and add mixpanel.com to custom filter list",
        "delete_url" : None,
        "vpn_needed" : False,
    },
    "segment": {
        "name"       : "Segment Data Pipeline",
        "risk"       : "HIGH",
        "data"       : ["Aggregates data from ALL other trackers on the site", "Sends to 300+ third-party tools"],
        "block"      : "Install uBlock Origin — blocking Segment cuts data to dozens of downstream trackers",
        "delete_url" : None,
        "vpn_needed" : True,
    },
    "tiktok": {
        "name"       : "TikTok Pixel Tracker",
        "risk"       : "CRITICAL",
        "data"       : ["Browsing behaviour", "Purchase data", "Device fingerprint", "Location", "Cross-app tracking"],
        "block"      : "Install uBlock Origin + consider DNS-level blocking via Pi-hole",
        "delete_url" : None,
        "vpn_needed" : True,
    },
    "snap.licdn": {
        "name"       : "LinkedIn Insight / Pixel Tracker",
        "risk"       : "HIGH",
        "data"       : ["Pages you visited", "Job title inferred from LinkedIn profile", "Company you work at", "Purchase behaviour", "Device info"],
        "block"      : "Install uBlock Origin — add 'snap.licdn.com' to custom filter list",
        "delete_url" : "https://www.linkedin.com/psettings/guest-controls/retargeting-opt-out",
        "vpn_needed" : True,
    },
    "platform.linkedin": {
        "name"       : "LinkedIn Insight / Pixel Tracker",
        "risk"       : "HIGH",
        "data"       : ["Pages you visited", "Job title inferred from LinkedIn profile", "Company you work at", "Purchase behaviour", "Device info"],
        "block"      : "Install uBlock Origin — add 'platform.linkedin.com' to custom filter list",
        "delete_url" : "https://www.linkedin.com/psettings/guest-controls/retargeting-opt-out",
        "vpn_needed" : True,
    },
    "ads.linkedin": {
        "name"       : "LinkedIn Ad Tracker",
        "risk"       : "HIGH",
        "data"       : ["Professional profile data", "Job title", "Industry", "Browsing behaviour across sites"],
        "block"      : "Install uBlock Origin + EasyPrivacy filter list",
        "delete_url" : "https://www.linkedin.com/psettings/guest-controls/retargeting-opt-out",
        "vpn_needed" : True,
    },
    "twitter": {
        "name"       : "Twitter / X Pixel Tracker",
        "risk"       : "HIGH",
        "data"       : ["Pages visited on other websites", "Purchase behaviour", "Device fingerprint", "App activity"],
        "block"      : "Install uBlock Origin — add 't.co' and 'ads.twitter.com' to custom filter list",
        "delete_url" : "https://twitter.com/settings/your_twitter_data",
        "vpn_needed" : True,
    },
    "pintrk": {
        "name"       : "Pinterest Pixel Tracker",
        "risk"       : "MEDIUM",
        "data"       : ["Pages you visited", "Products you viewed", "Purchase intent"],
        "block"      : "Install uBlock Origin — Pinterest Pixel is in EasyPrivacy by default",
        "delete_url" : "https://help.pinterest.com/en/article/personalization-and-data",
        "vpn_needed" : False,
    },
}

# ─────────────────────────────────────────────
# SERVICE DATABASE
# ─────────────────────────────────────────────
SERVICES: dict[str, str] = {
    # Messaging
    "whatsapp"       : "Messaging Service",
    "telegram"       : "Messaging Service",
    "discord"        : "Messaging Service",
    # Work / Meetings
    "teams"          : "Microsoft Teams",
    "microsoftteams" : "Microsoft Teams",
    "zoom"           : "Video Conferencing",
    "slack"          : "Work Chat",
    "notion"         : "Productivity Tool",
    # Coding / Learning
    "leetcode"       : "Coding Platform",
    "getbootstrap"   : "Bootstrap Docs",
    "bootstrap"      : "Web Framework / Docs",
    "w3schools"      : "Learning Website",
    "w3school"       : "Learning Website",
    "stackoverflow"  : "Developer Q&A",
    "geeksforgeeks"  : "Learning Website",
    "github"         : "Developer Platform",
    "wikipedia"      : "Knowledge Website",
    "mdn"            : "Developer Docs",
    "hackerrank"     : "Coding Platform",
    "codechef"       : "Coding Platform",
    # Search & General
    "google"         : "Search / Web Service",
    "bing"           : "Search Engine",
    "yahoo"          : "Search / Web Service",
    # Streaming
    "youtube"        : "Video Streaming",
    "netflix"        : "Video Streaming",
    "spotify"        : "Music Streaming",
    "hotstar"        : "Video Streaming",
    # Professional
    "linkedin"       : "Professional Network",
}

# ─────────────────────────────────────────────
# WEBSITE NAME LOOKUP
# Maps domain keyword → friendly website name
# Used to show "W3Schools" instead of "w3schools.com"
# ─────────────────────────────────────────────
WEBSITE_NAMES: dict[str, str] = {
    # Education & Coding
    "w3schools"       : "W3Schools",
    "w3school"        : "W3Schools",
    "leetcode"        : "LeetCode",
    "stackoverflow"   : "Stack Overflow",
    "geeksforgeeks"   : "GeeksForGeeks",
    "codecademy"      : "Codecademy",
    "udemy"           : "Udemy",
    "coursera"        : "Coursera",
    "khanacademy"     : "Khan Academy",
    "github"          : "GitHub",
    "medium"          : "Medium",
    "hackerrank"      : "HackerRank",
    "codechef"        : "CodeChef",
    "interviewbit"    : "InterviewBit",
    # Indian Shopping
    "nykaa"           : "Nykaa",
    "nykaafashion"    : "Nykaa Fashion",
    "flipkart"        : "Flipkart",
    "flixcart"        : "Flipkart",
    "myntra"          : "Myntra",
    "meesho"          : "Meesho",
    "snapdeal"        : "Snapdeal",
    "ajio"            : "AJIO",
    "amazon"          : "Amazon",
    "bigbasket"       : "BigBasket",
    "blinkit"         : "Blinkit",
    "zomato"          : "Zomato",
    "swiggy"          : "Swiggy",
    "zepto"           : "Zepto",
    "jiomart"         : "JioMart",
    "tatacliq"        : "Tata CLiQ",
    "reliancedigital" : "Reliance Digital",
    # Social Media
    "facebook"        : "Facebook",
    "instagram"       : "Instagram",
    "twitter"         : "Twitter / X",
    "linkedin"        : "LinkedIn",
    "reddit"          : "Reddit",
    "pinterest"       : "Pinterest",
    "snapchat"        : "Snapchat",
    "tiktok"          : "TikTok",
    "threads"         : "Threads",
    # Messaging
    "whatsapp"        : "WhatsApp",
    "telegram"        : "Telegram",
    "discord"         : "Discord",
    # Streaming
    "youtube"         : "YouTube",
    "netflix"         : "Netflix",
    "spotify"         : "Spotify",
    "hotstar"         : "Disney+ Hotstar",
    "primevideo"      : "Amazon Prime Video",
    "jiocinema"       : "JioCinema",
    "sonyliv"         : "SonyLIV",
    # News (India)
    "timesofindia"    : "Times of India",
    "ndtv"            : "NDTV",
    "thehindu"        : "The Hindu",
    "indiatimes"      : "India Times",
    "hindustantimes"  : "Hindustan Times",
    "indianexpress"   : "Indian Express",
    "livemint"        : "Livemint",
    "moneycontrol"    : "Moneycontrol",
    "economictimes"   : "Economic Times",
    # Web Frameworks / Docs
    "getbootstrap"    : "Bootstrap",
    "bootstrap"       : "Bootstrap",
    "cdnjs"           : "cdnjs CDN",
    "jsdelivr"        : "jsDelivr CDN",
    "unpkg"           : "unpkg CDN",
    "mdn"             : "MDN Web Docs",
    # Search / Productivity
    "google"          : "Google",
    "microsoft"       : "Microsoft",
    "apple"           : "Apple",
    "yahoo"           : "Yahoo",
    "bing"            : "Bing",
    "notion"          : "Notion",
    "slack"           : "Slack",
    "zoom"            : "Zoom",
    "teams"           : "Microsoft Teams",
    "microsoftteams"  : "Microsoft Teams",
    # Travel
    "makemytrip"      : "MakeMyTrip",
    "goibibo"         : "Goibibo",
    "irctc"           : "IRCTC",
    "cleartrip"       : "Cleartrip",
    # Finance
    "zerodha"         : "Zerodha",
    "groww"           : "Groww",
    "paytm"           : "Paytm",
    "phonepe"         : "PhonePe",
    "gpay"            : "Google Pay",
}

# ─────────────────────────────────────────────
# TRACKER → SITE ATTRIBUTION
# Maps tracker domain keywords to the real website
# that most commonly embeds them, so we can show
# "Loaded by: Nykaa" instead of "Loaded by: a website using Criteo"
#
# This is updated based on real observed sessions.
# Format: tracker_domain_keyword → likely site name
# ─────────────────────────────────────────────
TRACKER_SITE_HINTS: dict[str, str] = {
    # Nykaa specific signature trackers
    "criteo"          : "Nykaa / Flipkart / a shopping site",
    "amazon-adsystem" : "Nykaa / Flipkart / a shopping site",
    # LeetCode specific
    "growingio"       : "LeetCode",
    # Generic — shown when we truly can't tell
    "doubleclick"     : "a website with Google Ads",
    "googletagmanager": "a website with Google Tag Manager",
    "google-analytics": "a website with Google Analytics",
    "mixpanel"        : "a website with Mixpanel",
    "hotjar"          : "a website with Hotjar",
    "segment"         : "a website with Segment",
    "sentry"          : "a website with Sentry",
    "tiktok"          : "a website with TikTok Pixel",
    "snap.licdn"      : "a website with LinkedIn Pixel",
    "platform.linkedin": "a website with LinkedIn Pixel",
    "ads.linkedin"    : "a website with LinkedIn Ads",
    "twitter"         : "a website with Twitter Pixel",
    "pintrk"          : "a website with Pinterest Pixel",
    # MS Teams domains
    "teams.microsoft" : "Microsoft Teams",
    "teams.live"      : "Microsoft Teams",
    "skype"           : "Microsoft Teams / Skype",
    # Bootstrap CDN domains
    "getbootstrap"    : "Bootstrap",
    "bootstrapcdn"    : "Bootstrap",
    # Sentry → LeetCode (confirmed from session data)
    "ingest.sentry"   : "LeetCode",
}




# ─────────────────────────────────────────────
# WEBSITE NAME RESOLVER
# Converts raw domains to human-friendly names.
# Priority: tracker-specific hints → specific site names → broad fallback
# ─────────────────────────────────────────────

# Broad keywords that accidentally match tracker domains
# e.g. "google" would match "googletagmanager.com"
# So these are checked LAST, only after all specific matches fail
_BROAD_KEYWORDS = {"google", "microsoft", "amazon", "apple", "yahoo", "bing"}


def friendly_website_name(domain: str) -> str:
    """
    Convert a raw domain like 'gum.criteo.com' into a
    human-readable name like 'Nykaa / Flipkart / a shopping site'.

    Priority:
    1. TRACKER_SITE_HINTS (longest keyword first — most specific)
    2. WEBSITE_NAMES specific keywords (skipping broad ones)
    3. WEBSITE_NAMES broad keywords (google, microsoft, etc.)
    4. Root domain fallback
    """
    d = domain.lower()

    # 1. Tracker-to-site hints, longest keyword first to avoid partial matches
    for kw, hint in sorted(TRACKER_SITE_HINTS.items(), key=lambda x: -len(x[0])):
        if kw in d:
            return hint

    # 2. Specific site names (skip broad ones that cause false matches)
    for kw, name in sorted(WEBSITE_NAMES.items(), key=lambda x: -len(x[0])):
        if kw in _BROAD_KEYWORDS:
            continue
        if kw in d:
            return name

    # 3. Broad keywords as last resort
    for kw in sorted(_BROAD_KEYWORDS, key=lambda x: -len(x)):
        if kw in d:
            return WEBSITE_NAMES.get(kw, kw.title())

    # 4. Extract readable root domain
    parts = d.replace("www.", "").split(".")
    if len(parts) >= 2:
        return f"{parts[-2]}.{parts[-1]}"
    return domain


# ─────────────────────────────────────────────
# COUNTRY PRIVACY LAW DATABASE
# Maps ISO country code → privacy law info
# ─────────────────────────────────────────────
PRIVACY_LAWS: dict[str, dict] = {
    # Strong — GDPR or equivalent
    "DE": {"law": "GDPR",              "rating": "STRONG",   "icon": "✅", "color": "#22c55e"},
    "FR": {"law": "GDPR",              "rating": "STRONG",   "icon": "✅", "color": "#22c55e"},
    "NL": {"law": "GDPR",              "rating": "STRONG",   "icon": "✅", "color": "#22c55e"},
    "IE": {"law": "GDPR",              "rating": "STRONG",   "icon": "✅", "color": "#22c55e"},
    "SE": {"law": "GDPR",              "rating": "STRONG",   "icon": "✅", "color": "#22c55e"},
    "FI": {"law": "GDPR",              "rating": "STRONG",   "icon": "✅", "color": "#22c55e"},
    "DK": {"law": "GDPR",              "rating": "STRONG",   "icon": "✅", "color": "#22c55e"},
    "AT": {"law": "GDPR",              "rating": "STRONG",   "icon": "✅", "color": "#22c55e"},
    "CH": {"law": "Swiss nFADP",       "rating": "STRONG",   "icon": "✅", "color": "#22c55e"},
    "GB": {"law": "UK GDPR",           "rating": "STRONG",   "icon": "✅", "color": "#22c55e"},
    "CA": {"law": "PIPEDA",            "rating": "STRONG",   "icon": "✅", "color": "#22c55e"},
    "AU": {"law": "Privacy Act 1988",  "rating": "STRONG",   "icon": "✅", "color": "#22c55e"},
    "JP": {"law": "APPI",              "rating": "STRONG",   "icon": "✅", "color": "#22c55e"},
    "BR": {"law": "LGPD",              "rating": "STRONG",   "icon": "✅", "color": "#22c55e"},
    "KR": {"law": "PIPA",              "rating": "STRONG",   "icon": "✅", "color": "#22c55e"},
    "NZ": {"law": "Privacy Act 2020",  "rating": "STRONG",   "icon": "✅", "color": "#22c55e"},
    "SG": {"law": "PDPA",              "rating": "STRONG",   "icon": "✅", "color": "#22c55e"},
    # Moderate
    "US": {"law": "No federal law (state laws vary)", "rating": "MODERATE", "icon": "🟡", "color": "#eab308"},
    "IN": {"law": "DPDP Act 2023",     "rating": "MODERATE", "icon": "🟡", "color": "#eab308"},
    "MX": {"law": "LFPDPPP",           "rating": "MODERATE", "icon": "🟡", "color": "#eab308"},
    "ZA": {"law": "POPIA",             "rating": "MODERATE", "icon": "🟡", "color": "#eab308"},
    "IL": {"law": "Privacy Protection Law", "rating": "MODERATE", "icon": "🟡", "color": "#eab308"},
    "AR": {"law": "PDPA",              "rating": "MODERATE", "icon": "🟡", "color": "#eab308"},
    "TH": {"law": "PDPA 2019",         "rating": "MODERATE", "icon": "🟡", "color": "#eab308"},
    # Weak / None
    "CN": {"law": "No independent oversight", "rating": "WEAK", "icon": "🔴", "color": "#ef4444"},
    "RU": {"law": "Government access laws",   "rating": "WEAK", "icon": "🔴", "color": "#ef4444"},
    "VN": {"law": "Cybersecurity Law (gov access)", "rating": "WEAK", "icon": "🔴", "color": "#ef4444"},
    "MM": {"law": "No privacy law",    "rating": "WEAK",     "icon": "🔴", "color": "#ef4444"},
    "BD": {"law": "No privacy law",    "rating": "WEAK",     "icon": "🔴", "color": "#ef4444"},
    "PK": {"law": "No federal law",    "rating": "WEAK",     "icon": "🔴", "color": "#ef4444"},
    "NG": {"law": "No comprehensive law", "rating": "WEAK",  "icon": "🔴", "color": "#ef4444"},
    "EG": {"law": "No privacy law",    "rating": "WEAK",     "icon": "🔴", "color": "#ef4444"},
}

# Country flag emoji map (ISO → flag)
COUNTRY_FLAGS: dict[str, str] = {
    "US":"🇺🇸","GB":"🇬🇧","DE":"🇩🇪","FR":"🇫🇷","CN":"🇨🇳","RU":"🇷🇺",
    "IN":"🇮🇳","JP":"🇯🇵","AU":"🇦🇺","CA":"🇨🇦","BR":"🇧🇷","NL":"🇳🇱",
    "IE":"🇮🇪","SE":"🇸🇪","CH":"🇨🇭","SG":"🇸🇬","KR":"🇰🇷","NZ":"🇳🇿",
    "AT":"🇦🇹","FI":"🇫🇮","DK":"🇩🇰","MX":"🇲🇽","ZA":"🇿🇦","IL":"🇮🇱",
    "VN":"🇻🇳","TH":"🇹🇭","PK":"🇵🇰","BD":"🇧🇩","NG":"🇳🇬","EG":"🇪🇬",
    "AR":"🇦🇷","MM":"🇲🇲",
}

# Risk upgrade for weak-privacy countries
# If a tracker's server is in a WEAK country, upgrade risk by one level
RISK_UPGRADE = {"LOW": "MEDIUM", "MEDIUM": "HIGH", "HIGH": "CRITICAL", "CRITICAL": "CRITICAL"}


@lru_cache(maxsize=512)
def geolocate_domain(domain: str) -> dict:
    """
    Resolve domain → IP → geolocation + privacy law info.
    Returns a dict with city, country, org, law info.
    Cached so same domain is never looked up twice.
    """
    result = {
        "ip"          : "",
        "city"        : "Unknown",
        "region"      : "",
        "country"     : "Unknown",
        "country_code": "",
        "org"         : "Unknown",
        "flag"        : "🌐",
        "law"         : "Unknown",
        "law_rating"  : "UNKNOWN",
        "law_icon"    : "⚪",
        "law_color"   : "#64748b",
        "risk_upgrade": False,
        "error"       : False,
    }
    try:
        # Step 1 — DNS resolve domain → IP
        ip = socket.gethostbyname(domain)
        result["ip"] = ip

        # Step 2 — IP → geolocation via free ip-api.com (no key needed)
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,city,regionName,country,countryCode,org",
            timeout=5
        )
        data = resp.json()

        if data.get("status") == "success":
            cc = data.get("countryCode", "")
            result.update({
                "city"        : data.get("city", "Unknown"),
                "region"      : data.get("regionName", ""),
                "country"     : data.get("country", "Unknown"),
                "country_code": cc,
                "org"         : data.get("org", "Unknown"),
                "flag"        : COUNTRY_FLAGS.get(cc, "🌐"),
            })
            # Step 3 — look up privacy law for this country
            law_info = PRIVACY_LAWS.get(cc)
            if law_info:
                result.update({
                    "law"        : law_info["law"],
                    "law_rating" : law_info["rating"],
                    "law_icon"   : law_info["icon"],
                    "law_color"  : law_info["color"],
                    "risk_upgrade": law_info["rating"] == "WEAK",
                })
            else:
                result.update({
                    "law"       : "No known privacy law",
                    "law_rating": "WEAK",
                    "law_icon"  : "🔴",
                    "law_color" : "#ef4444",
                    "risk_upgrade": True,
                })

    except socket.gaierror:
        result["error"] = True   # DNS failed — domain may be down
    except Exception:
        result["error"] = True

    return result


def print_geo_info(domain: str, original_risk: str) -> tuple[dict, str]:
    """
    Print server location block and return (geo_data, effective_risk).
    effective_risk may be upgraded if server is in weak-privacy country.
    """
    geo = geolocate_domain(domain)

    if geo["error"] or not geo["ip"]:
        print("  🌐  Server Location :  Could not resolve (DNS failed)")
        return geo, original_risk

    location_str = geo["city"]
    if geo["region"]:
        location_str += f", {geo['region']}"
    location_str += f", {geo['country']}  {geo['flag']}"

    effective_risk = original_risk
    upgrade_note   = ""
    if geo["risk_upgrade"] and original_risk != "CRITICAL":
        effective_risk = RISK_UPGRADE[original_risk]
        upgrade_note = (
            f"\n  ⚠️   RISK UPGRADED  :  {original_risk} → {effective_risk}"
            f"  (server in {geo['country']} — weak privacy laws)"
        )

    print(f"\n  🌐  Server Location:")
    print(f"       📌 Location    :  {location_str}")
    print(f"       🏢 Organisation:  {geo['org']}")
    print(f"       ⚖️  Privacy Law  :  {geo['law']}  {geo['law_icon']} {geo['law_rating'].title()}")
    if upgrade_note:
        print(upgrade_note)

    return geo, effective_risk


# ─────────────────────────────────────────────
# RISK DISPLAY CONFIG
# ─────────────────────────────────────────────
RISK_DISPLAY: dict[str, dict] = {
    "LOW"      : {"icon": "🟢", "label": "LOW RISK"},
    "MEDIUM"   : {"icon": "🟡", "label": "MEDIUM RISK"},
    "HIGH"     : {"icon": "🔴", "label": "HIGH RISK"},
    "CRITICAL" : {"icon": "🚨", "label": "CRITICAL RISK"},
}

# ─────────────────────────────────────────────
# BROWSER-SPECIFIC SUGGESTIONS
# ─────────────────────────────────────────────
BROWSER_SUGGESTIONS: dict[str, list[str]] = {
    "chrome": [
        "Install uBlock Origin         → https://chrome.google.com/webstore/detail/ublock-origin/cjpalhdlnbpafiamejdnhcphjbkeiagm",
        "Install Privacy Badger        → https://chrome.google.com/webstore/detail/privacy-badger/pkehgijcmpdhfbdbbnkijodmdjhbjlgp",
        "Disable third-party cookies   → Settings → Privacy → Block third-party cookies",
        "Enable Safe Browsing (strict) → Settings → Privacy → Security → Enhanced Protection",
    ],
    "firefox": [
        "Enable Strict Tracking Protection → Preferences → Privacy → Strict",
        "Install uBlock Origin             → https://addons.mozilla.org/en-US/firefox/addon/ublock-origin/",
        "Install Facebook Container        → https://addons.mozilla.org/en-US/firefox/addon/facebook-container/",
        "Enable DNS-over-HTTPS             → Preferences → Network Settings → Enable DNS over HTTPS",
    ],
    "edge": [
        "Enable Strict Tracking Prevention → Settings → Privacy → Strict",
        "Install uBlock Origin             → https://microsoftedge.microsoft.com/addons/detail/ublock-origin/odfafepnkmbhccpbejgmiehpchacaeak",
        "Disable personalized ads          → Settings → Privacy → Personalization",
    ],
    "default": [
        "Install uBlock Origin  → https://ublockorigin.com  (works on Chrome, Firefox, Edge)",
        "Set up Pi-hole         → https://pi-hole.net       (blocks trackers on ALL devices on your network)",
        "Use a VPN              → ProtonVPN free tier        → https://protonvpn.com",
        "Switch to Firefox      → Best built-in privacy protections of any major browser",
    ],
}

# ─────────────────────────────────────────────
# SESSION STATS — tracked across all domains
# ─────────────────────────────────────────────
class SessionStats:
    def __init__(self):
        self.start_time       = datetime.now()
        self.total_domains    = 0
        self.tracker_hits     = Counter()   # domain → count
        self.risk_counts      = Counter()   # LOW/MEDIUM/HIGH/CRITICAL → count
        self.vpn_triggers     = 0
        # Full tracker log — each entry is a dict with all details
        # used to generate the HTML report
        self.tracker_log: list[dict] = []

    def record(self, domain: str, risk: str, vpn_needed: bool,
               tracker_name: str = "", site_name: str = "",
               data_points: list = None, block_tip: str = "",
               delete_url: str = "", geo: dict = None):
        self.tracker_hits[domain] += 1
        self.risk_counts[risk]    += 1
        if vpn_needed:
            self.vpn_triggers += 1
        # Store full details for HTML report (only first occurrence per domain)
        if self.tracker_hits[domain] == 1:
            self.tracker_log.append({
                "domain"      : domain,
                "tracker_name": tracker_name,
                "site_name"   : site_name,
                "risk"        : risk,
                "vpn_needed"  : vpn_needed,
                "data_points" : data_points or [],
                "block_tip"   : block_tip,
                "delete_url"  : delete_url,
                "time"        : datetime.now().strftime("%I:%M:%S %p"),
                "geo"         : geo or {},
            })

    def print_summary(self):
        duration = datetime.now() - self.start_time
        minutes  = int(duration.total_seconds() // 60)
        seconds  = int(duration.total_seconds() % 60)

        total_trackers = len(self.tracker_hits)
        critical = self.risk_counts.get("CRITICAL", 0)
        high     = self.risk_counts.get("HIGH",     0)
        medium   = self.risk_counts.get("MEDIUM",   0)
        low      = self.risk_counts.get("LOW",      0)

        print("\n\n" + "═" * 56)
        print("         📊  YOUR SESSION REPORT")
        print("═" * 56)
        print(f"  ⏱  You were monitored for  :  {minutes} min {seconds} sec")
        print(f"  🌐  Total websites contacted:  {self.total_domains}")
        print(f"  🕵  Hidden trackers found   :  {total_trackers}")
        print()

        if total_trackers == 0:
            print("  ✅  Great news! No trackers were detected this session.")
        else:
            print("  Here is what was tracking you:")
            print()
            if critical: print(f"    🚨  {critical}  CRITICAL tracker(s)  —  very serious")
            if high    : print(f"    🔴  {high}  HIGH risk tracker(s) —  follows you across sites")
            if medium  : print(f"    🟡  {medium}  MEDIUM risk tracker(s)—  watches how you use sites")
            if low     : print(f"    🟢  {low}  LOW risk tracker(s)  —  mostly harmless")

            if self.tracker_hits:
                top_domain, top_count = self.tracker_hits.most_common(1)[0]
                top_name  = friendly_website_name(top_domain)
                print()
                print(f"  🔁  Most active tracker  :  {top_name}")
                print(f"      Hidden domain         :  {top_domain}")
                print(f"      It contacted your device  {top_count}  time(s) this session.")

        print()
        print("─" * 56)
        print("  🛠   WHAT YOU SHOULD DO NOW")
        print("─" * 56)

        if critical > 0:
            print()
            print("  Your privacy is seriously at risk.")
            print("  Take these steps today:\n")
            print("  1️⃣   Install uBlock Origin in your browser (it's free)")
            print("       https://ublockorigin.com")
            print()
            print("  2️⃣   Use Firefox instead of Chrome for better privacy")
            print("       https://www.mozilla.org/firefox")
            print()
            print("  3️⃣   Install 'Facebook Container' in Firefox")
            print("       This stops Facebook seeing what you do on other sites")
            print("       https://addons.mozilla.org/en-US/firefox/addon/facebook-container/")
            print()
            print("  4️⃣   Use a VPN to hide your real IP address")
            print("       ProtonVPN is free  →  https://protonvpn.com")

        elif high > 0:
            print()
            print("  You have some serious trackers following you.")
            print("  Do this to protect yourself:\n")
            print("  1️⃣   Install uBlock Origin  →  https://ublockorigin.com")
            print("       Open it → Dashboard → Filter Lists → tick 'EasyPrivacy'")
            print()
            print("  2️⃣   Consider a VPN to hide your location")
            print("       ProtonVPN free  →  https://protonvpn.com")

        elif medium > 0:
            print()
            print("  Some trackers are watching your activity.")
            print("  A simple fix:\n")
            print("  1️⃣   Install uBlock Origin  →  https://ublockorigin.com")
            print("       This blocks most trackers automatically.")

        else:
            print()
            print("  ✅  You're in good shape! Only low-risk activity detected.")

        if self.vpn_triggers >= 3:
            print()
            print("  🔒  Multiple trackers recorded your IP address this session.")
            print("      A VPN hides your real location from all of them.")
            print("      ProtonVPN (free)  →  https://protonvpn.com")

        print()
        print("─" * 56)
        print("  🏠  PROTECT ALL YOUR HOME DEVICES AT ONCE")
        print("─" * 56)
        print()
        print("  Pi-hole blocks trackers on every device on your Wi-Fi")
        print("  — your phone, laptop, smart TV, everything.")
        print("  It's free and runs on a Raspberry Pi or old laptop.")
        print("  Setup guide  →  https://docs.pi-hole.net/main/basic-install/")
        print()
        print("═" * 56)

        # Generate and save HTML report
        report_path = generate_html_report(self)
        if report_path:
            print(f"\n  📄  HTML report saved  →  {report_path}")


# Global session stats instance
stats = SessionStats()


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def match_keys(domain: str, db: dict) -> list[tuple[str, any]]:
    """Return every (keyword, value) pair whose keyword appears in domain."""
    return [(k, v) for k, v in db.items() if k in domain]


def detect_browser() -> str:
    """
    Attempt to detect the default browser on Windows.
    Returns 'chrome', 'firefox', 'edge', or 'default'.
    """
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice"
        )
        prog_id = winreg.QueryValueEx(key, "ProgId")[0].lower()
        if "chrome"  in prog_id: return "chrome"
        if "firefox" in prog_id: return "firefox"
        if "edge"    in prog_id: return "edge"
    except Exception:
        pass
    return "default"


@lru_cache(maxsize=256)
def ai_analysis(domain: str) -> str:
    """Query local Phi-3 for privacy analysis. Cached per domain."""
    prompt = (
        f"Tracker detected: {domain}\n"
        "Explain briefly:\n"
        "1. Company owning the tracker\n"
        "2. Data collected\n"
        "3. Privacy risk (Low / Medium / High)\n"
        "4. How the user can block it\n"
        "Keep the answer short for terminal output."
    )
    try:
        log.info("Querying local Phi-3 model…")
        resp = requests.post(
            OLLAMA_URL,
            json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            timeout=OLLAMA_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json().get("response", "No response from model.")
    except requests.exceptions.Timeout:
        return "AI analysis timed out."
    except requests.exceptions.ConnectionError:
        return "AI analysis unavailable — Ollama not reachable."
    except Exception as exc:
        return f"AI analysis error: {exc}"


def clean_ai_response(text: str) -> str:
    """
    Strip code fences, backticks, shell commands, and blank lines
    from the AI response so only plain human-readable sentences remain.
    """
    import re
    # remove code blocks  ```...```
    text = re.sub(r"```[\s\S]*?```", "", text)
    # remove leftover backticks
    text = re.sub(r"`[^`]*`", "", text)
    # remove lines that look like shell commands or code
    clean_lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # skip lines starting with $, #, sudo, echo, curl, iptables, etc.
        if re.match(r"^(\$|#|sudo|echo|curl|grep|iptables|chromium|lynx|traceroute|about:|document\.|var |if |end )", stripped):
            continue
        # skip lines that are just closing braces / syntax noise
        if stripped in ("{", "}", "};", "});", "//", "/*", "*/"):
            continue
        clean_lines.append(stripped)
    return "\n".join(clean_lines).strip()


def box(title: str, width: int = 54) -> str:
    """Return a simple titled box top."""
    pad = width - len(title) - 4
    return f"  ┌── {title} {'─' * pad}┐"


def print_action_suggestions(tracker_info: dict, browser: str):
    """Print clean, beginner-friendly action suggestions."""
    risk        = tracker_info["risk"]
    risk_cfg    = RISK_DISPLAY[risk]
    suggestions = BROWSER_SUGGESTIONS.get(browser, BROWSER_SUGGESTIONS["default"])

    # ── Plain-English explanation of risk ───
    risk_explain = {
        "LOW"     : "This tracker is mostly harmless. It collects basic error info to help developers fix bugs.",
        "MEDIUM"  : "This tracker watches how you use websites — which pages you visit and how long you stay.",
        "HIGH"    : "This tracker follows you across multiple websites and builds a profile about your interests.",
        "CRITICAL": "This tracker knows almost everything — what you buy, where you go, who you talk to, even when you're NOT on their app.",
    }
    print(f"  ℹ  What this means : {risk_explain[risk]}")

    # ── Data collected ───────────────────────
    print("\n  📋  What they are collecting about you right now:")
    for point in tracker_info["data"]:
        print(f"       •  {point}")

    # ── Fix it — simple steps ────────────────
    print("\n  ✅  How to stop this tracker (easy fix):")
    print(f"       {tracker_info['block']}")

    # ── Delete existing data ─────────────────
    if tracker_info.get("delete_url"):
        print("\n  🗑   Delete data they already have:")
        print(f"       {tracker_info['delete_url']}")

    # ── VPN recommendation ───────────────────
    if tracker_info.get("vpn_needed"):
        print("\n  🔒  Your IP address is exposed to this tracker.")
        print("      A VPN hides your real location. Free options:")
        print("       → ProtonVPN  :  https://protonvpn.com  (free, no logs)")
        print("       → Mullvad    :  https://mullvad.net")

    # ── Browser steps ────────────────────────
    print(f"\n  🌐  Steps for your browser ({browser.title()}):")
    for step in suggestions[:2]:
        print(f"       → {step}")

    # ── Network-level for serious threats ────
    if risk in ("HIGH", "CRITICAL"):
        print("\n  🛡   Want to block this on ALL devices (phone, laptop, TV)?")
        print("      Set up Pi-hole — it blocks trackers at your Wi-Fi router level.")
        print("      Free guide : https://docs.pi-hole.net/main/basic-install/")


def handle_domain(domain: str, browser: str) -> None:
    """Process one domain — print clean beginner-friendly output."""
    stats.total_domains += 1

    service_hits = match_keys(domain, SERVICES)
    tracker_hits = match_keys(domain, TRACKERS)

    # ── Clean domain — just one quiet line ───
    if not tracker_hits:
        if service_hits:
            site_name = friendly_website_name(domain)
            label     = service_hits[0][1]
            print(f"  ✔  {site_name}  ({label})")
        return

    # ── Tracker found — print full card ──────
    site_name = friendly_website_name(domain)
    print(f"\n{'━' * 56}")

    for _, tracker_info in tracker_hits:
        risk_cfg = RISK_DISPLAY[tracker_info["risk"]]

        print(f"\n  {risk_cfg['icon']}  TRACKER DETECTED ON YOUR DEVICE")
        print(f"  {'─' * 52}")
        # ✅ Show friendly site name + raw domain for reference
        print(f"  🌍  Loaded by     :  {site_name}")
        print(f"  📍  Hidden domain :  {domain}")
        print(f"  🏢  Tracker Name  :  {tracker_info['name']}")
        print(f"  ⚡  Danger Level  :  {risk_cfg['label']}")

        # ── Geolocation — resolve server location + privacy law ──
        geo_data, effective_risk = print_geo_info(domain, tracker_info["risk"])

        # If risk was upgraded due to weak-privacy country, update display
        if effective_risk != tracker_info["risk"]:
            upgraded_cfg = RISK_DISPLAY[effective_risk]
            print(f"  ⚡  Upgraded Level :  {upgraded_cfg['label']}")

        # record in session stats (with full details for HTML report)
        stats.record(
            domain,
            effective_risk,
            tracker_info.get("vpn_needed", False),
            tracker_name = tracker_info["name"],
            site_name    = site_name,
            data_points  = tracker_info.get("data", []),
            block_tip    = tracker_info.get("block", ""),
            delete_url   = tracker_info.get("delete_url", "") or "",
            geo          = geo_data,
        )

        # action suggestions (no longer prints duplicate danger level)
        print_action_suggestions(tracker_info, browser)

        # AI analysis — suppress INFO log, show clean output only
        print("\n  🤖  AI says:")
        log.disabled = True          # ← hide the [INFO] line during AI call
        raw = ai_analysis(domain)
        log.disabled = False         # ← re-enable after
        cleaned = clean_ai_response(raw)
        if cleaned:
            for line in cleaned.splitlines():
                print(f"       {line}")
        else:
            print("       AI analysis unavailable right now.")

    print(f"\n{'━' * 56}")


def build_tshark_cmd() -> list[str]:
    return [
        TSHARK_PATH,
        "-i", NETWORK_IFACE,
        "-l",
        "-Y", "dns",
        "-T", "fields",
        "-e", "dns.qry.name",
    ]


def print_startup_banner(browser: str):
    safe_print("\n" + "═" * 56)
    safe_print("       🔍  AI Privacy Monitor  —  Now Watching")
    safe_print("═" * 56)
    safe_print(f"  Your browser  :  {browser.title()}")
    safe_print(f"  Started at    :  {datetime.now().strftime('%I:%M %p')}")
    safe_print()
    safe_print("  This tool watches every website your device contacts")
    safe_print("  in the background — including hidden trackers that")
    safe_print("  you never opened or agreed to.")
    safe_print()
    safe_print("  Press Ctrl+C at any time to stop and see a summary.")
    safe_print("═" * 56 + "\n")

    if browser in ("chrome", "firefox", "edge"):
        safe_print("  ⚠  IMPORTANT — One setting to check first:")
        safe_print("     Your browser may be hiding some tracker activity.")
        safe_print("     To make sure this tool sees everything, turn off")
        safe_print("     'Secure DNS' in your browser:")
        if browser == "chrome":
            safe_print("     Chrome  →  Settings → Privacy & Security")
            safe_print("                → Security → Use Secure DNS → Turn OFF")
        elif browser == "firefox":
            safe_print("     Firefox →  Settings → General → Network Settings")
            safe_print("                → Uncheck  'Enable DNS over HTTPS'")
        elif browser == "edge":
            safe_print("     Edge    →  Settings → Privacy, Search & Services")
            safe_print("                → Security → Use Secure DNS → Turn OFF")
        safe_print()
    safe_print("  Watching your traffic now...\n")


# ─────────────────────────────────────────────
# HTML REPORT GENERATOR
# ─────────────────────────────────────────────

def generate_html_report(s: "SessionStats") -> str:
    """
    Build a self-contained HTML privacy report and save it
    in the same folder as this script.
    Returns the file path, or empty string on failure.
    """
    duration  = datetime.now() - s.start_time
    mins      = int(duration.total_seconds() // 60)
    secs      = int(duration.total_seconds() % 60)
    date_str  = s.start_time.strftime("%d %B %Y")
    time_str  = s.start_time.strftime("%I:%M %p")

    critical  = s.risk_counts.get("CRITICAL", 0)
    high      = s.risk_counts.get("HIGH",     0)
    medium    = s.risk_counts.get("MEDIUM",   0)
    low       = s.risk_counts.get("LOW",      0)
    total     = len(s.tracker_log)

    # ── Privacy score (0–10, lower = worse) ─────────────────────
    score = max(0, 10 - (critical * 3 + high * 2 + medium * 1))
    score_label = (
        "Excellent" if score >= 9 else
        "Good"      if score >= 7 else
        "Fair"      if score >= 5 else
        "Poor"      if score >= 3 else
        "Critical"
    )
    score_color = (
        "#22c55e" if score >= 7 else
        "#f59e0b" if score >= 4 else
        "#ef4444"
    )

    # ── Tracker cards HTML ───────────────────────────────────────
    risk_colors = {
        "CRITICAL": {"bg": "#2d1515", "border": "#ef4444", "badge": "#ef4444", "text": "#fca5a5"},
        "HIGH"    : {"bg": "#2d1f0f", "border": "#f97316", "badge": "#f97316", "text": "#fdba74"},
        "MEDIUM"  : {"bg": "#2d2a0f", "border": "#eab308", "badge": "#eab308", "text": "#fde047"},
        "LOW"     : {"bg": "#0f2d1a", "border": "#22c55e", "badge": "#22c55e", "text": "#86efac"},
    }
    risk_icons = {"CRITICAL": "🚨", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}

    # ── Build country summary for HTML ─────────────────────────
    country_counter = Counter()
    for entry in s.tracker_log:
        geo = entry.get("geo", {})
        cc  = geo.get("country_code", "")
        if cc:
            country_counter[cc] += 1

    country_rows = ""
    for cc, cnt in country_counter.most_common():
        geo_info  = next((e.get("geo",{}) for e in s.tracker_log if e.get("geo",{}).get("country_code")==cc), {})
        flag      = COUNTRY_FLAGS.get(cc, "🌐")
        country   = geo_info.get("country", cc)
        law_info  = PRIVACY_LAWS.get(cc, {})
        law       = law_info.get("law", "Unknown")
        law_icon  = law_info.get("icon", "⚪")
        law_color = law_info.get("color", "#64748b")
        country_rows += f"""
        <tr>
          <td>{flag} {country}</td>
          <td style="font-family:'JetBrains Mono',monospace;font-weight:700">{cnt}</td>
          <td>{law}</td>
          <td style="color:{law_color};font-weight:600">{law_icon} {law_info.get("rating","UNKNOWN").title()}</td>
        </tr>"""

    country_table = f"""
    <div class="section">
      <div class="section-title">Tracker Server Locations</div>
      <table class="geo-table">
        <thead>
          <tr><th>Country</th><th>Trackers</th><th>Privacy Law</th><th>Protection</th></tr>
        </thead>
        <tbody>{country_rows if country_rows else "<tr><td colspan=4 style=color:var(--muted)>No geolocation data</td></tr>"}</tbody>
      </table>
    </div>""" if country_rows else ""

    tracker_cards = ""
    for entry in s.tracker_log:
        r      = entry["risk"]
        rc     = risk_colors.get(r, risk_colors["LOW"])
        icon   = risk_icons.get(r, "⚪")
        points = "".join(f"<li>{p}</li>" for p in entry["data_points"])
        del_btn = (
            f'<a href="{entry["delete_url"]}" target="_blank" class="action-btn delete-btn">'
            f'🗑 Delete Your Data</a>'
        ) if entry["delete_url"] else ""

        # geo block for this tracker card
        geo = entry.get("geo", {})
        if geo and not geo.get("error") and geo.get("city"):
            loc_str  = f"{geo.get('city','')} {geo.get('flag','🌐')}"
            law_col  = geo.get("law_color", "#64748b")
            geo_html = f"""
          <div class="card-geo">
            <div class="geo-item">
              <span class="meta-label">📌 Server Location</span>
              <span class="meta-value">{loc_str}, {geo.get("country","")}</span>
            </div>
            <div class="geo-item">
              <span class="meta-label">🏢 Organisation</span>
              <span class="meta-value" style="font-size:0.8rem">{geo.get("org","Unknown")}</span>
            </div>
            <div class="geo-item">
              <span class="meta-label">⚖️ Privacy Law</span>
              <span class="meta-value" style="color:{law_col}">{geo.get("law_icon","⚪")} {geo.get("law","Unknown")} — {geo.get("law_rating","").title()}</span>
            </div>
          </div>"""
        else:
            geo_html = ""

        tracker_cards += f"""
        <div class="tracker-card" style="border-left:4px solid {rc["border"]};background:{rc["bg"]}">
          <div class="card-header">
            <div>
              <span class="risk-badge" style="background:{rc["badge"]}">{icon} {r} RISK</span>
              <h3 class="tracker-name">{entry["tracker_name"]}</h3>
            </div>
            <span class="card-time">{entry["time"]}</span>
          </div>
          <div class="card-meta">
            <div class="meta-item">
              <span class="meta-label">🌍 Loaded by</span>
              <span class="meta-value">{entry["site_name"]}</span>
            </div>
            <div class="meta-item">
              <span class="meta-label">📍 Hidden domain</span>
              <span class="meta-value domain-tag">{entry["domain"]}</span>
            </div>
          </div>
          {geo_html}
          <div class="card-body">
            <div class="data-section">
              <p class="section-label">📋 What they collected:</p>
              <ul class="data-list" style="color:{rc["text"]}">{points}</ul>
            </div>
            <div class="action-section">
              <p class="section-label">✅ How to stop it:</p>
              <p class="block-tip">{entry["block_tip"]}</p>
              <div class="btn-row">{del_btn}</div>
            </div>
          </div>
        </div>"""

    # ── Pie chart data ────────────────────────────────────────────
    chart_data = json.dumps([critical, high, medium, low])

    # ── Recommendations ───────────────────────────────────────────
    if critical > 0:
        rec_html = """
          <div class="rec-item rec-critical">
            <span class="rec-num">1</span>
            <div><strong>Install uBlock Origin immediately</strong><br>
            <a href="https://ublockorigin.com" target="_blank">https://ublockorigin.com</a></div>
          </div>
          <div class="rec-item rec-critical">
            <span class="rec-num">2</span>
            <div><strong>Switch to Firefox for better privacy</strong><br>
            <a href="https://mozilla.org/firefox" target="_blank">https://mozilla.org/firefox</a></div>
          </div>
          <div class="rec-item rec-critical">
            <span class="rec-num">3</span>
            <div><strong>Install Facebook Container (Firefox)</strong><br>
            Stops Facebook tracking you on other sites</div>
          </div>
          <div class="rec-item rec-critical">
            <span class="rec-num">4</span>
            <div><strong>Use a VPN to hide your IP address</strong><br>
            <a href="https://protonvpn.com" target="_blank">ProtonVPN — free tier available</a></div>
          </div>"""
    elif high > 0:
        rec_html = """
          <div class="rec-item rec-high">
            <span class="rec-num">1</span>
            <div><strong>Install uBlock Origin</strong><br>
            <a href="https://ublockorigin.com" target="_blank">https://ublockorigin.com</a></div>
          </div>
          <div class="rec-item rec-high">
            <span class="rec-num">2</span>
            <div><strong>Enable EasyPrivacy list in uBlock</strong><br>
            Open uBlock → Dashboard → Filter Lists → tick EasyPrivacy</div>
          </div>
          <div class="rec-item rec-high">
            <span class="rec-num">3</span>
            <div><strong>Consider a VPN</strong><br>
            <a href="https://protonvpn.com" target="_blank">ProtonVPN — free</a></div>
          </div>"""
    else:
        rec_html = """
          <div class="rec-item rec-low">
            <span class="rec-num">1</span>
            <div><strong>Install uBlock Origin for basic protection</strong><br>
            <a href="https://ublockorigin.com" target="_blank">https://ublockorigin.com</a></div>
          </div>"""

    # ── Full HTML ─────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Privacy Report — {date_str}</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@400;600;800&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  :root {{
    --bg:        #0a0d12;
    --surface:   #111520;
    --surface2:  #181d2a;
    --border:    #1e2535;
    --text:      #e2e8f0;
    --muted:     #64748b;
    --accent:    #38bdf8;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: 'Syne', sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    padding: 0 0 60px;
  }}

  /* ── Header ── */
  .header {{
    background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%);
    border-bottom: 1px solid #2d3560;
    padding: 48px 40px 40px;
    position: relative;
    overflow: hidden;
  }}
  .header::before {{
    content: '';
    position: absolute;
    top: -60px; right: -60px;
    width: 300px; height: 300px;
    background: radial-gradient(circle, rgba(56,189,248,0.08) 0%, transparent 70%);
    pointer-events: none;
  }}
  .header-top {{
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 24px;
    flex-wrap: wrap;
  }}
  .header h1 {{
    font-size: 2rem;
    font-weight: 800;
    letter-spacing: -0.5px;
    color: #f1f5f9;
  }}
  .header h1 span {{ color: var(--accent); }}
  .header-meta {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.78rem;
    color: var(--muted);
    margin-top: 6px;
    line-height: 1.8;
  }}
  .score-badge {{
    text-align: center;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 20px 32px;
    min-width: 160px;
  }}
  .score-num {{
    font-size: 3rem;
    font-weight: 800;
    line-height: 1;
    font-family: 'JetBrains Mono', monospace;
  }}
  .score-label {{
    font-size: 0.75rem;
    color: var(--muted);
    margin-top: 4px;
    text-transform: uppercase;
    letter-spacing: 1px;
  }}

  /* ── Layout ── */
  .container {{ max-width: 1100px; margin: 0 auto; padding: 0 24px; }}
  .section {{ margin-top: 40px; }}
  .section-title {{
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 2px;
    color: var(--muted);
    margin-bottom: 16px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
  }}

  /* ── Stat Cards ── */
  .stats-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 14px;
    margin-top: 24px;
  }}
  .stat-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
    transition: transform 0.2s;
  }}
  .stat-card:hover {{ transform: translateY(-2px); }}
  .stat-card .num {{
    font-size: 2.4rem;
    font-weight: 800;
    font-family: 'JetBrains Mono', monospace;
    line-height: 1;
  }}
  .stat-card .lbl {{
    font-size: 0.75rem;
    color: var(--muted);
    margin-top: 6px;
    text-transform: uppercase;
    letter-spacing: 1px;
  }}
  .stat-critical {{ border-top: 3px solid #ef4444; }}
  .stat-high     {{ border-top: 3px solid #f97316; }}
  .stat-medium   {{ border-top: 3px solid #eab308; }}
  .stat-low      {{ border-top: 3px solid #22c55e; }}
  .stat-total    {{ border-top: 3px solid var(--accent); }}

  /* ── Chart ── */
  .chart-row {{
    display: grid;
    grid-template-columns: 260px 1fr;
    gap: 24px;
    align-items: center;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 28px;
    margin-top: 16px;
  }}
  @media (max-width: 600px) {{
    .chart-row {{ grid-template-columns: 1fr; }}
  }}
  .chart-legend {{ display: flex; flex-direction: column; gap: 12px; }}
  .legend-item {{ display: flex; align-items: center; gap: 10px; font-size: 0.9rem; }}
  .legend-dot {{ width: 12px; height: 12px; border-radius: 50%; flex-shrink: 0; }}
  .legend-count {{
    margin-left: auto;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.85rem;
    color: var(--muted);
  }}

  /* ── Tracker Cards ── */
  .tracker-card {{
    border-radius: 14px;
    padding: 22px 24px;
    margin-bottom: 14px;
    transition: transform 0.15s;
  }}
  .tracker-card:hover {{ transform: translateX(4px); }}
  .card-header {{
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 14px;
    flex-wrap: wrap;
    gap: 8px;
  }}
  .risk-badge {{
    display: inline-block;
    font-size: 0.65rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    padding: 3px 10px;
    border-radius: 20px;
    color: #0a0d12;
    margin-bottom: 6px;
  }}
  .tracker-name {{
    font-size: 1.05rem;
    font-weight: 700;
    color: #f1f5f9;
  }}
  .card-time {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    color: var(--muted);
    white-space: nowrap;
  }}
  .card-meta {{
    display: flex;
    gap: 24px;
    flex-wrap: wrap;
    margin-bottom: 16px;
    padding-bottom: 16px;
    border-bottom: 1px solid rgba(255,255,255,0.06);
  }}
  .meta-label {{
    font-size: 0.7rem;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 1px;
    display: block;
    margin-bottom: 3px;
  }}
  .meta-value {{ font-size: 0.88rem; font-weight: 600; }}
  .domain-tag {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem !important;
    color: var(--accent) !important;
  }}
  .card-body {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
  }}
  @media (max-width: 600px) {{ .card-body {{ grid-template-columns: 1fr; }} }}
  .section-label {{
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--muted);
    margin-bottom: 8px;
  }}
  .data-list {{
    list-style: none;
    font-size: 0.85rem;
    line-height: 1.8;
  }}
  .data-list li::before {{ content: '• '; opacity: 0.6; }}
  .block-tip {{
    font-size: 0.85rem;
    line-height: 1.6;
    color: #cbd5e1;
  }}
  .btn-row {{ margin-top: 12px; display: flex; gap: 10px; flex-wrap: wrap; }}
  .action-btn {{
    display: inline-block;
    font-size: 0.75rem;
    font-weight: 600;
    padding: 6px 14px;
    border-radius: 8px;
    text-decoration: none;
    transition: opacity 0.2s;
  }}
  .action-btn:hover {{ opacity: 0.8; }}
  .delete-btn {{ background: #1e293b; color: #94a3b8; border: 1px solid #334155; }}

  /* ── Recommendations ── */
  .rec-grid {{ display: flex; flex-direction: column; gap: 12px; margin-top: 16px; }}
  .rec-item {{
    display: flex;
    align-items: flex-start;
    gap: 16px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 18px 20px;
    font-size: 0.9rem;
    line-height: 1.6;
  }}
  .rec-item a {{ color: var(--accent); }}
  .rec-num {{
    flex-shrink: 0;
    width: 28px; height: 28px;
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 0.75rem;
    font-weight: 800;
    font-family: 'JetBrains Mono', monospace;
    background: var(--surface2);
  }}
  .rec-critical .rec-num {{ background: #450a0a; color: #ef4444; }}
  .rec-high .rec-num     {{ background: #431407; color: #f97316; }}
  .rec-low .rec-num      {{ background: #052e16; color: #22c55e; }}

  /* ── Footer ── */
  .footer {{
    margin-top: 60px;
    padding: 24px 40px;
    border-top: 1px solid var(--border);
    font-size: 0.75rem;
    color: var(--muted);
    font-family: 'JetBrains Mono', monospace;
    text-align: center;
  }}

  /* ── Animations ── */
  @keyframes fadeUp {{
    from {{ opacity: 0; transform: translateY(16px); }}
    to   {{ opacity: 1; transform: translateY(0); }}
  }}
  .stat-card, .tracker-card, .rec-item {{
    animation: fadeUp 0.4s ease both;
  }}
</style>
</head>
<body>

<!-- HEADER -->
<div class="header">
  <div class="container">
    <div class="header-top">
      <div>
        <h1>🔍 Privacy <span>Report</span></h1>
        <div class="header-meta">
          📅 {date_str} &nbsp;·&nbsp; 🕐 Started {time_str} &nbsp;·&nbsp;
          ⏱ Duration {mins}m {secs}s &nbsp;·&nbsp;
          🌐 {s.total_domains} domains contacted
        </div>
      </div>
      <div class="score-badge">
        <div class="score-num" style="color:{score_color}">{score}/10</div>
        <div class="score-label">Privacy Score</div>
        <div style="font-size:0.7rem;margin-top:4px;color:{score_color}">{score_label}</div>
      </div>
    </div>
  </div>
</div>

<div class="container">

  <!-- STATS -->
  <div class="section">
    <div class="section-title">Session Overview</div>
    <div class="stats-grid">
      <div class="stat-card stat-total">
        <div class="num" style="color:var(--accent)">{total}</div>
        <div class="lbl">Trackers Found</div>
      </div>
      <div class="stat-card stat-critical">
        <div class="num" style="color:#ef4444">{critical}</div>
        <div class="lbl">Critical Risk</div>
      </div>
      <div class="stat-card stat-high">
        <div class="num" style="color:#f97316">{high}</div>
        <div class="lbl">High Risk</div>
      </div>
      <div class="stat-card stat-medium">
        <div class="num" style="color:#eab308">{medium}</div>
        <div class="lbl">Medium Risk</div>
      </div>
      <div class="stat-card stat-low">
        <div class="num" style="color:#22c55e">{low}</div>
        <div class="lbl">Low Risk</div>
      </div>
    </div>
  </div>

  <!-- CHART -->
  <div class="section">
    <div class="section-title">Risk Breakdown</div>
    <div class="chart-row">
      <canvas id="pieChart" width="220" height="220"></canvas>
      <div class="chart-legend">
        <div class="legend-item">
          <div class="legend-dot" style="background:#ef4444"></div>
          <span>Critical Risk</span>
          <span class="legend-count">{critical} tracker(s)</span>
        </div>
        <div class="legend-item">
          <div class="legend-dot" style="background:#f97316"></div>
          <span>High Risk</span>
          <span class="legend-count">{high} tracker(s)</span>
        </div>
        <div class="legend-item">
          <div class="legend-dot" style="background:#eab308"></div>
          <span>Medium Risk</span>
          <span class="legend-count">{medium} tracker(s)</span>
        </div>
        <div class="legend-item">
          <div class="legend-dot" style="background:#22c55e"></div>
          <span>Low Risk</span>
          <span class="legend-count">{low} tracker(s)</span>
        </div>
      </div>
    </div>
  </div>

  {country_table}

  <!-- TRACKER CARDS -->
  <div class="section">
    <div class="section-title">Trackers Detected ({total})</div>
    {tracker_cards if tracker_cards else '<p style="color:var(--muted);padding:20px 0">✅ No trackers detected this session.</p>'}
  </div>

  <!-- RECOMMENDATIONS -->
  <div class="section">
    <div class="section-title">What You Should Do</div>
    <div class="rec-grid">{rec_html}</div>
    <div class="rec-item" style="margin-top:12px;border-color:#1e2535">
      <span class="rec-num" style="background:#0c1a2e;color:var(--accent)">🛡</span>
      <div><strong>Block trackers on ALL your devices at once</strong><br>
      Set up Pi-hole on your Wi-Fi router — free, blocks everything network-wide.<br>
      <a href="https://docs.pi-hole.net/main/basic-install/" target="_blank">
      https://docs.pi-hole.net/main/basic-install/</a></div>
    </div>
  </div>

</div>

<!-- FOOTER -->
<div class="footer">
  Generated by AI Privacy Monitor &nbsp;·&nbsp;
  {date_str} {time_str} &nbsp;·&nbsp;
  This report is private and stored only on your device.
</div>

<script>
const data = {chart_data};
const ctx  = document.getElementById('pieChart').getContext('2d');
new Chart(ctx, {{
  type: 'doughnut',
  data: {{
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [{{
      data: data,
      backgroundColor: ['#ef4444','#f97316','#eab308','#22c55e'],
      borderColor: '#0a0d12',
      borderWidth: 3,
      hoverOffset: 8,
    }}]
  }},
  options: {{
    responsive: false,
    plugins: {{
      legend: {{ display: false }},
      tooltip: {{
        callbacks: {{
          label: ctx => ` ${{ctx.label}}: ${{ctx.parsed}} tracker(s)`
        }}
      }}
    }},
    cutout: '68%',
  }}
}});
</script>
</body>
</html>"""

    # ── Save file ─────────────────────────────────────────────────
    try:
        script_dir = Path(__file__).parent
        fname      = f"privacy_report_{s.start_time.strftime('%Y%m%d_%I%M%p')}.html"
        fpath      = script_dir / fname
        fpath.write_text(html, encoding="utf-8")
        return str(fpath)
    except Exception as e:
        log.error("Could not save HTML report: %s", e)
        return ""


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main() -> None:
    browser = detect_browser()
    print_startup_banner(browser)

    seen: set[str] = set()

    try:
        proc = subprocess.Popen(
            build_tshark_cmd(),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except FileNotFoundError:
        log.error("tshark not found at: %s", TSHARK_PATH)
        return

    try:
        for raw_line in proc.stdout:
            domain = raw_line.strip()
            if not domain or domain in seen:
                continue
            seen.add(domain)
            handle_domain(domain, browser)

    except KeyboardInterrupt:
        print("\n\n[✓] Monitor stopped by user.")

    finally:
        proc.terminate()
        stats.print_summary()


def scan_domains(domains: list[str]) -> dict:
    """
    Direct integration method for SentinelAI orchestrator.
    Scans a list of domains against the local tracker DB and returns a risk assessment.
    """
    total_score = 0
    threats = []
    
    # Process unique domains
    seen = set()
    for raw_domain in domains:
        if not raw_domain:
            continue
            
        # Clean domain
        domain = raw_domain.split('//')[-1].split('/')[0].split(':')[0].strip().lower()
        
        if domain in seen:
            continue
        seen.add(domain)

        tracker_hits = match_keys(domain, TRACKERS)
        
        if not tracker_hits:
            continue

        unique_trackers = {}
        for _, tracker_info in tracker_hits:
            t_name = tracker_info["name"]
            if t_name not in unique_trackers or (
                # Higher risk version of the same tracker takes precedence
                (tracker_info["risk"] == "CRITICAL") or 
                (tracker_info["risk"] == "HIGH" and unique_trackers[t_name]["risk"] != "CRITICAL")
            ):
                unique_trackers[t_name] = tracker_info

        for t_name, tracker_info in unique_trackers.items():
            base_risk = tracker_info["risk"]
            geo_data, effective_risk = print_geo_info(domain, base_risk)
            
            score_addition = 0
            if effective_risk == "CRITICAL":
                score_addition = 35
            elif effective_risk == "HIGH":
                score_addition = 20
            elif effective_risk == "MEDIUM":
                score_addition = 10
            elif effective_risk == "LOW":
                score_addition = 3
                
            total_score += score_addition
            
            threat_id = f"network-tracker-{effective_risk.lower()}"
            threats.append({
                "type": threat_id,
                "detail": f"Tracker '{tracker_info['name']}' ({domain}) detected. Server location: {geo_data.get('country', 'Unknown')}. Privacy Law: {geo_data.get('law', 'Unknown')}.",
            })
            
    # Build data_sharing and blocking_tips from tracker hits
    data_sharing = []
    blocking_tips = []
    domain_locations = {}

    for raw_domain in domains:
        if not raw_domain:
            continue
        domain = raw_domain.split('//')[-1].split('/')[0].split(':')[0].strip().lower()
        tracker_hits = match_keys(domain, TRACKERS)
        if not tracker_hits:
            continue
        geo_data = geolocate_domain(domain)
        domain_locations[domain] = {
            "country": geo_data.get("country", "Unknown"),
            "country_code": geo_data.get("country_code", ""),
            "city": geo_data.get("city", "Unknown"),
            "org": geo_data.get("org", "Unknown"),
            "law": geo_data.get("law", "Unknown"),
            "law_rating": geo_data.get("law_rating", "UNKNOWN"),
        }
        for _, tracker_info in tracker_hits:
            data_sharing.append({
                "destination": domain,
                "tracker_name": tracker_info["name"],
                "data_collected": tracker_info.get("data", "unknown data"),
                "risk": tracker_info["risk"],
                "location": geo_data.get("country", "Unknown"),
                "law": geo_data.get("law", "Unknown"),
                "law_rating": geo_data.get("law_rating", "UNKNOWN"),
                "how_to_block": tracker_info.get("block", "Block via browser privacy settings"),
            })
            blocking_tips.append({
                "tracker": tracker_info["name"],
                "domain": domain,
                "tip": tracker_info.get("block", "Block via browser privacy settings"),
                "delete_url": tracker_info.get("delete_url", ""),
            })

    # Determine primary location
    primary_location = "Unknown"
    if domain_locations:
        countries = [v["country"] for v in domain_locations.values() if v["country"] != "Unknown"]
        if countries:
            primary_location = max(set(countries), key=countries.count)

    return {
        "agent": "monitor-analysis",
        "score": min(total_score, 100),
        "threats": threats,
        "data_sharing": data_sharing,
        "blocking_tips": blocking_tips,
        "primary_location": primary_location,
        "domain_locations": domain_locations,
    }


if __name__ == "__main__":
    main()
