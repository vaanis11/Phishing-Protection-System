"""
PhishGuard Detection Engine v2.0
Advanced URL threat intelligence and phishing detection system.
"""

import re
import urllib.parse
import hashlib
import math
from datetime import datetime
from collections import Counter


# ─── Threat Intelligence Databases ────────────────────────────────────────────

TRUSTED_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com", "github.com",
    "stackoverflow.com", "wikipedia.org", "youtube.com", "linkedin.com",
    "twitter.com", "x.com", "facebook.com", "instagram.com", "reddit.com",
    "netflix.com", "spotify.com", "paypal.com", "ebay.com", "adobe.com",
    "cloudflare.com", "aws.amazon.com", "azure.microsoft.com"
}

PHISHING_KEYWORDS = {
    # Account / Auth
    "login": 12, "signin": 12, "sign-in": 10, "logon": 10,
    "verify": 10, "verification": 10, "validate": 10, "confirm": 8,
    "authentication": 8, "authorize": 8,
    # Financial
    "banking": 15, "payment": 10, "checkout": 8, "invoice": 8,
    "billing": 8, "wallet": 10, "crypto": 10, "bitcoin": 12,
    "transfer": 10, "wire": 8, "refund": 8,
    # Urgency / Social engineering
    "urgent": 15, "suspended": 15, "blocked": 12, "limited": 10,
    "expire": 12, "expires": 12, "immediately": 12, "alert": 8,
    "warning": 8, "notice": 6, "update": 6, "required": 6,
    # Brand abuse
    "paypal": 15, "amazon": 12, "apple": 12, "microsoft": 12,
    "google": 10, "netflix": 10, "ebay": 10, "facebook": 10,
    # Prize / Scam
    "winner": 20, "prize": 18, "reward": 15, "free": 10,
    "gift": 10, "bonus": 8, "lucky": 8, "congratulations": 15,
    # Security pretense
    "secure": 8, "security": 8, "protect": 6, "safe": 6,
    "official": 10, "support": 6, "helpdesk": 10,
}

SUSPICIOUS_TLDS = {
    ".xyz": 20, ".tk": 25, ".ml": 25, ".ga": 25, ".cf": 25,
    ".gq": 25, ".top": 15, ".pw": 20, ".cc": 12, ".click": 18,
    ".download": 20, ".loan": 20, ".work": 15, ".bid": 18,
    ".win": 18, ".racing": 20, ".date": 15, ".faith": 20,
    ".review": 15, ".stream": 15, ".gdn": 20, ".men": 18
}

KNOWN_BRAND_TYPOS = {
    "paypa1": "paypal", "paypai": "paypal", "paypa-l": "paypal",
    "micosoft": "microsoft", "microsofft": "microsoft", "micros0ft": "microsoft",
    "g00gle": "google", "gooogle": "google", "googgle": "google",
    "amaz0n": "amazon", "amazom": "amazon", "arnazon": "amazon",
    "app1e": "apple", "appie": "apple", "aplle": "apple",
    "faceb00k": "facebook", "facebok": "facebook", "faceboook": "facebook",
    "netf1ix": "netflix", "netflx": "netflix", "netlfix": "netflix",
}

HOMOGLYPH_MAP = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
    '6': 'g', '7': 't', '8': 'b', '@': 'a', '!': 'i',
    'vv': 'w', 'rn': 'm',
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "buff.ly", "short.link", "is.gd", "rb.gy", "cutt.ly",
    "shorte.st", "adf.ly", "bc.vc", "clk.sh"
}

IP_REGEX = re.compile(r'^https?://(\d{1,3}\.){3}\d{1,3}(:\d+)?(/.*)?$')
DATA_URI_REGEX = re.compile(r'^data:', re.IGNORECASE)
PUNYCODE_REGEX = re.compile(r'xn--', re.IGNORECASE)
PORT_REGEX = re.compile(r':(\d+)/')
HEX_ENCODING_REGEX = re.compile(r'%[0-9a-fA-F]{2}')


# ─── Helper Functions ──────────────────────────────────────────────────────────

def extract_parts(url: str) -> dict:
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        # Strip port from domain
        domain_clean = domain.split(":")[0]
        parts = domain_clean.split(".")
        tld = "." + parts[-1] if len(parts) > 1 else ""
        subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
        apex = ".".join(parts[-2:]) if len(parts) >= 2 else domain_clean
        return {
            "full": domain,
            "clean": domain_clean,
            "subdomain": subdomain,
            "apex": apex,
            "tld": tld,
            "path": parsed.path,
            "query": parsed.query,
            "scheme": parsed.scheme,
            "parts": parts,
        }
    except Exception:
        return {}


def calculate_entropy(s: str) -> float:
    """Shannon entropy — high entropy = random/encoded strings, suspicious."""
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def url_hash(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()[:16].upper()


def levenshtein(s1: str, s2: str) -> int:
    """Edit distance for typosquatting detection."""
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1,
                            prev[j] + (0 if c1 == c2 else 1)))
        prev = curr
    return prev[-1]


def check_structural_anomalies(url: str, parts: dict) -> list:
    findings = []

    # Raw IP address
    if IP_REGEX.match(url):
        findings.append({
            "category": "Structural",
            "severity": "HIGH",
            "detail": "URL uses a raw IP address instead of a domain name — a hallmark of phishing infrastructure"
        })

    # Data URI
    if DATA_URI_REGEX.match(url):
        findings.append({
            "category": "Structural",
            "severity": "CRITICAL",
            "detail": "Data URI detected — used to embed malicious HTML/JS content directly in URLs"
        })

    # Non-standard port
    port_match = PORT_REGEX.search(url)
    if port_match:
        port = int(port_match.group(1))
        if port not in (80, 443, 8080, 8443):
            findings.append({
                "category": "Structural",
                "severity": "MEDIUM",
                "detail": f"Non-standard port {port} detected — legitimate services rarely use obscure ports"
            })

    # Punycode / IDN homograph attack
    if PUNYCODE_REGEX.search(url):
        findings.append({
            "category": "Structural",
            "severity": "HIGH",
            "detail": "Punycode (IDN homograph attack) detected — domain uses Unicode lookalike characters to impersonate trusted brands"
        })

    # URL length
    if len(url) > 100:
        findings.append({
            "category": "Structural",
            "severity": "LOW" if len(url) < 150 else "MEDIUM",
            "detail": f"Abnormally long URL ({len(url)} chars) — adversaries embed decoys in query strings to obscure the true destination"
        })

    # Excessive subdomains
    if parts.get("subdomain") and parts["subdomain"].count(".") >= 2:
        findings.append({
            "category": "Structural",
            "severity": "HIGH",
            "detail": f"Excessive subdomain nesting ({parts['subdomain']}) — classic technique to make phishing domains appear legitimate"
        })

    # @ symbol in URL (credential embedding trick)
    if "@" in parts.get("full", ""):
        findings.append({
            "category": "Structural",
            "severity": "CRITICAL",
            "detail": "@ symbol in domain — browsers use everything before @ as credentials; attackers exploit this for redirect deception"
        })

    # Hex encoding obfuscation
    hex_count = len(HEX_ENCODING_REGEX.findall(url))
    if hex_count > 3:
        findings.append({
            "category": "Obfuscation",
            "severity": "HIGH",
            "detail": f"{hex_count} percent-encoded characters detected — encoding used to bypass URL filters and hide malicious content"
        })

    return findings


def check_domain_intelligence(parts: dict) -> list:
    findings = []
    apex = parts.get("apex", "")
    domain_clean = parts.get("clean", "")

    # Whitelist
    for trusted in TRUSTED_DOMAINS:
        if apex == trusted or domain_clean == trusted:
            return [{"category": "Whitelist", "severity": "SAFE", "detail": f"Domain verified in trusted whitelist: {trusted}"}]

    # Suspicious TLD
    tld = parts.get("tld", "")
    if tld in SUSPICIOUS_TLDS:
        findings.append({
            "category": "Domain",
            "severity": "HIGH",
            "detail": f"High-risk TLD '{tld}' — commonly used in free/disposable domain abuse for phishing campaigns"
        })

    # Multiple hyphens
    hyphen_count = apex.count("-")
    if hyphen_count >= 2:
        findings.append({
            "category": "Domain",
            "severity": "MEDIUM",
            "detail": f"{hyphen_count} hyphens in domain — attackers use hyphens to construct convincing fake domains like 'secure-login-amazon.xyz'"
        })

    # Known brand typosquatting
    for typo, brand in KNOWN_BRAND_TYPOS.items():
        if typo in domain_clean:
            findings.append({
                "category": "Typosquatting",
                "severity": "CRITICAL",
                "detail": f"Known typosquat pattern '{typo}' impersonating '{brand}' — direct brand impersonation"
            })

    # Levenshtein-based typosquatting against major brands
    major_brands = ["paypal", "microsoft", "amazon", "google", "apple", "netflix", "facebook"]
    domain_no_tld = apex.rsplit(".", 1)[0] if "." in apex else apex
    for brand in major_brands:
        dist = levenshtein(domain_no_tld, brand)
        if 0 < dist <= 2 and domain_no_tld != brand:
            findings.append({
                "category": "Typosquatting",
                "severity": "CRITICAL",
                "detail": f"Domain '{domain_no_tld}' is {dist} edit(s) away from '{brand}' — likely typosquatting"
            })

    # Domain entropy (random-looking domains = DGA / fast-flux)
    entropy = calculate_entropy(domain_no_tld)
    if entropy > 3.8:
        findings.append({
            "category": "Domain",
            "severity": "MEDIUM",
            "detail": f"High domain entropy ({entropy:.2f}) — suggests algorithmically-generated domain (DGA), common in botnet C2 and phishing kits"
        })

    # URL shortener
    if apex in SHORTENER_DOMAINS:
        findings.append({
            "category": "Domain",
            "severity": "MEDIUM",
            "detail": f"URL shortener detected ({apex}) — destination is hidden; shorteners are frequently abused in phishing and malware distribution"
        })

    # Brand name buried in subdomain
    brands_in_sub = ["paypal", "amazon", "apple", "microsoft", "google", "netflix", "ebay"]
    subdomain = parts.get("subdomain", "").lower()
    for brand in brands_in_sub:
        if brand in subdomain and brand not in apex:
            findings.append({
                "category": "Domain",
                "severity": "HIGH",
                "detail": f"Brand '{brand}' placed in subdomain, not apex — e.g., paypal.evil.com tricks users into thinking it's legitimate"
            })

    return findings


def check_content_patterns(url: str, parts: dict) -> list:
    findings = []
    url_lower = url.lower()

    # Keyword scoring
    matched = {}
    for kw, score in PHISHING_KEYWORDS.items():
        if kw in url_lower:
            matched[kw] = score

    if matched:
        top_kw = sorted(matched, key=matched.get, reverse=True)[:5]
        severity = "HIGH" if sum(matched.values()) > 40 else "MEDIUM"
        findings.append({
            "category": "Content",
            "severity": severity,
            "detail": f"Social engineering keywords detected: {', '.join(top_kw)} — these terms are weaponized to create urgency or impersonate services"
        })

    # Multiple redirects in path
    if url_lower.count("http") > 1:
        findings.append({
            "category": "Redirect",
            "severity": "HIGH",
            "detail": "Nested URL detected — open redirect or redirect chain used to evade URL scanners and confuse users"
        })

    # Double slashes in path (path traversal attempt)
    if "//" in parts.get("path", ""):
        findings.append({
            "category": "Structural",
            "severity": "MEDIUM",
            "detail": "Double slashes in path — possible path traversal or proxy bypass attempt"
        })

    # Query string entropy
    query = parts.get("query", "")
    if query and calculate_entropy(query) > 4.2:
        findings.append({
            "category": "Obfuscation",
            "severity": "MEDIUM",
            "detail": "High-entropy query parameters — encoded/obfuscated data in query string may contain payload or tracking tokens"
        })

    # Homoglyph check
    for char, replacement in HOMOGLYPH_MAP.items():
        if char in parts.get("apex", ""):
            findings.append({
                "category": "Homoglyph",
                "severity": "HIGH",
                "detail": f"Homoglyph character '{char}' (looks like '{replacement}') used in domain — visual spoofing attack"
            })
            break

    return findings

def check_protocol_security(url: str) -> list:
    findings = []
    if url.startswith("http://") and not url.startswith("https://"):
        findings.append({
            "category": "Protocol",
            "severity": "MEDIUM",
            "detail": "Unencrypted HTTP connection — credentials and data transmitted in plaintext; no TLS protection"
        })
    return findings


SEVERITY_WEIGHTS = {"CRITICAL": 35, "HIGH": 20, "MEDIUM": 10, "LOW": 5, "SAFE": -100}

def analyze_url(url: str) -> dict:
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    url_id = url_hash(url)

    parts = extract_parts(url)

    # Run all detection modules
    all_findings = []
    all_findings += check_structural_anomalies(url, parts)
    all_findings += check_domain_intelligence(parts)
    all_findings += check_content_patterns(url, parts)
    all_findings += check_protocol_security(url)

    # Check for whitelist safe signal
    is_whitelisted = any(f["severity"] == "SAFE" for f in all_findings)
    if is_whitelisted:
        return {
            "url": url,
            "url_id": url_id,
            "timestamp": timestamp,
            "risk_score": 0,
            "verdict": "SAFE",
            "verdict_label": "Trusted Domain",
            "confidence": 99,
            "threat_level": "NONE",
            "findings": [],
            "categories_hit": [],
            "domain_info": {
                "apex": parts.get("apex", ""),
                "tld": parts.get("tld", ""),
                "scheme": parts.get("scheme", ""),
            },
            "whitelisted": True,
        }

    # Score calculation
    raw_score = sum(SEVERITY_WEIGHTS.get(f["severity"], 0) for f in all_findings)
    risk_score = max(0, min(100, raw_score))

    # Confidence based on number of signals
    confidence = min(95, 50 + len(all_findings) * 8)

    # Threat level
    if risk_score >= 70:
        threat_level = "CRITICAL"
        verdict = "PHISHING"
        verdict_label = "Confirmed Phishing Threat"
    elif risk_score >= 45:
        threat_level = "HIGH"
        verdict = "SUSPICIOUS"
        verdict_label = "Highly Suspicious URL"
    elif risk_score >= 20:
        threat_level = "MEDIUM"
        verdict = "CAUTION"
        verdict_label = "Proceed with Caution"
    else:
        threat_level = "LOW"
        verdict = "SAFE"
        verdict_label = "No Significant Threats Detected"

    categories_hit = list(set(f["category"] for f in all_findings))

    return {
        "url": url,
        "url_id": url_id,
        "timestamp": timestamp,
        "risk_score": risk_score,
        "verdict": verdict,
        "verdict_label": verdict_label,
        "confidence": confidence,
        "threat_level": threat_level,
        "findings": all_findings,
        "categories_hit": categories_hit,
        "domain_info": {
            "apex": parts.get("apex", ""),
            "subdomain": parts.get("subdomain", ""),
            "tld": parts.get("tld", ""),
            "scheme": parts.get("scheme", ""),
            "entropy": round(calculate_entropy(parts.get("apex", "").split(".")[0]), 3),
        },
        "whitelisted": False,
    }