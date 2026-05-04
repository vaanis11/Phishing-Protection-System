"""
PhishGuard Stats Engine
Tracks scan history and generates threat intelligence summaries.
"""

import json
import os
import tempfile
from datetime import datetime
from collections import defaultdict

_DEFAULT_DATA_DIR = os.environ.get("PHISHGUARD_DATA_DIR") or os.path.join(tempfile.gettempdir(), "phishguard")
STATS_FILE = os.environ.get("PHISHGUARD_STATS_FILE") or os.path.join(_DEFAULT_DATA_DIR, "stats.json")

def _load():
    os.makedirs(os.path.dirname(STATS_FILE), exist_ok=True)
    if os.path.exists(STATS_FILE):
        try:
            with open(STATS_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "total_scans": 0,
        "threats_detected": 0,
        "safe_urls": 0,
        "suspicious": 0,
        "recent": [],
        "category_hits": {},
        "tld_hits": {},
        "hourly": {}
    }

def _save(data):
    try:
        with open(STATS_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

def record_scan(result: dict):
    data = _load()
    data["total_scans"] += 1

    verdict = result.get("verdict", "")
    if verdict in ("PHISHING",):
        data["threats_detected"] += 1
    elif verdict == "SAFE":
        data["safe_urls"] += 1
    else:
        data["suspicious"] += 1

    # Category tracking
    for cat in result.get("categories_hit", []):
        data["category_hits"][cat] = data["category_hits"].get(cat, 0) + 1

    # TLD tracking
    tld = result.get("domain_info", {}).get("tld", "")
    if tld:
        data["tld_hits"][tld] = data["tld_hits"].get(tld, 0) + 1

    # Hourly tracking
    hour = datetime.utcnow().strftime("%Y-%m-%dT%H:00Z")
    data["hourly"][hour] = data["hourly"].get(hour, 0) + 1

    # Recent scans (last 10)
    recent_entry = {
        "url": result["url"][:60] + "..." if len(result["url"]) > 60 else result["url"],
        "verdict": result["verdict"],
        "risk_score": result["risk_score"],
        "timestamp": result["timestamp"],
        "url_id": result.get("url_id", "")
    }
    data["recent"] = [recent_entry] + data["recent"][:9]

    _save(data)
    return data

def get_stats():
    return _load()
