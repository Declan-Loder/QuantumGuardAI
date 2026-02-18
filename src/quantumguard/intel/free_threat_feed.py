"""
Free Threat Intelligence Feed Fetcher
Pulls public, free IOCs from reliable sources (no API keys required).
"""

import requests
import json
from pathlib import Path
import time

OUTPUT_DIR = Path("outputs")
INTEL_FILE = OUTPUT_DIR / "free_threat_intel.json"

def fetch_urlhaus():
    """Fetch recent malware distribution URLs/IPs from abuse.ch URLhaus (public feed)"""
    url = "https://urlhaus.abuse.ch/downloads/json_recent/"
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        data = r.json()
        intel = []
        for entry in data[:20]:  # Limit to most recent 20
            intel.append({
                "source": "URLhaus",
                "url": entry["url"],
                "ip": entry.get("ip", "N/A"),
                "threat": entry["threat"],
                "tags": entry["tags"],
                "date_added": entry["date_added"]
            })
        return intel
    except Exception as e:
        print(f"URLhaus fetch error: {e}")
        return []

def fetch_malware_traffic_analysis():
    """Fetch latest daily IOCs from MalwareTrafficAnalysis.net (public)"""
    # For simplicity, fetch a known recent daily report (update date as needed)
    url = "https://www.malwaretrafficanalysis.net/2025/02/18/index.html"  # Example - change to latest
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            return [{
                "source": "MalwareTrafficAnalysis",
                "url": url,
                "note": "Daily malware report - check for IOCs (IPs, hashes, URLs)"
            }]
        else:
            return []
    except Exception as e:
        print(f"MTA fetch error: {e}")
        return []

def merge_and_save():
    urlhaus = fetch_urlhaus()
    mta = fetch_malware_traffic_analysis()

    combined = urlhaus + mta

    if not combined:
        print("No intel fetched from free sources.")
        return

    OUTPUT_DIR.mkdir(exist_ok=True)
    with open(INTEL_FILE, "w", encoding="utf-8") as f:
        json.dump({
            "last_updated": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_indicators": len(combined),
            "sources": {
                "urlhaus": len(urlhaus),
                "malwaretrafficanalysis": len(mta)
            },
            "indicators": combined
        }, f, indent=2)

    print(f"Saved {len(combined)} indicators to {INTEL_FILE}")
    print(f"URLhaus: {len(urlhaus)} | MTA: {len(mta)}")

if __name__ == "__main__":
    print("Fetching free threat intel...")
    merge_and_save()
