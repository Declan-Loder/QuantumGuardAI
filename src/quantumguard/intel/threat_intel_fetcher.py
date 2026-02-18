"""
Threat Intelligence Fetcher
Pulls malicious IPs from AlienVault OTX and AbuseIPDB.
Saves merged intel for ThreatDetector to use.
"""

import requests
import json
from pathlib import Path
import time

OTX_API_KEY = "ac9703819808a60e06242403ff75166ca0d6de7865960/ca5ba364db1a"
ABUSEIPDB_API_KEY = "878da0a978afb89789f601e978557ec2b59317a96038b21ee823113d0c5cfe3a7196ec05db142a20"

OTX_BASE_URL = "https://otx.alienvault.com/api/v1"
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"

OUTPUT_DIR = Path("outputs")
INTEL_FILE = OUTPUT_DIR / "threat_intel.json"

def fetch_otx_pulses(limit=5):
    url = f"{OTX_BASE_URL}/pulses/subscribed?limit={limit}"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}

    try:
        r = requests.get(url, headers=headers, timeout=10)
        r.raise_for_status()
        pulses = r.json().get("results", [])

        intel = []
        for pulse in pulses:
            for ind in pulse.get("indicators", []):
                if ind["type"] == "IPv4" and ind.get("is_active"):
                    intel.append({
                        "ip": ind["indicator"],
                        "source": "OTX",
                        "pulse": pulse["name"],
                        "confidence": 80,  # OTX doesn't give %, so default medium-high
                        "tags": pulse.get("tags", [])
                    })
        return intel
    except Exception as e:
        print(f"OTX fetch error: {e}")
        return []

def fetch_abuseipdb(limit=10, min_confidence=80):
    url = f"{ABUSEIPDB_BASE_URL}/check-blocklist?confidenceMinimum={min_confidence}&limit={limit}"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}

    try:
        r = requests.get(url, headers=headers, timeout=10)
        r.raise_for_status()
        data = r.json().get("data", [])

        intel = []
        for entry in data:
            intel.append({
                "ip": entry["ipAddress"],
                "source": "AbuseIPDB",
                "abuse_confidence": entry["abuseConfidenceScore"],
                "last_reported": entry["lastReportedAt"],
                "categories": entry["categories"]
            })
        return intel
    except Exception as e:
        print(f"AbuseIPDB fetch error: {e}")
        return []

def merge_and_save():
    otx_intel = fetch_otx_pulses()
    abuse_intel = fetch_abuseipdb()

    all_intel = otx_intel + abuse_intel

    if not all_intel:
        print("No intel fetched from either source.")
        return

    OUTPUT_DIR.mkdir(exist_ok=True)
    with open(INTEL_FILE, "w", encoding="utf-8") as f:
        json.dump({
            "last_updated": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_indicators": len(all_intel),
            "sources": {
                "otx": len(otx_intel),
                "abuseipdb": len(abuse_intel)
            },
            "indicators": all_intel
        }, f, indent=2)

    print(f"Saved {len(all_intel)} indicators to {INTEL_FILE}")
    print(f"OTX: {len(otx_intel)} | AbuseIPDB: {len(abuse_intel)}")

if __name__ == "__main__":
    print("Fetching threat intel...")
    merge_and_save()
