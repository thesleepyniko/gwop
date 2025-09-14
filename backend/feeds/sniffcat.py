import httpx
from pathlib import Path
import datetime
import json
from resources.parse_url import parse_url
import csv
import dotenv
import resources.definitions as definitions
from resources.cache import Cache
SNIFFCAT_CATEGORIES = {
    1: definitions.ThreatType.malware,
    2: definitions.ThreatType.malware,
    3: definitions.ThreatType.malware,
    4: definitions.ThreatType.malware,
    5: definitions.ThreatType.malware,
    6: definitions.ThreatType.malware,
    7: definitions.ThreatType.malware,
    8: definitions.ThreatType.malware,
    9: definitions.ThreatType.malware,
    10: definitions.ThreatType.phishing,
    11: definitions.ThreatType.malware,
    12: definitions.ThreatType.malware,
    13: definitions.ThreatType.malware,
    14: definitions.ThreatType.other,
    15: definitions.ThreatType.other,
    16: definitions.ThreatType.malware,
    17: definitions.ThreatType.malware,
    18: definitions.ThreatType.other,
    19: definitions.ThreatType.other,
    20: definitions.ThreatType.malware,
    21: definitions.ThreatType.malware,
    22: definitions.ThreatType.malware,
    23: definitions.ThreatType.malware,
    24: definitions.ThreatType.malware,
    25: definitions.ThreatType.malware,
    26: definitions.ThreatType.malware,
    27: definitions.ThreatType.other,
}

def check_sniffcat_ip(ip):
    try:
        request=httpx.get(f"https://api.sniffcat.com/api/v1/check", 
                        params={"ip": ip,}, 
                        timeout=10.0
        )
        request.raise_for_status()
    except Exception as e:
        return definitions.UrlCheckResponse(
            result=definitions.Result.error,
            is_threat=False,
            via=definitions.Via.none,
            source="sniffcat",
            threat_type=None,
            attributes=None,
            confidence=definitions.Confidence.notapplicable,
            error={"details": f"error while getting sniffcat result {e}"}
        ) 
    resp = request.json()
    if resp.get("count", 0) == 0:
        return definitions.UrlCheckResponse(
            result=definitions.Result.miss,
            is_threat=False,
            via=definitions.Via.api,
            source="sniffcat",
            threat_type=None,
            attributes=None,
            confidence=definitions.Confidence.high,
            error=None
        ) 
    else:
        threattype_list=[]
        for report in resp.get("reports", []):
            for category in report.get("category"):
                threattype_list.append(SNIFFCAT_CATEGORIES.get(int(category), definitions.ThreatType.unknown))


    