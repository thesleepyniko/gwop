# Code to handle checking a URL against OTX AlienVault

import httpx
from pathlib import Path
import datetime
import json
from resources.parse_url import parse_url
import csv
import dotenv
import resources.definitions as definitions
from urllib.parse import quote

def check_url_otx(url: str, api_key):
   
    # url_encoded = quote(url, safe="")
    request=httpx.get(f"https://otx.alienvault.com/api/v1/indicators/url/{url}/general", 
                       headers={"X-OTX_API-KEY": api_key}, 
                       timeout=10.0
    )
    try:
        request.raise_for_status()
    except httpx.HTTPStatusError:
        return
    except Exception as e:
        return definitions.UrlCheckResponse(
            result=definitions.Result.error,
            is_threat=False,
            via=definitions.Via.api,
            source="otx",
            threat_type=None,
            attributes=None,
            error={"details": str(e)},
        )

    data = request.json()
    pulse_info = data.get("pulse_info", {})
    pulse_count = pulse_info.get("count", 0)
    print(data)
    if pulse_count > 0:
        return definitions.UrlCheckResponse(
            result=definitions.Result.hit,
            is_threat=True,
            via=definitions.Via.api,
            source="otx",
            threat_type=definitions.ThreatType.unknown, 
            attributes={"pulse_count": pulse_count},
            error=None,
        )
    else:
        return definitions.UrlCheckResponse(
            result=definitions.Result.miss,
            is_threat=False,
            via=definitions.Via.api,
            source="otx",
            threat_type=None,
            attributes={"pulse_count": pulse_count},
            error=None,
        )
