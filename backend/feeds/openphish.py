import httpx
from pathlib import Path
import datetime
import json
from resources.parse_url import parse_url
import csv
import dotenv
import resources.definitions as definitions

METADATA_URL = Path("data/metadata/openphish.json")
CACHE_URL = Path("data/openphish.txt")

def refresh_openphish(): # just get the txt file 
    request = httpx.get("https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt")
    if not Path.is_dir(CACHE_URL.parent):
        Path.mkdir(CACHE_URL.parent, exist_ok=True, parents=True)
        CACHE_URL.touch()
    if not Path.is_dir(METADATA_URL):
        Path.mkdir(CACHE_URL.parent, exist_ok=True, parents=True)
        METADATA_URL.touch()
    with open(CACHE_URL, 'w') as f:
        f.write(request.text) # write the txt file
    with open(Path(METADATA_URL), 'w') as f: # write some data
        metadata_openphish= {
            "last_updated_at": datetime.datetime.now().isoformat() # get the time now, then turn into isoforfmat so we can put it in json
        }
        json.dump(metadata_openphish, f)
    return {line.strip() for line in request.text.splitlines() if line.strip()}


def check_url_openphish(url: str, opset: set):
    try:
        if url in opset:
            return definitions.UrlCheckResponse(
                        result=definitions.Result.hit,
                        is_threat=True,
                        via=definitions.Via.cache,
                        source="openphish", 
                        threat_type=definitions.ThreatType.phishing, #its in the name openphish
                        attributes={"urlhaus_id": None, "surbl_status": None, "spamhaus_dbl_status": None},
                        error=None)

        else:
            return definitions.UrlCheckResponse(
                        result=definitions.Result.miss,
                        is_threat=False,
                        via=definitions.Via.cache,
                        source="openphish", 
                        threat_type=None,
                        attributes=None,
                        error=None
                    )
    except Exception as e:
        return definitions.UrlCheckResponse(
                        result=definitions.Result.error,
                        is_threat=False,
                        via=definitions.Via.cache,
                        source="openphish", 
                        threat_type=None,
                        attributes=None,
                        error={"details": str(e)}
                    )