# Code to handle checking a URL against urlhaus

import httpx
from pathlib import Path
import datetime
import json
from backend.resources.parse_url import parse_url
import csv
import dotenv
METADATA_URL = Path("data/metadata/urlhaus.txt")
CACHE_URL = Path("data/urlhaus.csv")

dotenv.load_dotenv()

URLHAUS_HEADERS = [
    "id", "dateadded", "url", "url_status", "last_online", 
    "threat", "tags", "urlhaus_link", "reporter"
]

def refresh_local_cache():
    if Path.exists(METADATA_URL):
        try:
            with open(METADATA_URL, "r") as f:
                if METADATA_URL.stat().st_size == 0:
                    pass # treat as needing refresh because it's empty
                else:
                    metadata_urlhaus = json.load(f)
                    next_update_at_str = metadata_urlhaus.get("next_update_at")
                    if next_update_at_str and datetime.datetime.fromisoformat(next_update_at_str) > datetime.datetime.now():
                        return False # false means that it does not need an update
        except (json.JSONDecodeError, FileNotFoundError):
            pass

    request=httpx.get("https://urlhaus.abuse.ch/downloads/csv_online/")
    CACHE_URL.parent.mkdir(parents=True, exist_ok=True)
    CACHE_URL.touch()
    METADATA_URL.parent.mkdir(parents=True, exist_ok=True)
    METADATA_URL.touch()
    with open(CACHE_URL, 'w') as f:
        f.write(request.text)
    with open(Path(METADATA_URL), 'w') as f:
        metadata_urlhaus = {"last_updated_at": datetime.datetime.now().isoformat(), 
                            "next_update_at": (datetime.datetime.now() + datetime.timedelta(minutes = 5)).isoformat()
        }
        json.dump(metadata_urlhaus, f)
    return True # it has been updated, so then we can go ahead

def check_url_urlhaus(url, api_key):
    if not (Path.exists(CACHE_URL) and Path.exists(METADATA_URL)):
        refresh_local_cache()

    url_parsed = parse_url(url)
    
    with open(CACHE_URL, "r") as f:
        non_comment_lines = (line for line in f if not line.startswith('#'))
        reader = csv.DictReader(non_comment_lines, fieldnames=URLHAUS_HEADERS)
        for row in reader:
            if row["url"] == url_parsed:
                return {
                    "urlhaus_id": row["id"], 
                    "threat": row["threat"], 
                    "surbl_status": None,
                    "spamhaus_dbl_status": None,
                    "confirmed_via": "cache",
                    "error": None
                }
        refresh_local_cache()

    request=httpx.post("https://urlhaus-api.abuse.ch/v1/url/", 
                       headers={"Auth-Key": api_key}, 
                       data={"url": url_parsed}
    )
    try:
        request.raise_for_status()
    except httpx.HTTPStatusError:
        return
    print(f"HTTP/{request.http_version} {request.status_code} {request.reason_phrase}")
    for header, value in request.headers.items():
        print(f"{header}: {value}")
    print() # Blank line separator
    print(request.text)
    if not request.text:
        return {
            "urlhaus_id": None,
            "threat": False,
            "surbl_status": None,
            "spamhaus_dbl_status": None,
            "confirmed_via": "api",
            "error": "no_results (empty response)"
        }
    
    response=request.json()
    if response.get("query_status", "") == "no_results":
        return {
            "urlhaus_id": None,
            "threat": False,
            "surbl_status": None,
            "spamhaus_dbl_status": None,
            "confirmed_via": "api",
            "error": None
        }
    elif response.get("query") == "ok":
        return {
            "urlhaus_id": response.get("id", ""), 
            "threat": response.get("threat", ""), 
            "surbl_status": response.get("blacklists", {}).get("surbl", ""),
            "spamhaus_dbl_status": response.get("blacklists", {}).get("spamhaus_dbl", ""),
            "confirmed_via": "api",
            "error": None
        }
    else:
        return {
            "urlhaus_id": None,
            "threat": None,
            "surbl_status": None,
            "spamhaus_dbl_status": None,
            "error": response.get("query")
        }


