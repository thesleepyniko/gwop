# Code to handle checking a URL against urlhaus

import httpx
from pathlib import Path
import datetime
import json
from urllib.parse import urlparse
import csv
import dotenv
METADATA_URL = Path("data/metadata/urlhaus.txt")
CACHE_URL = Path("data/urlhaus.csv")

dotenv.load_dotenv()
    
def refresh_local_cache():
    if Path.exists(METADATA_URL):
        with open(METADATA_URL, "r") as f:
            metadata_urlhaus = json.load(f)
            if metadata_urlhaus.get("next_update_at".fromisoformat(), datetime.datetime.now()) <= datetime.datetime.now(): # type: ignore
                pass
            else:
                return False # false means that it does not need an update
    request=httpx.get("https://urlhaus.abuse.ch/downloads/csv_online/")
    CACHE_URL.parent.mkdir(parents=True, exist_ok=True)
    CACHE_URL.touch()
    METADATA_URL.parent.mkdir(parents=True, exist_ok=True)
    METADATA_URL.touch()
    with open(CACHE_URL, 'w') as f:
        f.write(request.text)
    with open(Path(METADATA_URL), 'w') as f:
        metadata_urlhaus = {"last_updated_at": datetime.datetime.now().isoformat(), 
                            "next_update_at": (datetime.datetime.now() + datetime.timedelta(minutes = 5)).isoformat
        }
        json.dump(metadata_urlhaus, f)
    return True # it has been updated, so then we can go ahead

def check_url_urlhaus(url, api_key):
    if not (Path.exists(CACHE_URL) and Path.exists(METADATA_URL)):
        refresh_local_cache()

    parsed = urlparse(url)

    # first parsing the scheme
    scheme = parsed.scheme.lower()

    # then we parse host + port
    host, sep, port = parsed.netloc.partition(":")
    host = host.lower().rstrip(".")

    # if there is a port we either strip it because it's default or add it onto the host
    if port:
        if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
            netloc = host
        else:
            netloc = f"{host}:{port}"
    else:
        netloc = host
    
    # then we reconstruct the url
    url_parsed = f"{scheme}://{netloc}{parsed.path}"

    # finally we'll add the query and fragment back on
    if parsed.query:
        url_parsed += f"?{parsed.query}"
    if parsed.fragment:
        url_parsed += f"#{parsed.fragment}"
    
    with open(CACHE_URL, "r") as f:
        for line in f:
            reader = csv.DictReader(f)
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

    request=httpx.post("https://urlhaus-api.abuse.ch/v1/url/", 
                       headers={"Auth-Key": api_key}, 
                       json={"url": url}
    )
    try:
        request.raise_for_status()
    except httpx.HTTPStatusError:
        return
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


