# Code to handle checking a URL against urlhaus

import httpx
from pathlib import Path
import datetime
import json
from backend.resources.parse_url import parse_url
import csv
import dotenv
import backend.resources.definitions as definitions
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

    request=httpx.get("https://urlhaus.abuse.ch/downloads/csv_online/") # get the csv from the link

    # make sure that both the parent dirs and the files themselves exist as otherwise the below would fail
    CACHE_URL.parent.mkdir(parents=True, exist_ok=True)
    CACHE_URL.touch()
    METADATA_URL.parent.mkdir(parents=True, exist_ok=True)
    METADATA_URL.touch()

    with open(CACHE_URL, 'w') as f:
        f.write(request.text) # write the csv file

    with open(Path(METADATA_URL), 'w') as f:
        metadata_urlhaus = {"last_updated_at": datetime.datetime.now().isoformat(), # get the time now, then turn into isoforfmat so we can put it in json
                            "next_update_at": (datetime.datetime.now() + datetime.timedelta(minutes = 5)).isoformat() # same except add 5 minutes due to urlhaus recommendations
        }
        json.dump(metadata_urlhaus, f)
    return True # it has been updated, so return true just in case, more for logging than anything

def check_url_urlhaus(url, api_key):
    if not (Path.exists(CACHE_URL) or not Path.exists(METADATA_URL)): # if neither of these (or just one of these) don't exist, update these
        refresh_local_cache() 

    url_parsed = parse_url(url) # parse the url into a usable form
    
    with open(CACHE_URL, "r") as f:
        non_comment_lines = (line for line in f if not line.startswith('#')) # get rid of any commented lines
        reader = csv.DictReader(non_comment_lines, fieldnames=URLHAUS_HEADERS) # define the headers and feed lines into a csv reader
        for row in reader:
            if row["url"] == url_parsed:
                return definitions.UrlCheckResponse(
                    result=definitions.Result.hit,
                    is_threat=True,
                    via=definitions.Via.cache,
                    source="urlhaus", 
                    threat_type=definitions.ThreatType.malware, # urlhaus is for malware only so,
                    attributes={"urlhaus_id": None, "surbl_status": None, "spamhaus_dbl_status": None},
                    error=None
                 ) # if we find it here it is good, return immediately
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

        return definitions.UrlCheckResponse(
                    result=definitions.Result.error,
                    is_threat=False,
                    via=definitions.Via.none,
                    source="urlhaus", 
                    threat_type=None,
                    attributes=None,
                    error={"details": "no_results (empty_response)"}
        ) # this indicates that something went wrong with the request so we raise error
    
    response=request.json()
    if response.get("query_status", "") == "no_results":
        return definitions.UrlCheckResponse(
                    result=definitions.Result.miss,
                    is_threat=False,
                    via=definitions.Via.api,
                    source="urlhaus", 
                    threat_type=None, 
                    attributes={"surbl_status": None, 
                                "spamhaus_dbl_status": None, 
                                "urlhaus_id": None},
                    error=None
        ) # it was clean so we tell them that
    elif response.get("query") == "ok":
        refresh_local_cache()
        return definitions.UrlCheckResponse(
                    result=definitions.Result.hit,
                    is_threat=True,
                    via=definitions.Via.api,
                    source="urlhaus", 
                    threat_type=definitions.ThreatType.malware, 
                    attributes={
                        "surbl_status": response.get("blacklists", {}).get("surbl", None), 
                        "spamhaus_dbl_status": response.get("blacklists", {}).get("spamhaus_dbl", None), 
                        "urlhaus_id": response.get("id", "")},
                    error=None
        ) # flagged by api, we should also refresh our local cache just in case
    else:
        return definitions.UrlCheckResponse(
                        result=definitions.Result.error,
                        is_threat=False,
                        via=definitions.Via.api,
                        source="urlhaus", 
                        threat_type=None, 
                        attributes={
                            "surbl_status": None, 
                            "spamhaus_dbl_status": None, 
                            "urlhaus_id": None},
                        error=response.get("query")
        )


