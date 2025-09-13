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
    return True # it has been updated, so return true just in case, more for logging than anything

def check_url_openphish(url: str, opset: set):
    if url in opset:
        return True
    else:
        return False