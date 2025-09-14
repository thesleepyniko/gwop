import httpx
from pathlib import Path
import datetime
import json
from resources.parse_url import parse_url
import csv
import dotenv
import resources.definitions as definitions

METADATA_URL = Path("data/metadata/certpl.json")
CACHE_URL = Path("data/certpl.tsv")
CERTPL_HEADERS = [
    "id", "url", "dateadded"
]
def refresh_certpl(): # just get the txt file 
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
        
    request = httpx.get("https://hole.cert.pl/domains/v2/domains.csv")
    if not Path.is_dir(CACHE_URL.parent):
        Path.mkdir(CACHE_URL.parent, exist_ok=True, parents=True)
        CACHE_URL.touch()
    if not Path.is_dir(METADATA_URL):
        Path.mkdir(CACHE_URL.parent, exist_ok=True, parents=True)
        METADATA_URL.touch()
    with open(CACHE_URL, 'w') as f:
        f.write(request.text) # write the txt file
    with open(Path(METADATA_URL), 'w') as f: # write some data
        metadata_certpl= {
            "last_updated_at": datetime.datetime.now().isoformat(), # get the time now, then turn into isoforfmat so we can put it in json
            "next_update_at": (datetime.datetime.now() + datetime.timedelta(hours=1)).isoformat()
        }
        json.dump(metadata_certpl, f)
    return True # it has been updated, so return true just in case, more for logging than anything

def check_url_certpl(url: str):
    if not (CACHE_URL.exists() and METADATA_URL.exists()):
        refresh_certpl()
    with open(CACHE_URL, "r") as f:
        non_comment_lines = (line for line in f if not line.startswith('#'))
        reader = csv.DictReader(non_comment_lines, fieldnames=CERTPL_HEADERS, delimiter="\t") # define the headers and feed lines into a tsv reader
        for row in reader:
            if row["url"] == url:
                return definitions.UrlCheckResponse(
                    result=definitions.Result.hit,
                    is_threat=True,
                    via=definitions.Via.cache,
                    source="certpl", 
                    threat_type=definitions.ThreatType.mixed,
                    attributes=None,
                    confidence=definitions.Confidence.high,
                    error=None
                 )
        return definitions.UrlCheckResponse(
                    result=definitions.Result.miss,
                    is_threat=False,
                    via=definitions.Via.cache,
                    source="certpl", 
                    threat_type=None,
                    attributes=None,
                    confidence=definitions.Confidence.high,
                    error=None
                 )