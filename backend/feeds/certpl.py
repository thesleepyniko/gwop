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
    "id", "domain", "added"
]
def refresh_certpl(): # just get the txt file 
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
        metadata_openphish= {
            "last_updated_at": datetime.datetime.now().isoformat() # get the time now, then turn into isoforfmat so we can put it in json
        }
        json.dump(metadata_openphish, f)
    return True # it has been updated, so return true just in case, more for logging than anything

def check_url_certpl(url: str):
    with open(CACHE_URL, "r") as f:
        non_comment_lines = (line for line in f if not line.startswith('#')) # get rid of any commented lines
        reader = csv.DictReader(non_comment_lines, fieldnames=CERTPL_HEADERS, delimiter="\t") # define the headers and feed lines into a csv reader
        for row in reader:
            if row["url"] == url:
                return definitions.UrlCheckResponse(
                    result=definitions.Result.hit,
                    is_threat=True,
                    via=definitions.Via.cache,
                    source="urlhaus", 
                    threat_type=definitions.ThreatType.malware, # urlhaus is for malware only so,
                    attributes={"urlhaus_id": None, "surbl_status": None, "spamhaus_dbl_status": None},
                    error=None
                 ) # if we find it here it is good, return immediately