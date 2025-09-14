# Code to handle checking a URL against urlhaus
#TODO: Actually do this
import httpx
from pathlib import Path
import datetime
import json
from resources.parse_url import parse_url
import csv
import dotenv
import resources.definitions as definitions
import zipfile
import io
METADATA_URL = Path("data/metadata/threatfox.json")
CACHE_URL = Path("data/threatfox.csv")

dotenv.load_dotenv()

THREATFOX_HEADERS = [
    "first_seen_utc", "ioc_id", "ioc_value", "ioc_type", "threat_type",
    "fk_malware", "malware_alias", "malware_printable", "last_seen_utc",
    "confidence_level", "reference", "tags", "anonymous", "reporter"
]

THREATFOX_MAP = {
    "payload_delivery": definitions.ThreatType.malware,
    "botnet_cc": definitions.ThreatType.malware,
    "payload": definitions.ThreatType.malware,
    "cc_skimming": definitions.ThreatType.other,
}

def refresh_threatfox_cache():
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

    request=httpx.get("https://threatfox.abuse.ch/export/csv/full/") # get the csv from the link

    # make sure that both the parent dirs and the files themselves exist as otherwise the below would fail
    CACHE_URL.parent.mkdir(parents=True, exist_ok=True)
    CACHE_URL.touch()
    METADATA_URL.parent.mkdir(parents=True, exist_ok=True)
    METADATA_URL.touch()

    with zipfile.ZipFile(io.BytesIO(request.content), "r") as f:
        csv_file_name = f.namelist()[0]
        with f.open(csv_file_name) as csv_file:
            with open(CACHE_URL, 'wb') as output_f:
                output_f.write(csv_file.read())
        
    # with open(CACHE_URL, 'w') as f:
    #     f.write(request.text) # write the csv file

    with open(Path(METADATA_URL), 'w') as f:
        metadata_threatfox = {"last_updated_at": datetime.datetime.now().isoformat(), # get the time now, then turn into isoforfmat so we can put it in json
                            "next_update_at": (datetime.datetime.now() + datetime.timedelta(hours=1)).isoformat() # same except add 5 minutes due to urlhaus recommendations
        }
        json.dump(metadata_threatfox, f)
    return True # it has been updated, so return true just in case, more for logging than anything

def check_url_threatfox(parsed_url, raw_url, api_key):
    if not (CACHE_URL.exists() and METADATA_URL.exists()): # if neither of these (or just one of these) don't exist, update these
        refresh_threatfox_cache() 
    
    with open(CACHE_URL, "r") as f:
        non_comment_lines = (line for line in f if not line.startswith('#')) # get rid of any commented lines
        reader = csv.DictReader(non_comment_lines, fieldnames=THREATFOX_HEADERS) # define the headers and feed lines into a csv reader
        for row in reader:
            if row["ioc_type"] == parsed_url or row["ioc_value"] == raw_url:
                tf_confidence = definitions.Confidence.low
                if row["confidence_level"]:
                    if int(row["confidence_level"]) >= 75:
                        tf_confidence = definitions.Confidence.high
                    elif int(row["confidence_level"]) >= 50:
                        tf_confidence = definitions.Confidence.medium
                    else:
                        tf_confidence = definitions.Confidence.low
                else:
                    tf_confidence = definitions.Confidence.low
                return [definitions.UrlCheckResponse(
                    result=definitions.Result.hit,
                    is_threat=True,
                    via=definitions.Via.cache,
                    source="urlhaus", 
                    threat_type=definitions.ThreatType.malware,
                    attributes={"urlhaus_id": None, "surbl_status": None, "spamhaus_dbl_status": None},
                    confidence=tf_confidence,
                    error=None
                 )] # if we find it here it is good, return immediately
        refresh_threatfox_cache()

    raw_request=httpx.post("https://threatfox-api.abuse.ch/api/v1/", 
                       headers={"Auth-Key": api_key}, 
                       json={
                           "query": "search_ioc",
                           "search_term": raw_url}
    )
    parse_request=httpx.post("https://threatfox-api.abuse.ch/api/v1/", 
                       headers={"Auth-Key": api_key}, 
                       json={
                           "query": "search_ioc",
                           "search_term": parsed_url}
    )
    requests_list = [raw_request, parse_request]
    try:
        parse_request.raise_for_status()
        raw_request.raise_for_status()
    except httpx.HTTPStatusError:
        return [definitions.UrlCheckResponse(
                    result=definitions.Result.error,
                    is_threat=False,
                    via=definitions.Via.none,
                    source="threatfox", 
                    threat_type=None,
                    attributes=None,
                    confidence=definitions.Confidence.notapplicable,
                    error={"details": "HTTPStatusError"})]
    
    decisions_list = []
    for request in requests_list:
        print(f"HTTP/{request.http_version} {request.status_code} {request.reason_phrase}")
        for header, value in request.headers.items():
            print(f"{header}: {value}")
        print() # Blank line separator
        print(request.text)
        if not request.text:
            decisions_list.append(definitions.UrlCheckResponse(
                        result=definitions.Result.error,
                        is_threat=False,
                        via=definitions.Via.none,
                        source="threatfox", 
                        threat_type=None,
                        attributes=None,
                        confidence=definitions.Confidence.low,
                        error={"details": "no_results (empty_response)"}
            )) # this indicates that something went wrong with the request so we raise error
        
        response=request.json()
        if response.get("query_status", "") == "no_result":
            decisions_list.append(definitions.UrlCheckResponse(
                        result=definitions.Result.miss,
                        is_threat=False,
                        via=definitions.Via.api,
                        source="threatfox", 
                        threat_type=None, 
                        attributes={"malware_type": None, 
                                    "malware_printable": None, 
                                    "threat_type": None},
                        confidence=definitions.Confidence.medium,
                        error=None
            )) # it was clean so we tell them that
            continue
        
        data=response.get("data", [{}])[0] #

        if response.get("query_status") == "ok":
            refresh_threatfox_cache()
            tf_confidence = definitions.Confidence.low
            if data.get("confidence_level", None) is not None:
                if int(data.get("confidence_level", 0)) >= 75:
                    tf_confidence = definitions.Confidence.high
                elif int(data.get("confidence_level", 0)) >= 50:
                    tf_confidence = definitions.Confidence.medium
                else:
                    tf_confidence = definitions.Confidence.low
            else:
                tf_confidence = definitions.Confidence.low

            fk_type = data.get("threat_type", "")
            mapped_type = THREATFOX_MAP.get(fk_type, definitions.ThreatType.unknown)

            decisions_list.append(definitions.UrlCheckResponse(
                        result=definitions.Result.hit,
                        is_threat=True,
                        via=definitions.Via.api,
                        source="threatfox", 
                        threat_type=mapped_type, 
                        attributes={"malware_type": data.get("malware", ""), 
                                    "malware_printable": data.get("malware_printable", ""), 
                                    "threat_type": data.get("threat_type", "")},
                        confidence=tf_confidence,
                        error=None
            )) # flagged by api, we should also refresh our local cache just in case
        else:
            return definitions.UrlCheckResponse(
                            result=definitions.Result.error,
                            is_threat=False,
                            via=definitions.Via.api,
                            source="threatfox", 
                            threat_type=None, 
                            attributes={
                                "malware_type": None, 
                                "malware_printable": None, 
                                "threat_type": None},
                            confidence=definitions.Confidence.notapplicable,
                            error={"details": response}
            )
    hit = next((d for d in decisions_list if d.result == definitions.Result.hit and d.is_threat), None)
    if hit:
        return hit

    error = next((d for d in decisions_list if d.result == definitions.Result.error), None)
    if error:
        return error

    miss = next((d for d in decisions_list if d.result == definitions.Result.miss), None)
    if miss:
        return miss

    return definitions.UrlCheckResponse(
        result=definitions.Result.error,
        is_threat=False,
        via=definitions.Via.none,
        source="threatfox",
        threat_type=None,
        attributes=None,
        confidence=definitions.Confidence.notapplicable,
        error={"details": "unexpected empty result list"}
    )

