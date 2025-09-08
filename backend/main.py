from feeds.phishdirectory import check_url_phishdir
from feeds.urlhaus import check_url_urlhaus, refresh_local_cache
from resources.parse_url import parse_url
import resources.definitions as definitions
import os
import asyncio # we need this to run our periodic scanning
from urllib.parse import urlparse
from pathlib import Path
from fastapi import FastAPI
from contextlib import asynccontextmanager, suppress
from fastapi.responses import JSONResponse
from fastapi.exceptions import HTTPException
from typing import List, Union
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent  
load_dotenv(BASE_DIR / ".env") 

app = FastAPI()

DATA_DIR=Path("./data")

async def refresh_feeds():
    while True:
        # first, refreshing urlhaus
        refresh_local_cache()
        await asyncio.sleep(300)

@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(refresh_feeds())
    try:
        yield
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task


def simple_construct_verdict(responses: List[definitions.UrlCheckResponse]) -> definitions.ClientResponse: 
    # simple verdict construction for when phish.directory is down
    cleared_by_temp=[]
    flagged_by_temp=[]
    errored_by_temp=[]
    amount_phish=0
    amount_malware=0
    amount_other=0 # this includes unclassified
    malicious_flag=False
    suspicious_flag=False
    if len(responses) == 0:
        return definitions.ClientResponse(
            verdict=definitions.Verdict.error,
            is_threat=False,
            threat_type=definitions.ThreatType.unknown,
            confirmed_via=definitions.Via.none,
            flagged_by=[],
            cleared_by=[],
            errored_by=[],
            error="Need at least one response",
            evidence=[]
        )
    elif len(responses) == 1:
        for response in responses:
            if not response:
                continue
            else:
                if not response.is_threat:
                    cleared_by_temp.append(response.source)
                elif response.is_threat and response.error is None:
                    flagged_by_temp.append(response.source)
                else:
                    errored_by_temp.append(response.source)
        return definitions.ClientResponse(
            verdict=definitions.Verdict.malicious if responses[0].result == definitions.Result.hit else definitions.Verdict.clean,
            is_threat=True if responses[0].result == definitions.Result.hit else False,
            threat_type=responses[0].threat_type,
            confirmed_via=responses[0].via,
            flagged_by=flagged_by_temp,
            cleared_by=cleared_by_temp,
            errored_by=errored_by_temp,
            error=None,
            evidence=responses
        )
    elif len(responses) > 1:
        for response in responses:
            if not response.is_threat:
                cleared_by_temp.append(response.source)
            elif response.is_threat and response.error is None:
                flagged_by_temp.append(response.source)
            else:
                errored_by_temp.append(response.source)
            if response.threat_type == definitions.ThreatType.phishing:
                amount_phish+=1
            elif response.threat_type == definitions.ThreatType.malware:
                amount_malware+=1
            else:
                amount_other+=1
        if len(flagged_by_temp) >= (len(cleared_by_temp) +  + len(errored_by_temp)):
            majority_flag=True
        elif len(flagged_by_temp) >= len(cleared_by_temp):
            malicious_flag=True # we want to ensure that if consensus is not reached due to errors, we call it suspicious
        elif len(cleared_by_temp) >= len(flagged_by_temp):
            malicious_flag = False
            suspicious_flag = False    
        if amount_phish == 0 and amount_other == 0:
            threat_type_ret = definitions.ThreatType.malware
        elif amount_malware == 0 and amount_other == 0:
            threat_type_ret = definitions.ThreatType.phishing
        else:
            threat_type_ret = definitions.ThreatType.mixed

        if malicious_flag:
            ret_verdict = definitions.Verdict.malicious
        elif suspicious_flag:
            ret_verdict = definitions.Verdict.suspicious
        else:
            ret_verdict = definitions.Verdict.clean
        return definitions.ClientResponse(
            verdict=ret_verdict,
            threat_type=threat_type_ret,
            is_threat=True if ret_verdict in [definitions.Verdict.malicious, definitions.Verdict.suspicious] else False,
            confirmed_via=definitions.Via.multi,
            flagged_by=flagged_by_temp,
            cleared_by=cleared_by_temp,
            errored_by=errored_by_temp,
            error=None,
            evidence=responses
        )
    else:
        return definitions.ClientResponse(
            verdict=definitions.Verdict.error,
            is_threat=False,
            threat_type=definitions.ThreatType.unknown,
            confirmed_via=definitions.Via.none,
            flagged_by=[],
            cleared_by=[],
            errored_by=[],
            error="Unhandled Exception while parsing response: Amount of responses negative?",
            evidence=[]
        )
        
        

@app.post("/check-url")
def check_url(url: definitions.UrlCheckRequest) -> definitions.ClientResponse:
    results=[]
    simple_check=False
    parse_result = parse_url(str(url.link))
    if not parse_result:
        return definitions.ClientResponse(
            verdict=definitions.Verdict.error,
            is_threat=False,
            threat_type=definitions.ThreatType.unknown,
            confirmed_via=definitions.Via.none,
            flagged_by=[],
            cleared_by=[],
            errored_by=[],
            error="Unhandled Exception while parsing response: No host found?",
            evidence=[]
        )
    phishdir_resp=check_url_phishdir(parse_result, None)
    if phishdir_resp:
        results.append(phishdir_resp)
    else:
        simple_check = True
    refresh_local_cache()
    print(parse_result)
    urlhaus_resp = check_url_urlhaus(parse_result, os.environ["URLHAUS_API_KEY"])
    if urlhaus_resp:
        results.append(urlhaus_resp)
    
    if simple_check:
        return simple_construct_verdict(results)
    
    else:
        raise HTTPException(status_code=501, detail="Complex check not implemented yet")
    