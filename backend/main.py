from feeds.phishdirectory import check_url_phishdir
from feeds.urlhaus import check_url_urlhaus, refresh_urlhaus_cache
from feeds.openphish import check_url_openphish, refresh_openphish
from feeds.certpl import check_url_certpl, refresh_certpl
from feeds.otxalienvault import check_url_otx
from feeds.heuristics import check_heuristic
from feeds.surbl import check_domain_surbl
from resources.parse_url import parse_url
from resources.ipcheck import ip_or_not
import resources.definitions as definitions
import os
import asyncio # we need this to run our periodic scanning
from urllib.parse import urlparse
from pathlib import Path
from fastapi import FastAPI, Depends, Cookie
from contextlib import asynccontextmanager, suppress
from fastapi.responses import JSONResponse
from fastapi.exceptions import HTTPException
from typing import List, Union
from dotenv import load_dotenv
from fastapi import Depends, Cookie

BASE_DIR = Path(__file__).resolve().parent  
DATA_DIR=Path("./data")

load_dotenv(BASE_DIR / ".env") 
openphish_set = set()

async def refresh_feeds():
    while True:
        global openphish_set
        # first, refreshing urlhaus
        refresh_urlhaus_cache()
        new_set = refresh_openphish()
        refresh_certpl()
        openphish_set = new_set
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

app = FastAPI(lifespan=lifespan)

def simple_construct_verdict(responses: List[definitions.UrlCheckResponse], heuristics) -> definitions.ClientResponse: 
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
            heuristics=[], #type: ignore
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
            heuristics_is_threat=True if heuristics.get("score", 0) >= 4 else False,
            is_threat=True if responses[0].result == definitions.Result.hit else False,
            threat_type=responses[0].threat_type,
            confirmed_via=responses[0].via,
            flagged_by=flagged_by_temp,
            cleared_by=cleared_by_temp,
            errored_by=errored_by_temp,
            heuristics=heuristics,
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
        if len(flagged_by_temp) >= (len(cleared_by_temp) + len(errored_by_temp)):
            malicious_flag=True
            suspicious_flag=False
        elif len(flagged_by_temp) >= len(cleared_by_temp):
            malicious_flag=False
            suspicious_flag=True # we want to ensure that if consensus is not reached due to errors, we call it suspicious
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
            heuristics_is_threat=True if heuristics.get("score", 0) >= 4 else False,
            is_threat=True if ret_verdict in [definitions.Verdict.malicious, definitions.Verdict.suspicious] else False,
            confirmed_via=definitions.Via.multi,
            flagged_by=flagged_by_temp,
            cleared_by=cleared_by_temp,
            errored_by=errored_by_temp,
            heuristics=heuristics,
            error=None,
            evidence=responses
        )
    else:
        return definitions.ClientResponse(
            verdict=definitions.Verdict.error,
            is_threat=False,
            heuristics_is_threat=False,
            threat_type=definitions.ThreatType.unknown,
            confirmed_via=definitions.Via.none,
            flagged_by=[],
            cleared_by=[],
            errored_by=[],
            heuristics=heuristics,
            error="Unhandled Exception while parsing response: Amount of responses negative?",
            evidence=[]
        )
        
        

@app.post("/check-url")
def check_url(url: definitions.UrlCheckRequest) -> definitions.ClientResponse:
    global openphish_set
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
            heuristics=[], # type: ignore
            evidence=[]
        )
    
    #scanning phishdir
    phishdir_resp=check_url_phishdir(parse_result, None)
    if phishdir_resp:
        results.append(phishdir_resp)
    else:
        simple_check = True
    print(parse_result)
    urlhaus_resp = check_url_urlhaus(parse_result, os.environ["ABUSECH_API_KEY"])
    if urlhaus_resp:
        results.append(urlhaus_resp)
        print(urlhaus_resp)
    
    surbl_resp = check_domain_surbl(urlparse(str(url.link)).hostname)
    if surbl_resp:
        results.append(surbl_resp)
        print(surbl_resp)
    # removed below due to extremely high inaccuracy
    # scanning openphish blocklist
    openphish_response = check_url_openphish(parse_result, openphish_set) #type: ignore
    if simple_check and openphish_response:
        results.append(openphish_response)
        print(openphish_response)

    # scanning certpl blocklist
    # certpl_parse = urlparse(str(url.link)).hostname
    # if certpl_parse:
    #     certpl_response = check_url_certpl(certpl_parse)
    # else:
    #     certpl_response = None
    # if simple_check and certpl_response:
    #     results.append(certpl_response)
    # otx_resp = check_url_otx(str(url.link), os.environ["OTX_API_KEY"])
    # if otx_resp:
    #     print(otx_resp)
    #     results.append(otx_resp)

    heuristics = check_heuristic(str(urlparse(str(url.link)).hostname or str(url.link)), ip_or_not(urlparse(str(url.link)).hostname or str(url.link)))
    print(heuristics)
    if simple_check:
        return simple_construct_verdict(results, heuristics)
    
    else:
        raise HTTPException(status_code=501, detail="Complex check not implemented yet")
    